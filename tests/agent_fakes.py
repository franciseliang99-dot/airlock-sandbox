"""Shared fakes for the agent tests: client, sandbox, sink, budget, HTTP provider."""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from airlock.agent import ChatResponse, RawToolCall
from airlock.sandbox import DestroyProof, DiffResult, ToolResult
from airlock.sandbox import _policy
from airlock.sandbox._policy import Rejection

OK_RESULT = ToolResult(True, 0, "ok\n", 3, False, 5, None, None)
FATAL_RESULT = ToolResult(False, None, "sandbox not running", 19, False, 0, None, None)
TAG_RE = re.compile(r"\[\[TOOL OUTPUT ([0-9a-f]{16}) BEGIN\]\]")


# ---------------------------------------------------------------------- reply builders

def reply(content: str | None = None, calls: tuple = (), pt: int | None = 10,
          ct: int | None = 5, u: int = 0) -> ChatResponse:
    return ChatResponse(content, tuple(calls), pt, ct, u)


def text_block(tool: str, args: dict) -> str:
    return "```json\n" + json.dumps({"tool": tool, "args": args}) + "\n```"


def text_reply(tool: str, args: dict, **kw) -> ChatResponse:
    return reply(text_block(tool, args), **kw)


def native_reply(tool: str, args: dict, **kw) -> ChatResponse:
    return reply(None, (RawToolCall(tool, json.dumps(args)),), **kw)


def tag_of(request) -> str:
    match = TAG_RE.search(request.messages[-1]["content"])
    assert match is not None
    return match.group(1)


# ---------------------------------------------------------------------- client

class HANG:
    """Script entry: block until `event` is set, then return `then` (or raise it)."""

    def __init__(self, event: threading.Event, then=None) -> None:
        self.event = event
        self.then = then


class FakeClient:
    def __init__(self, script, *, max_attempts: int = 1, repeat: bool = False) -> None:
        self.script = list(script)
        self.max_attempts = max_attempts
        self.repeat = repeat
        self.requests: list = []
        self._n = 0
        self._lock = threading.Lock()

    def complete(self, request, *, deadline: float):
        with self._lock:
            self.requests.append(request)
            idx = self._n
            self._n += 1
        if idx < len(self.script):
            item = self.script[idx]
        elif self.repeat and self.script:
            item = self.script[-1]
        else:
            raise AssertionError("fake client script exhausted")
        if isinstance(item, HANG):
            item.event.wait()
            item = item.then if item.then is not None else reply(text_block("finish", {"summary": "late"}))
        if isinstance(item, BaseException):
            raise item
        return item


# ---------------------------------------------------------------------- sandbox

class FakeSandbox:
    def __init__(self, *, results=(), default: ToolResult | None = None, peaks=(),
                 diff: DiffResult | None = None, diff_error: Exception | None = None,
                 proof: DestroyProof | None = None) -> None:
        self._results = list(results)
        self._default = default or OK_RESULT
        self._peaks = list(peaks)
        self._diff = diff or DiffResult("ok", "d", 1, "a" * 64,
                                        [{"path": "a.py", "change": "M", "lines_added": 1,
                                          "lines_removed": 0}])
        self._diff_error = diff_error
        self._proof = proof or DestroyProof("abc123def456", True, None)
        self.calls: list = []
        self.peak_calls = 0
        self.collect_diff_calls = 0
        self.destroy_calls = 0

    def call(self, tool, args):
        self.calls.append((tool, dict(args) if isinstance(args, dict) else args))
        v = _policy.validate_call(tool, args, file_write_max_bytes=256 * 1024)
        if isinstance(v, Rejection):
            return ToolResult(False, None, v.message, len(v.message.encode("utf-8")), False, 0,
                              v.blocked_reason, None)
        item = self._results.pop(0) if self._results else self._default
        return item(tool, args) if callable(item) else item

    def resource_peak(self):
        self.peak_calls += 1
        if self._peaks:
            return self._peaks.pop(0)
        return {"memory_bytes": None, "pids": None, "cpu_ms": None}

    def collect_diff(self):
        self.collect_diff_calls += 1
        if self._diff_error is not None:
            raise self._diff_error
        return self._diff

    def destroy(self):
        self.destroy_calls += 1
        return self._proof


class FakeFactory:
    def __init__(self, sandbox=None, error: Exception | None = None) -> None:
        self.sandbox = sandbox
        self.error = error
        self.calls = 0
        self.kwargs: dict = {}

    def __call__(self, sample_repo, **kwargs):
        self.calls += 1
        self.kwargs = kwargs
        if self.error is not None:
            raise self.error
        return self.sandbox


# ---------------------------------------------------------------------- sink and budget

class RecSink:
    def __init__(self, raise_on: int | None = None) -> None:
        self.events: list = []
        self.calls = 0
        self.raise_on = raise_on

    def __call__(self, event: dict) -> None:
        self.calls += 1
        if self.raise_on == self.calls:
            raise RuntimeError("sink failure")
        self.events.append(event)


class RecBudget:
    def __init__(self, *, charge_results: dict | None = None, stop=None,
                 charge_raises: Exception | None = None) -> None:
        self.charges: list = []
        self.stop_calls = 0
        self._results = charge_results or {}
        self._stop = stop
        self._raises = charge_raises

    def charge(self, tokens_in, tokens_out):
        self.charges.append((tokens_in, tokens_out))
        if self._raises is not None:
            raise self._raises
        return self._results.get(len(self.charges))

    def should_stop(self):
        self.stop_calls += 1
        return self._stop


# ---------------------------------------------------------------------- grammar

_LETTERS = {"sandbox_created": "s", "llm_call": "l", "tool_call": "t", "tool_result": "r",
            "action_blocked": "a", "budget_stop": "b", "resource_peak": "p",
            "artifact_collected": "c", "sandbox_destroyed": "d", "sandbox_destroy_failed": "f",
            "task_finished": "z"}
# The design grammar, with one relaxation: a valid finish emits a bare tool_call (no result).
GRAMMAR = re.compile(r"(?:s(?:l(?:t[ra]?|a)?b?)*b?pc?[df])?z")


def types_of(events) -> list[str]:
    return [e["type"] for e in events]


def assert_grammar(testcase, events) -> None:
    letters = "".join(_LETTERS[t] for t in types_of(events))
    testcase.assertIsNotNone(GRAMMAR.fullmatch(letters), f"event grammar violated: {letters}")


# ---------------------------------------------------------------------- HTTP provider

class Reply:
    def __init__(self, status: int = 200, body: bytes = b"", headers: dict | None = None,
                 delay: float = 0.0, content_length: bool = True) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.delay = delay
        self.content_length = content_length


def chat_ok(content: str | None = "hi", tool_calls: list | None = None, usage="default") -> bytes:
    message: dict = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    data: dict = {"choices": [{"message": message}]}
    if usage == "default":
        data["usage"] = {"prompt_tokens": 12, "completion_tokens": 7}
    elif usage is not None:
        data["usage"] = usage
    return json.dumps(data).encode("utf-8")


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:  # clients abort on purpose
        return


class FakeProvider:
    def __init__(self, script) -> None:
        self.script = list(script)
        self.hits = 0
        self.paths: list[str] = []
        self.headers: list[dict] = []
        self.bodies: list[bytes] = []
        self.release = threading.Event()
        self._lock = threading.Lock()
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with provider._lock:
                    idx = provider.hits
                    provider.hits += 1
                    provider.paths.append(self.path)
                    provider.headers.append({k.lower(): v for k, v in self.headers.items()})
                    provider.bodies.append(body)
                    item = provider.script[min(idx, len(provider.script) - 1)]
                if item.delay:
                    provider.release.wait(item.delay)
                try:
                    self.send_response(item.status)
                    for key, value in item.headers.items():
                        self.send_header(key, value)
                    if item.content_length:
                        self.send_header("Content-Length", str(len(item.body)))
                    self.end_headers()
                    self.wfile.write(item.body)
                except OSError:
                    pass

            do_POST = _serve
            do_GET = _serve

            def log_message(self, *args) -> None:
                return

        self._server = _QuietServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}/v1"

    def reset(self, script) -> None:
        with self._lock:
            self.script = list(script)
            self.hits = 0
            self.paths.clear()
            self.headers.clear()
            self.bodies.clear()

    def close(self) -> None:
        self.release.set()
        self._server.shutdown()
        self._server.server_close()
