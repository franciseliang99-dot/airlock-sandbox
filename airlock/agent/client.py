"""OpenAI-compatible chat client. The only module that touches the network."""
from __future__ import annotations

import http.client
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import replace

from .contract import ChatRequest, ChatResponse, InferenceError, RawToolCall

_log = logging.getLogger("airlock.agent.client")

MIN_ATTEMPT_S = 0.5
_CHUNK = 65536
_UNCERTAIN = frozenset({"timeout", "oversize", "bad_response"})
_RETRYABLE = frozenset({"timeout", "connection", "http_429", "http_5xx"})
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
_MODEL_RE = re.compile(r"[A-Za-z0-9._:/@-]{1,200}")
_KEY_RE = re.compile(r"[\x21-\x7e]{1,512}")
_RETRY_AFTER_RE = re.compile(r"[0-9]{1,3}")
_BAD_URL_CHARS_RE = re.compile(r"[\x00-\x20\x7f]")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect so the Authorization header can never travel elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class _AttemptFailed(Exception):
    """Internal: one attempt failed. Carries only fixed fields, never provider text."""

    def __init__(self, kind: str, status: int | None = None,
                 retry_after: str | None = None) -> None:
        super().__init__(kind)
        self.kind = kind
        self.status = status
        self.retry_after = retry_after


def _validate_base_url(base_url: object) -> str:
    if not isinstance(base_url, str) or not base_url or _BAD_URL_CHARS_RE.search(base_url):
        raise ValueError("invalid base_url")
    try:
        parts = urllib.parse.urlsplit(base_url)
        host = parts.hostname
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        raise ValueError("invalid base_url") from None
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("invalid base_url")
    if parts.query or parts.fragment or "?" in base_url or "#" in base_url:
        raise ValueError("invalid base_url")
    if not host:
        raise ValueError("invalid base_url")
    if parts.scheme == "https":
        pass
    elif parts.scheme == "http" and host in _LOOPBACK:
        pass  # the named loopback exception
    else:
        raise ValueError("invalid base_url")
    return base_url.rstrip("/")


def _num_in(value: object, low: float, high: float) -> bool:
    return type(value) in (int, float) and low <= value <= high


def _usage_valid(v: object) -> bool:
    return type(v) is int and 1 <= v <= 10_000_000


def _status_kind(status: int) -> str:
    if status == 429:
        return "http_429"
    if 500 <= status <= 599:
        return "http_5xx"
    return "http_status"


def _reject_constant(name: str) -> object:
    raise ValueError("non-finite number")


def _extract(data: object) -> ChatResponse | None:
    """Shape-check a decoded body; None means bad_response."""
    if not isinstance(data, dict):
        return None
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    first = choices[0]
    if not isinstance(first, dict):
        return None
    message = first.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if content is not None and not isinstance(content, str):
        return None
    raw_calls = message.get("tool_calls")
    calls: list[RawToolCall] = []
    if raw_calls is not None:
        if not isinstance(raw_calls, list):
            return None
        for item in raw_calls:
            if not isinstance(item, dict) or item.get("type") != "function":
                return None
            fn = item.get("function")
            if not isinstance(fn, dict):
                return None
            name, arguments = fn.get("name"), fn.get("arguments")
            if not isinstance(name, str) or not isinstance(arguments, str):
                return None
            calls.append(RawToolCall(name, arguments))
    usage = data.get("usage")
    prompt_tokens = completion_tokens = None
    if isinstance(usage, dict):
        pt, ct = usage.get("prompt_tokens"), usage.get("completion_tokens")
        prompt_tokens = pt if _usage_valid(pt) else None
        completion_tokens = ct if _usage_valid(ct) else None
    return ChatResponse(content, tuple(calls), prompt_tokens, completion_tokens, 0)


def _parse_response(raw: bytes) -> ChatResponse:
    data: object = None
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError
        data = None
    parsed = _extract(data)
    if parsed is None:
        raise _AttemptFailed("bad_response")
    return parsed


class OpenAICompatClient:
    def __init__(self, *, base_url: str, model: str, api_key_provider: Callable[[], str],
                 request_timeout_s: float = 120.0, max_retries: int = 2,
                 backoff_s: tuple[float, ...] = (1.0, 4.0),
                 max_response_bytes: int = 1024 * 1024,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> None:
        """ValueError on invalid args. Stores the provider, never a key."""
        self._base_url = _validate_base_url(base_url)
        if not isinstance(model, str) or not _MODEL_RE.fullmatch(model):
            raise ValueError("invalid model")
        if not callable(api_key_provider):
            raise ValueError("invalid api_key_provider")
        if not _num_in(request_timeout_s, 0.1, 600):
            raise ValueError("invalid request_timeout_s")
        if type(max_retries) is not int or not (0 <= max_retries <= 5):
            raise ValueError("invalid max_retries")
        if (not isinstance(backoff_s, tuple) or not backoff_s
                or not all(_num_in(v, 0, 30) for v in backoff_s)):
            raise ValueError("invalid backoff_s")
        if type(max_response_bytes) is not int or not (1024 <= max_response_bytes <= 16 * 1024 * 1024):
            raise ValueError("invalid max_response_bytes")
        if not callable(sleep) or not callable(clock):
            raise ValueError("invalid sleep or clock")
        self._endpoint = self._base_url + "/chat/completions"
        self._model = model
        self._provider = api_key_provider
        self._request_timeout_s = float(request_timeout_s)
        self._max_retries = max_retries
        self._backoff = tuple(float(v) for v in backoff_s)
        self._max_response_bytes = max_response_bytes
        self._sleep = sleep
        self._clock = clock
        # No proxy from the environment, and no redirects.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    @property
    def max_attempts(self) -> int:
        return self._max_retries + 1

    def __repr__(self) -> str:
        return f"OpenAICompatClient(model={self._model!r}, max_attempts={self.max_attempts})"

    # ------------------------------------------------------------------ call

    def _encode(self, request: ChatRequest) -> bytes:
        payload: dict = {"model": self._model, "messages": list(request.messages),
                         "max_tokens": request.max_tokens, "stream": False}
        if request.tools is not None:
            payload["tools"] = list(request.tools)
            payload["tool_choice"] = "auto"
        body: bytes | None = None
        try:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            body = None
        if body is None:
            raise InferenceError("bad_response")
        return body

    def complete(self, request: ChatRequest, *, deadline: float) -> ChatResponse:
        body = self._encode(request)
        uncertain = 0
        attempt = 0
        while True:
            remaining = deadline - self._clock()
            if remaining < MIN_ATTEMPT_S:
                raise InferenceError("deadline", uncertain_attempts=uncertain)
            timeout = min(self._request_timeout_s, remaining)
            started = self._clock()
            response: ChatResponse | None = None
            failure: _AttemptFailed | None = None
            try:
                response = self._attempt(body, timeout, deadline)
            except _AttemptFailed as exc:
                failure = exc
            duration_ms = int((self._clock() - started) * 1000)
            # Everything below runs outside any except block, so raised errors carry no context.
            if failure is None and response is not None:
                _log.info("inference attempt=%d outcome=%s status=%s duration_ms=%d",
                          attempt + 1, "ok", 200, duration_ms)
                return replace(response, uncertain_attempts=uncertain)
            if failure is None:
                raise InferenceError("bad_response", uncertain_attempts=uncertain)
            kind = failure.kind
            _log.info("inference attempt=%d outcome=%s status=%s duration_ms=%d",
                      attempt + 1, kind, failure.status, duration_ms)
            if kind in _UNCERTAIN:
                uncertain += 1
            if kind not in _RETRYABLE or attempt >= self._max_retries:
                raise InferenceError(kind, status=failure.status, uncertain_attempts=uncertain)
            delay = self._backoff[min(attempt, len(self._backoff) - 1)]
            if kind == "http_429" and failure.retry_after is not None:
                header = failure.retry_after.strip()
                if _RETRY_AFTER_RE.fullmatch(header):
                    delay = max(delay, min(float(int(header)), 10.0))
            if self._clock() + delay + MIN_ATTEMPT_S > deadline:
                raise InferenceError(kind, status=failure.status, uncertain_attempts=uncertain)
            self._sleep(delay)
            attempt += 1

    def _get_key(self) -> str:
        key: object = None
        failed = False
        try:
            key = self._provider()
        except Exception:
            failed = True
        if failed or type(key) is not str or not _KEY_RE.fullmatch(key):
            raise _AttemptFailed("credential")
        return key

    def _attempt(self, body: bytes, timeout: float, deadline: float) -> ChatResponse:
        key = self._get_key()  # the key lives only in this frame
        request = urllib.request.Request(
            self._endpoint, data=body, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "User-Agent": "airlock-agent", "Authorization": "Bearer " + key})
        del key
        try:
            response = self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            status = exc.code
            retry_after = exc.headers.get("Retry-After") if exc.headers is not None else None
            exc.close()
            raise _AttemptFailed(_status_kind(status), status, retry_after) from None
        except TimeoutError:
            raise _AttemptFailed("timeout") from None
        except urllib.error.URLError as exc:
            kind = "timeout" if isinstance(exc.reason, TimeoutError) else "connection"
            raise _AttemptFailed(kind) from None
        except (OSError, http.client.HTTPException, ValueError):
            raise _AttemptFailed("connection") from None
        raw = self._read_body(response, deadline)
        return _parse_response(raw)

    def _read_body(self, response: http.client.HTTPResponse, deadline: float) -> bytes:
        try:
            status = response.status
            if status != 200:
                raise _AttemptFailed(_status_kind(status), status)
            length = response.headers.get("Content-Length")
            if length is not None:
                text = length.strip()
                if text.isascii() and text.isdigit() and int(text) > self._max_response_bytes:
                    raise _AttemptFailed("oversize")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read1(_CHUNK)  # one recv at most: a slow drip cannot pin us
                if not chunk:
                    break
                total += len(chunk)
                if total > self._max_response_bytes:
                    raise _AttemptFailed("oversize")
                chunks.append(chunk)
                if self._clock() > deadline:
                    raise _AttemptFailed("timeout")
            return b"".join(chunks)
        except TimeoutError:
            raise _AttemptFailed("timeout") from None
        except (OSError, http.client.HTTPException):
            raise _AttemptFailed("connection") from None
        finally:
            response.close()
