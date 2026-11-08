"""Client tests against a fake HTTP provider on 127.0.0.1 (no real provider)."""
from __future__ import annotations

import json
import logging
import os
import pathlib
import sys
import time
import traceback
import unittest
import urllib.request
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = pathlib.Path(__file__).resolve().parent
for _p in (str(ROOT), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agent_fakes import (FakeProvider, FakeSandbox, Reply, chat_ok, text_block)  # noqa: E402
from airlock.agent import (AgentConfig, ChatRequest, InferenceError, OpenAICompatClient,  # noqa: E402
                           run_task)
from airlock.agent.prompt import OFFERED_TOOLS, TOOL_SPECS  # noqa: E402

KEY = "sk-CANARY-" + os.urandom(8).hex()
REQ_TEXT = ChatRequest(({"role": "user", "content": "hi"},), None, 64)
REQ_NATIVE = ChatRequest(({"role": "user", "content": "hi"},), TOOL_SPECS, 64)


class ClientCase(unittest.TestCase):
    def provider(self, script) -> FakeProvider:
        p = FakeProvider(script)
        self.addCleanup(p.close)
        return p

    def client(self, p: FakeProvider, **kw) -> OpenAICompatClient:
        self.sleeps: list[float] = []
        kw.setdefault("sleep", self.sleeps.append)
        kw.setdefault("api_key_provider", lambda: KEY)
        return OpenAICompatClient(base_url=p.base_url, model="test-model", **kw)

    @staticmethod
    def deadline(seconds: float = 60.0) -> float:
        return time.monotonic() + seconds

    def kind_of(self, client, request=REQ_TEXT, deadline=None) -> InferenceError:
        with self.assertRaises(InferenceError) as cm:
            client.complete(request, deadline=deadline or self.deadline())
        return cm.exception


class TestClient(ClientCase):
    def test_AC1_request_shapes(self):
        p = self.provider([Reply(body=chat_ok())])
        c = self.client(p)
        c.complete(REQ_NATIVE, deadline=self.deadline())
        c.complete(REQ_TEXT, deadline=self.deadline())
        native, text = (json.loads(b) for b in p.bodies)
        self.assertEqual(set(native), {"model", "messages", "max_tokens", "stream", "tools",
                                       "tool_choice"})
        self.assertEqual([t["function"]["name"] for t in native["tools"]], list(OFFERED_TOOLS))
        self.assertEqual(set(text), {"model", "messages", "max_tokens", "stream"})
        self.assertEqual(p.paths, ["/v1/chat/completions"] * 2)

    def test_AC2_key_canary(self):
        p = self.provider([Reply(status=400, body=b'{"error":"bad"}')])
        c = self.client(p)
        with self.assertLogs(level="DEBUG") as logs:
            exc = self.kind_of(c)
        self.assertEqual(exc.kind, "http_status")
        self.assertEqual(p.headers[0]["authorization"], "Bearer " + KEY)
        shown = [repr(c), repr(vars(c)), str(exc), repr(exc),
                 "".join(traceback.format_exception(exc)), "\n".join(logs.output)]
        for text in shown:
            self.assertNotIn(KEY, text)
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)

    def test_AC3_retry_after_429(self):
        p = self.provider([Reply(status=429), Reply(body=chat_ok())])
        c = self.client(p)
        resp = c.complete(REQ_TEXT, deadline=self.deadline())
        self.assertEqual(p.hits, 2)
        self.assertEqual(self.sleeps, [1.0])
        self.assertEqual(resp.uncertain_attempts, 0)

    def test_AC4_400_not_retried(self):
        p = self.provider([Reply(status=400)])
        exc = self.kind_of(self.client(p, max_retries=2))
        self.assertEqual(exc.kind, "http_status")
        self.assertEqual(p.hits, 1)

    def test_AC5_timeout(self):
        p = self.provider([Reply(body=chat_ok(), delay=5.0)])
        exc = self.kind_of(self.client(p, request_timeout_s=0.3, max_retries=0))
        self.assertEqual(exc.kind, "timeout")
        self.assertEqual(exc.uncertain_attempts, 1)
        p.reset([Reply(body=chat_ok(), delay=5.0)])
        exc = self.kind_of(self.client(p, request_timeout_s=0.3, max_retries=2,
                                       backoff_s=(0.01,)))
        self.assertEqual(p.hits, 3)
        self.assertEqual(exc.uncertain_attempts, 3)

    def test_AC6_oversize(self):
        body = b'{"x":"' + b"a" * (1024 * 1024 - 8) + b'"}'
        self.assertEqual(len(body), 1024 * 1024)
        body += b" "  # 1 MiB + 1 byte
        for with_length in (True, False):
            with self.subTest(content_length=with_length):
                p = self.provider([Reply(body=body, content_length=with_length)])
                exc = self.kind_of(self.client(p))
                self.assertEqual(exc.kind, "oversize")
                self.assertEqual(p.hits, 1)

    def test_AC7_redirect_refused(self):
        p = self.provider([Reply(status=302, headers={"Location": "/other"})])
        exc = self.kind_of(self.client(p))
        self.assertEqual(exc.kind, "http_status")
        self.assertEqual(p.paths, ["/v1/chat/completions"])

    def test_AC8_client_timeout_capped_by_deadline(self):
        p = self.provider([Reply(body=chat_ok(), delay=5.0)])
        c = self.client(p, request_timeout_s=30)
        started = time.monotonic()
        with self.assertRaises(InferenceError):
            c.complete(REQ_TEXT, deadline=time.monotonic() + 1.0)
        self.assertLess(time.monotonic() - started, 2.5)
        p.reset([Reply(body=chat_ok())])
        exc = self.kind_of(c, deadline=time.monotonic() + 0.1)
        self.assertEqual(exc.kind, "deadline")
        self.assertEqual(p.hits, 0)

    def test_AC9_base_url_table(self):
        for ok in ("https://h/v1", "http://127.0.0.1:1/v1", "http://[::1]:1/v1"):
            with self.subTest(ok=ok):
                OpenAICompatClient(base_url=ok, model="m", api_key_provider=lambda: KEY)
        for bad in ("http://example.com/v1", "https://u:p@h/v1", "https://h/v1?x=1", "ftp://h", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    OpenAICompatClient(base_url=bad, model="m", api_key_provider=lambda: KEY)

    def test_AC10_credential(self):
        p = self.provider([Reply(body=chat_ok())])
        exc = self.kind_of(self.client(p, api_key_provider=lambda: "abc\r\nX-Injected: 1"))
        self.assertEqual(exc.kind, "credential")
        self.assertEqual(p.hits, 0)

        def boom() -> str:
            raise RuntimeError("PROVIDER-CANARY")
        exc = self.kind_of(self.client(p, api_key_provider=boom))
        self.assertEqual(exc.kind, "credential")
        self.assertNotIn("PROVIDER-CANARY", str(exc) + "".join(traceback.format_exception(exc)))
        self.assertIsNone(exc.__context__)

    def test_AC12_bad_bodies(self):
        bodies = [b"not json", b'{"x":1}', b"[" * 200000,
                  b'{"choices":[{"message":{"content":5}}]}']
        p = self.provider([Reply(body=b"x")])
        c = self.client(p)
        for body in bodies:
            with self.subTest(body=body[:20]):
                p.reset([Reply(body=body)])
                exc = self.kind_of(c)
                self.assertEqual(exc.kind, "bad_response")
                self.assertEqual(p.hits, 1)

    def test_AC13_usage(self):
        cases = [(None, None, None), ({"prompt_tokens": True, "completion_tokens": True}, None, None),
                 ({"prompt_tokens": 0, "completion_tokens": 0}, None, None),
                 ({"prompt_tokens": 12, "completion_tokens": 7}, 12, 7)]
        p = self.provider([Reply(body=b"x")])
        c = self.client(p)
        for usage, pt, ct in cases:
            with self.subTest(usage=usage):
                p.reset([Reply(body=chat_ok(usage=usage))])
                resp = c.complete(REQ_TEXT, deadline=self.deadline())
                self.assertEqual((resp.prompt_tokens, resp.completion_tokens), (pt, ct))

    def test_AC14_proxy_environment_ignored(self):
        target = self.provider([Reply(body=chat_ok())])
        proxy = self.provider([Reply(body=chat_ok())])
        proxy_url = proxy.base_url.rsplit("/v1", 1)[0]
        with mock.patch.dict(os.environ):
            for name in ("NO_PROXY", "no_proxy"):
                os.environ.pop(name, None)
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                os.environ[name] = proxy_url
            c = self.client(target)
            c.complete(REQ_TEXT, deadline=self.deadline())
            # Control arm: a default opener in this same environment does pick up the proxy.
            default = urllib.request.build_opener()
            self.assertTrue([h for h in default.handlers
                             if isinstance(h, urllib.request.ProxyHandler) and h.proxies])
        self.assertEqual(proxy.hits, 0)
        self.assertEqual(target.hits, 1)
        proxy_handlers = [h for h in c._opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
        # ProxyHandler({}) registers no handler methods, so the opener carries none at all.
        self.assertEqual([h.proxies for h in proxy_handlers if h.proxies], [])


class TestEndToEnd(ClientCase):
    def test_AC11_no_secret_reaches_events_or_sandbox(self):
        env_canary = "ENV-CANARY-" + os.urandom(6).hex()
        script = [Reply(body=chat_ok(text_block("list_dir", {"path": "."}))),
                  Reply(body=chat_ok(text_block("finish", {"summary": "done"})))]
        p = self.provider(script)
        sandbox = FakeSandbox()
        events: list = []
        from agent_fakes import FakeFactory, RecBudget
        with mock.patch.dict(os.environ, {"AIRLOCK_ENV_CANARY": env_canary}):
            outcome = run_task("fix it", pathlib.Path("/nonexistent"), client=self.client(p),
                               config=AgentConfig(action_mode="text"), sink=events.append,
                               budget=RecBudget(), sandbox_factory=FakeFactory(sandbox))
        self.assertEqual(outcome.reason, "agent_finished")
        for secret in (KEY, env_canary):
            self.assertNotIn(secret, json.dumps(events))
            self.assertNotIn(secret, repr(sandbox.calls))
            self.assertNotIn(secret, repr(outcome))
        self.assertTrue(all(h["authorization"] == "Bearer " + KEY for h in p.headers))
        self.assertEqual(p.hits, 2)


if __name__ == "__main__":
    logging.disable(logging.NOTSET)
    unittest.main()
