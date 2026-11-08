"""HTTP tests H1..H11: a real Service on 127.0.0.1:0 with a fake run_task."""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = pathlib.Path(__file__).resolve().parent
for _p in (str(ROOT), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from service_fakes import (API, KEY, ORIGIN, FakeRunTask, LogCapture, api, db_bytes,  # noqa: E402
                           env_with_key, five_events, jget, jpost, make_env, make_outcome,
                           open_session, wait_for, wait_task_done)
from airlock.service.app import Service  # noqa: E402
from airlock.service.config import load_config  # noqa: E402

TASK = {"sample_id": "s1", "instruction": "do the thing"}


class HttpBase(unittest.TestCase):
    patch: dict = {}
    workers = True

    def make_fake(self) -> FakeRunTask:
        return FakeRunTask()

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="airlock-http-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = env_with_key()
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cfg_path, _, self.docker_dir = make_env(self.tmp, patch=self.patch)
        self.cfg = load_config(self.cfg_path)
        self.fake = self.make_fake()
        self.logs = LogCapture()
        self.logs.__enter__()
        self.addCleanup(self.logs.__exit__, None, None, None)
        self.svc = Service(self.cfg, run_task_fn=self.fake, start_workers=self.workers)
        self.svc.start()
        self.addCleanup(self.svc.stop)
        self.port = self.svc.address[1]
        self.db = sqlite3.connect(self.cfg.db_path, timeout=10)
        self.addCleanup(self.db.close)

    def count(self, table: str) -> int:
        return self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]

    def submit(self, cookie: str, body: dict | None = None) -> str:
        status, data, _ = jpost(self.port, "/tasks", body or TASK, cookie)
        self.assertEqual(status, 202, data)
        return data["task"]["id"]


class TestSessions(HttpBase):
    patch = {"cookie_secure": True}

    def test_H1_sessions(self):
        status, headers, _ = api(self.port, "POST", API + "/sessions")
        self.assertEqual(status, 201)
        parts = [p.strip() for p in headers["set-cookie"].split(";")]
        token = parts[0].split("=", 1)[1]
        self.assertEqual(parts[0].split("=")[0], "airlock_session")
        self.assertEqual(sorted(parts[1:]), sorted(["Max-Age=43200", "Path=/api", "HttpOnly",
                                                    "SameSite=Strict", "Secure"]))
        self.assertNotIn(token.encode(), db_bytes(self.cfg.data_dir))
        row = self.db.execute("SELECT token_hash FROM sessions").fetchone()
        self.assertEqual(row[0], hashlib.sha256(token.encode("ascii")).digest())


class TestNoSecureFlag(HttpBase):
    def test_H1_cookie_without_secure(self):
        _, headers, _ = api(self.port, "POST", API + "/sessions")
        self.assertNotIn("Secure", headers["set-cookie"])


class TestOwnership(HttpBase):
    workers = False

    def test_H2_ownership(self):
        a, b = open_session(self.port), open_session(self.port)
        tid = self.submit(a)
        routes = [("GET", f"/tasks/{tid}"), ("GET", f"/tasks/{tid}/events"),
                  ("GET", f"/tasks/{tid}/diff"), ("POST", f"/tasks/{tid}/review"),
                  ("GET", f"/tasks/{tid}/patch")]
        for method, path in routes:
            body = {"decision": "approve"} if method == "POST" else None
            with self.subTest(route=path):
                self.assertEqual(api(self.port, method, API + path, body=body, cookie=b)[0], 404)
                self.assertEqual(api(self.port, method, API + path, body=body)[0], 401)
                self.assertEqual(api(self.port, method, API + path, body=body, cookie="x" * 43 + "!")[0], 401)
                self.assertEqual(api(self.port, method, API + path, body=body, cookie="A" * 43)[0], 401)
        self.assertEqual(api(self.port, "GET", API + f"/tasks/{'0' * 32}", cookie=a)[0], 404)
        self.assertEqual(api(self.port, "GET", API + "/tasks/not-an-id", cookie=a)[0], 404)
        self.assertEqual(api(self.port, "GET", API + f"/tasks/{tid}", cookie=a)[0], 200)


class TestCsrf(HttpBase):
    workers = False

    def test_H3_csrf(self):
        cookie = open_session(self.port)
        sessions_before = self.count("sessions")
        for kw in ({"csrf": False}, {"headers": {"X-Airlock": "0"}},
                   {"headers": {"Origin": "https://evil.example.invalid"}}):
            with self.subTest(kw=kw):
                self.assertEqual(api(self.port, "POST", API + "/tasks", body=TASK, cookie=cookie, **kw)[0], 403)
        self.assertEqual(self.count("tasks"), 0)
        self.assertEqual(api(self.port, "POST", API + "/sessions", csrf=False)[0], 403)
        self.assertEqual(self.count("sessions"), sessions_before)
        status, _, _ = api(self.port, "POST", API + "/tasks", body=TASK, cookie=cookie,
                           headers={"Origin": ORIGIN})
        self.assertEqual(status, 202)


class TestBody(HttpBase):
    workers = False

    def post(self, cookie, **kw):
        return api(self.port, "POST", API + "/tasks", cookie=cookie, **kw)

    def test_H4_body(self):
        cookie = open_session(self.port)
        padded = json.dumps(TASK).encode() + b" " * (16385 - len(json.dumps(TASK)))
        self.assertEqual(len(padded), 16385)
        self.assertEqual(self.post(cookie, raw=padded)[0], 413)
        cases = [({"sample_id": "s1", "instruction": "x", "path": "/etc"}, 422),
                 ({"sample_id": "s1", "instruction": "x", "preset_id": "p1"}, 422),
                 ({"sample_id": "nope", "instruction": "x"}, 422),
                 ({"sample_id": "s1", "preset_id": "q1"}, 422)]
        for body, want in cases:
            with self.subTest(body=body):
                self.assertEqual(self.post(cookie, body=body)[0], want)
        self.assertEqual(self.post(cookie, raw=b"not json")[0], 400)
        self.assertEqual(self.post(cookie, raw=b"{}", content_type="text/plain")[0], 415)
        self.assertEqual(self.post(cookie, raw=b'{"sample_id":"s1","sample_id":"s2","instruction":"x"}')[0], 422)
        self.assertEqual(self.post(cookie, raw=b'{"sample_id":"s1","instruction":"a\\ud800"}')[0], 422)
        self.assertEqual(self.post(cookie, raw=b'[1]')[0], 422)
        self.assertEqual(self.post(cookie, body={"sample_id": "s1", "preset_id": "p1"})[0], 202)
        self.assertEqual(self.post(cookie, body=TASK)[0], 202)
        self.assertEqual(self.count("tasks"), 2)


class TestReview(HttpBase):
    DIFF = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-one\n+two\n"

    def make_fake(self):
        return FakeRunTask(outcome=make_outcome(diff_text=self.DIFF))

    def finished(self, cookie):
        tid = self.submit(cookie)
        task = wait_task_done(self.port, cookie, tid)
        return tid, task

    def test_H5_review_gate(self):
        cookie = open_session(self.port)
        tid, task = self.finished(cookie)
        self.assertEqual(task["review_state"], "pending")
        self.assertEqual(api(self.port, "GET", API + f"/tasks/{tid}/patch", cookie=cookie)[0], 409)
        self.assertEqual(jget(self.port, f"/tasks/{tid}/diff", cookie)[1]["diff"]["text"], self.DIFF)
        self.assertEqual(jpost(self.port, f"/tasks/{tid}/review", {"decision": "approve"}, cookie)[0], 200)
        status, headers, body = api(self.port, "GET", API + f"/tasks/{tid}/patch", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(body.decode(), self.DIFF)
        self.assertEqual(headers["content-type"], "text/x-diff; charset=utf-8")
        self.assertEqual(headers["content-disposition"], f'attachment; filename="airlock-{tid}.patch"')
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["cache-control"], "no-store")
        for decision in ("approve", "reject"):
            self.assertEqual(jpost(self.port, f"/tasks/{tid}/review", {"decision": decision}, cookie)[0], 409)
        tid2, _ = self.finished(cookie)
        self.assertEqual(jpost(self.port, f"/tasks/{tid2}/review", {"decision": "reject"}, cookie)[0], 200)
        self.assertEqual(self.db.execute("SELECT count(*) FROM task_diffs WHERE task_pk = "
                                         "(SELECT pk FROM tasks WHERE id=?)", (tid2,)).fetchone()[0], 0)
        self.assertEqual(api(self.port, "GET", API + f"/tasks/{tid2}/diff", cookie=cookie)[0], 404)
        self.assertEqual(api(self.port, "GET", API + f"/tasks/{tid2}/patch", cookie=cookie)[0], 404)

    def test_H5_not_reviewable(self):
        self.fake.outcome = make_outcome()
        cookie = open_session(self.port)
        tid, _ = self.finished(cookie)
        status, body, _ = jpost(self.port, f"/tasks/{tid}/review", {"decision": "approve"}, cookie)
        self.assertEqual((status, body["error"]["code"]), (409, "not_reviewable"))


class TestReviewQueued(HttpBase):
    workers = False

    def test_H5_patch_while_queued(self):
        cookie = open_session(self.port)
        tid = self.submit(cookie)
        self.assertEqual(api(self.port, "GET", API + f"/tasks/{tid}/patch", cookie=cookie)[0], 404)


class TestNoEcho(HttpBase):
    def make_fake(self):
        return FakeRunTask(raises=RuntimeError("CANARYEXC"))

    def test_H6_no_echo(self):
        cookie = open_session(self.port)
        status, headers, body = api(self.port, "POST", API + "/tasks", cookie=cookie,
                                    body={"sample_id": "s1", "instruction": "CANARYINS\x00"})
        self.assertEqual(status, 422)
        self.assertNotIn(b"CANARYINS", body)
        tid = self.submit(cookie)
        task = wait_task_done(self.port, cookie, tid)
        self.assertEqual(task["end_reason"], "internal_error")
        blob = json.dumps(task) + self.logs.text + json.dumps(jget(self.port, f"/tasks/{tid}/events", cookie)[1])
        self.assertNotIn("CANARYEXC", blob)
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(b"GET /api/v1/CANARY7f3a HTTP/1.1 extra\r\n\r\n")
            data = b""
            while chunk := s.recv(4096):
                data += chunk
        status_line = data.split(b"\r\n")[0].decode("latin-1")
        self.assertRegex(status_line, r"^HTTP/1\.[01] 400 ")
        self.assertIn(b'"bad_request"', data)
        # Neither the status line (reason phrase), the headers nor the body echo the request.
        self.assertNotIn(b"CANARY7f3a", data)
        self.assertNotIn(b"extra", data.split(b"\r\n\r\n", 1)[-1])
        _, _, body = api(self.port, "GET", API + "/CANARY7f3a")
        self.assertNotIn(b"CANARY7f3a", body)


class TestKeyCanary(HttpBase):
    def make_fake(self):
        return FakeRunTask(events=five_events())

    def test_H7_key_canary(self):
        cookie = open_session(self.port)
        bodies = []
        tid = self.submit(cookie)
        wait_task_done(self.port, cookie, tid)
        for path in (f"/tasks/{tid}", f"/tasks/{tid}/events", "/session", "/samples"):
            bodies.append(api(self.port, "GET", API + path, cookie=cookie)[2])
        bodies.append(api(self.port, "GET", API + "/nope", cookie=cookie)[2])
        blob = b"".join(bodies) + db_bytes(self.cfg.data_dir) + self.logs.text.encode()
        self.assertNotIn(KEY.encode(), blob)


class TestEvents(HttpBase):
    def make_fake(self):
        return FakeRunTask(events=five_events())

    def test_H8_events(self):
        cookie = open_session(self.port)
        tid = self.submit(cookie)
        wait_task_done(self.port, cookie, tid)
        _, page, _ = jget(self.port, f"/tasks/{tid}/events?after_seq=0&limit=2", cookie)
        self.assertEqual([e["seq"] for e in page["events"]], [1, 2])
        self.assertTrue(page["has_more"])
        self.assertEqual(page["next_after_seq"], 2)
        _, page, _ = jget(self.port, f"/tasks/{tid}/events?after_seq=4", cookie)
        self.assertEqual([e["seq"] for e in page["events"]], [5])
        self.assertFalse(page["has_more"])
        self.assertTrue(page["terminal"])
        self.assertEqual(page["last_seq"], 5)
        for q in ("limit=0", "limit=201", "after_seq=-1", "after_seq=1&after_seq=2", "foo=1"):
            with self.subTest(q=q):
                self.assertEqual(api(self.port, "GET", API + f"/tasks/{tid}/events?{q}", cookie=cookie)[0], 422)


class TestSessionView(HttpBase):
    workers = False
    patch = {"quotas": {"max_queued": 2}}

    def test_H9_session_view(self):
        cookie = open_session(self.port)
        _, view, _ = jget(self.port, "/session", cookie)
        self.assertEqual(view["quota"]["tasks_used"], 0)
        self.assertTrue(view["service"]["accepting_tasks"])
        self.submit(cookie)
        _, view, _ = jget(self.port, "/session", cookie)
        self.assertEqual((view["quota"]["tasks_used"], view["quota"]["tasks_remaining"]), (1, 9))
        self.assertEqual(view["service"]["queued"], 1)
        self.submit(cookie)
        _, view, _ = jget(self.port, "/session", cookie)
        self.assertTrue(view["service"]["queue_full"])
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("UPDATE breaker SET state='open', reason='admin', opened_at=1, opened_day='2000-01-01'")
        self.db.execute("COMMIT")
        _, view, _ = jget(self.port, "/session", cookie)
        self.assertEqual((view["service"]["accepting_tasks"], view["service"]["pause_reason"]),
                         (False, "maintenance"))

    def test_H10_samples(self):
        status, body, _ = jget(self.port, "/samples")
        self.assertEqual(status, 200)
        self.assertEqual([s["id"] for s in body["samples"]], ["s1", "s2"])
        self.assertNotIn('"path"', json.dumps(body))
        self.assertEqual(body["samples"][0]["presets"][0]["instruction"], "preset instruction one")


class TestRefusals(HttpBase):
    workers = False
    patch = {"quotas": {"session_tasks_per_day": 2, "max_queued": 3, "ip_tasks_per_hour": 100}}

    def test_H11_quota_paused_queue(self):
        cookie = open_session(self.port)
        self.submit(cookie)
        self.submit(cookie)
        status, body, headers = jpost(self.port, "/tasks", TASK, cookie)
        self.assertEqual((status, body["error"]["code"]), (429, "session_task_quota"))
        self.assertTrue(headers["retry-after"].isdigit())
        other = open_session(self.port)
        self.submit(other)
        third = open_session(self.port)
        status, body, _ = jpost(self.port, "/tasks", TASK, third)
        self.assertEqual((status, body["error"]["code"]), (503, "queue_full"))
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("UPDATE breaker SET state='open', reason='admin', opened_at=1, opened_day='2000-01-01'")
        self.db.execute("COMMIT")
        status, body, _ = jpost(self.port, "/tasks", TASK, third)
        self.assertEqual((status, body["error"]["code"]), (503, "service_paused"))


class TestRateLimited(HttpBase):
    workers = False
    patch = {"quotas": {"ip_tasks_per_hour": 2}}

    def test_H11_rate_limited(self):
        cookie = open_session(self.port)
        self.submit(cookie)
        self.submit(cookie)
        status, body, headers = jpost(self.port, "/tasks", TASK, cookie)
        self.assertEqual((status, body["error"]["code"]), (429, "rate_limited"))
        self.assertIn("retry-after", headers)


class TestTooManyActive(HttpBase):
    patch = {"quotas": {"session_max_active": 1}}

    def make_fake(self):
        self.block = threading.Event()
        self.addCleanup(self.block.set)
        return FakeRunTask(block=self.block)

    def test_H11_too_many_active(self):
        cookie = open_session(self.port)
        self.submit(cookie)
        status, body, _ = jpost(self.port, "/tasks", TASK, cookie)
        self.assertEqual((status, body["error"]["code"]), (429, "too_many_active"))


if __name__ == "__main__":
    unittest.main()
