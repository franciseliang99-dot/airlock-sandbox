"""Concurrency tests C1, C1b, C2, C3, C4."""
from __future__ import annotations

import os
import pathlib
import shutil
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

from service_fakes import (API, FakeClock, FakeRunTask, api, env_with_key, jpost, make_env,  # noqa: E402
                           make_outcome, open_session, wait_task_done)
from airlock.service.accounting import Accounting, TaskBudget  # noqa: E402
from airlock.service.app import Service  # noqa: E402
from airlock.service.clock import utc_day  # noqa: E402
from airlock.service.config import load_config  # noqa: E402
from airlock.service.store import Store  # noqa: E402

TASK = {"sample_id": "s1", "instruction": "do it"}
N = 50


class Env(unittest.TestCase):
    patch: dict = {}

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="airlock-conc-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = env_with_key()
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cfg_path, _, _ = make_env(self.tmp, patch=self.patch)
        self.cfg = load_config(self.cfg_path)

    def db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.cfg.db_path, timeout=30)
        self.addCleanup(conn.close)
        return conn

    def run_threads(self, target, n: int = N, timeout: float = 120.0) -> list:
        barrier = threading.Barrier(n)
        results: list = [None] * n
        errors: list = []

        def wrap(i: int) -> None:
            try:
                barrier.wait(30)
                results[i] = target(i)
            except BaseException as exc:  # noqa: BLE001
                errors.append(repr(exc))
        threads = [threading.Thread(target=wrap, args=(i,), daemon=True) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout)
        self.assertFalse([t for t in threads if t.is_alive()], "threads did not terminate")
        self.assertEqual(errors, [])
        return results


class ChargeBase(Env):
    patch = {"quotas": {"global_tokens_per_day": 30000, "session_tokens_per_day": 10**9,
                        "session_tasks_per_day": 1000, "session_max_active": 200,
                        "max_queued": 200, "usd_cap": 1000}}

    def prepare(self):
        self.clock = FakeClock()
        self.store = Store(self.cfg.db_path)
        self.store.initialize()
        self.acct = Accounting(self.cfg, self.clock)
        conn = self.store.connect(busy_timeout_ms=30000)
        self.addCleanup(conn.close)
        with self.store.write_tx(conn):
            cur = conn.execute("INSERT INTO sessions(token_hash, created_at, expires_at) VALUES (?,?,?)",
                               (os.urandom(32), self.clock.now_ms(), self.clock.now_ms() + 10**9))
        self.session = cur.lastrowid
        self.task_pks = []
        for _ in range(N):
            with self.store.write_tx(conn):
                self.task_pks.append(self.acct.admit_in_tx(
                    conn, session_pk=self.session, task_id=os.urandom(16).hex(), sample_id="s1",
                    preset_id=None, instruction="x"))

    def worker(self, check_first: bool):
        def run(i: int) -> int:
            conn = self.store.connect(busy_timeout_ms=30000)
            try:
                budget = TaskBudget(self.store, self.acct, conn, self.task_pks[i], self.session,
                                    self.clock.monotonic() + 10_000, self.clock)
                charges = 0
                for _ in range(1000):
                    if check_first and budget.should_stop():
                        break
                    charges += 1
                    if budget.charge(100, 50):
                        break
                return charges
            finally:
                conn.close()
        return run


class TestCharging(ChargeBase):
    def test_C1_atomic_ledgers(self):
        self.prepare()
        charges = sum(self.run_threads(self.worker(True)))
        db = self.db()
        total = 150 * charges
        self.assertEqual(db.execute("SELECT sum(tokens_in + tokens_out) FROM tasks").fetchone()[0], total)
        day = utc_day(self.clock.now_ms())
        session_tokens = db.execute("SELECT tokens FROM session_usage WHERE session_pk=? AND day=?",
                                    (self.session, day)).fetchone()[0]
        self.assertEqual(session_tokens, 150 * charges)
        g = db.execute("SELECT tokens_in + tokens_out FROM global_usage WHERE day=?", (day,)).fetchone()[0]
        self.assertEqual(g, total)
        self.assertEqual(db.execute("SELECT usd_spent_micros FROM breaker").fetchone()[0], 45 * charges)
        self.assertEqual(db.execute("SELECT count(*) FROM breaker_log WHERE action='open'").fetchone()[0], 1)
        self.assertLess(g, 30000 + N * 150)

    def test_C1b_overshoot_bounded(self):
        self.prepare()
        self.run_threads(self.worker(False))
        db = self.db()
        g = db.execute("SELECT tokens_in + tokens_out FROM global_usage").fetchone()[0]
        self.assertLess(g, 30000 + N * 150)
        self.assertGreaterEqual(g, 30000)


class TestAdmission(Env):
    patch = {"quotas": {"session_tasks_per_day": 7, "session_max_active": 200, "max_queued": 200}}

    def test_C2_quota_exactly_k(self):
        svc = Service(self.cfg, run_task_fn=FakeRunTask(), start_workers=False)
        svc.start()
        self.addCleanup(svc.stop)
        port = svc.address[1]
        cookie = open_session(port)
        results = self.run_threads(lambda i: jpost(port, "/tasks", TASK, cookie)[:2])
        accepted = [r for r in results if r[0] == 202]
        self.assertEqual(len(accepted), 7)
        self.assertTrue(all(r[0] == 429 and r[1]["error"]["code"] == "session_task_quota"
                            for r in results if r[0] != 202))
        self.assertEqual(self.db().execute("SELECT count(*) FROM tasks").fetchone()[0], 7)


class TestQueueBound(Env):
    patch = {"quotas": {"max_queued": 5}}

    def test_C3_queue_bound(self):
        svc = Service(self.cfg, run_task_fn=FakeRunTask(), start_workers=False)
        svc.start()
        self.addCleanup(svc.stop)
        port = svc.address[1]
        cookies = [open_session(port) for _ in range(N)]
        results = self.run_threads(lambda i: jpost(port, "/tasks", TASK, cookies[i])[0])
        self.assertEqual(results.count(202), 5)
        self.assertEqual(results.count(503), N - 5)
        self.assertEqual(self.db().execute("SELECT count(*) FROM tasks WHERE status='queued'").fetchone()[0], 5)


class TestReviewRace(Env):
    def test_C4_single_decision(self):
        fake = FakeRunTask(outcome=make_outcome(diff_text="diff\n"))
        svc = Service(self.cfg, run_task_fn=fake)
        svc.start()
        self.addCleanup(svc.stop)
        port = svc.address[1]
        cookie = open_session(port)
        status, body, _ = jpost(port, "/tasks", TASK, cookie)
        tid = body["task"]["id"]
        wait_task_done(port, cookie, tid)
        decisions = ["approve", "reject"] * 10
        results = self.run_threads(lambda i: jpost(port, f"/tasks/{tid}/review",
                                                   {"decision": decisions[i]}, cookie)[0], n=20)
        self.assertEqual(results.count(200), 1)
        self.assertEqual(results.count(409), 19)
        row = self.db().execute("SELECT review_state, decided_at FROM tasks WHERE id=?", (tid,)).fetchone()
        self.assertIn(row[0], ("approved", "rejected"))
        self.assertIsNotNone(row[1])


if __name__ == "__main__":
    unittest.main()
