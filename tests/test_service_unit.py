"""Unit tests U1..U18, U21 (no Docker, no network, fake run_task)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = pathlib.Path(__file__).resolve().parent
for _p in (str(ROOT), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from service_fakes import (API, KEY, FakeClock, FakeRunTask, LogCapture, at_utc, api,  # noqa: E402
                           docker_calls, env_with_key, five_events, jget, jpost, make_env,
                           make_outcome, open_session, set_docker_ps, wait_for, wait_task_done)
from airlock.agent import END_REASONS  # noqa: E402
from airlock.agent.loop import _CANCEL_RE, _check_cancel  # noqa: E402
from airlock.sandbox import DestroyProof  # noqa: E402
from airlock.service import admin  # noqa: E402
from airlock.service.accounting import (CANCEL_REASONS, Accounting, Refusal, TaskBudget,  # noqa: E402
                                        cost_micros)
from airlock.service.app import Service, StartupError  # noqa: E402
from airlock.service.clock import utc_day  # noqa: E402
from airlock.service.config import ConfigError, load_config  # noqa: E402
from airlock.service.execution import ClaimedTask, build_report, finalize  # noqa: E402
from airlock.service.manifest import ManifestError, load_manifest  # noqa: E402
from airlock.service.ratelimit import RateLimiter, client_key  # noqa: E402
from airlock.service.scheduler import (Scheduler, claim_next, list_stuck, purge_now,  # noqa: E402
                                       recover_interrupted)
from airlock.service.store import Busy, Store, StoreError  # noqa: E402


class Base(unittest.TestCase):
    patch: dict = {}

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="airlock-unit-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = env_with_key()
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cfg_path, self.manifest_path, self.docker_dir = make_env(self.tmp, patch=self.patch)
        self.cfg = load_config(self.cfg_path)
        self.clock = FakeClock()
        self.store = Store(self.cfg.db_path)
        self.store.initialize()
        self.acct = Accounting(self.cfg, self.clock)
        self.conn = self.store.connect(busy_timeout_ms=5000)
        self.addCleanup(self.conn.close)

    # ---- helpers
    def new_session(self, conn=None, expires_in_ms: int = 3_600_000, created_ms: int | None = None) -> int:
        conn = conn or self.conn
        now = self.clock.now_ms() if created_ms is None else created_ms
        with self.store.write_tx(conn):
            cur = conn.execute("INSERT INTO sessions(token_hash, created_at, expires_at) VALUES (?,?,?)",
                               (os.urandom(32), now, now + expires_in_ms))
        return cur.lastrowid

    def expire_session(self, session_pk: int) -> None:
        """Make a session that was valid at admission time expire (admission itself stays strict)."""
        now = self.clock.now_ms()
        with self.store.write_tx(self.conn):
            self.conn.execute("UPDATE sessions SET created_at=?, expires_at=? WHERE pk=?",
                              (now - 100_000, now - 1, session_pk))

    def admit(self, session_pk: int, conn=None) -> tuple[int, str]:
        conn = conn or self.conn
        task_id = os.urandom(16).hex()
        with self.store.write_tx(conn):
            pk = self.acct.admit_in_tx(conn, session_pk=session_pk, task_id=task_id, sample_id="s1",
                                       preset_id=None, instruction="do it")
        return pk, task_id

    def set_status(self, pk: int, status: str, *, created_ms: int | None = None,
                   started_ms: int | None = None) -> None:
        with self.store.write_tx(self.conn):
            if status == "running":
                self.conn.execute("UPDATE tasks SET status='running', started_at=? WHERE pk=?",
                                  (started_ms or self.clock.now_ms(), pk))
            if created_ms is not None:
                self.conn.execute("UPDATE tasks SET created_at=? WHERE pk=?", (created_ms, pk))

    def budget(self, task_pk: int, session_pk: int, conn=None) -> TaskBudget:
        return TaskBudget(self.store, self.acct, conn or self.conn, task_pk, session_pk,
                          self.clock.monotonic() + 1000.0, self.clock)

    def one(self, sql: str, *args):
        return self.conn.execute(sql, args).fetchone()

    def global_tokens(self) -> int:
        row = self.one("SELECT tokens_in + tokens_out FROM global_usage WHERE day = ?",
                       utc_day(self.clock.now_ms()))
        return row[0] if row else 0


class TestConfig(Base):
    def write(self, patch: dict) -> pathlib.Path:
        path, _, _ = make_env(self.tmp / "cfg", patch=patch) if (self.tmp / "cfg").mkdir(exist_ok=True) is None else (None,) * 3
        return path

    def test_U1_config(self):
        self.assertEqual(self.cfg.quotas.max_queued, 20)
        for patch in ({"bogus": 1}, {"quotas": {"max_running": True}},
                      {"inference": {"api_key_file": "/nonexistent/key"}},
                      {"inference": {"price_in_usd_per_mtok": 0}},
                      {"retention": {"task_retention_s": 82801}},
                      {"listen": {"host": "0.0.0.0"}}, {"quotas": {"unknown_quota": 1}}):
            with self.subTest(patch=patch):
                with self.assertRaises(ConfigError):
                    load_config(self.write(patch))
        with self.assertRaises(ConfigError) as ctx:
            load_config(self.write({"public_origin": "CANARYORIGIN-not-an-origin", "bogus": 1}))
        self.assertNotIn("CANARYORIGIN", str(ctx.exception))


class TestManifest(Base):
    def write_manifest(self, sample: dict) -> pathlib.Path:
        d = self.tmp / "mf"
        shutil.rmtree(d, ignore_errors=True)
        (d / "ok").mkdir(parents=True)
        (self.tmp / "outside").mkdir(exist_ok=True)
        (d / "link").symlink_to(self.tmp / "outside")
        base = {"id": "s1", "title": "t", "description": "d", "path": "ok", "presets": []}
        base.update(sample)
        (d / "manifest.json").write_text(json.dumps({"version": 1, "samples": [base]}), encoding="utf-8")
        return d / "manifest.json"

    def test_U2_manifest(self):
        manifest = load_manifest(self.manifest_path)
        self.assertNotIn("path", json.dumps(manifest.public_view()))
        for sample in ({"path": "../outside"}, {"path": "link"}, {"path": "missing"},
                       {"path": "outside/../ok/.."},
                       {"presets": [{"id": "p", "title": "t", "description": "d", "instruction": "a\x00b"}]},
                       {"presets": [{"id": "p", "title": "t", "description": "d", "instruction": "x" * 2001}]}):
            with self.subTest(sample=sample), self.assertRaises(ManifestError):
                load_manifest(self.write_manifest(sample))
        # intermediate symlink: no ".." component, but the resolved path leaves the manifest dir
        mf = self.write_manifest({"path": "link/sub"})
        (self.tmp / "outside" / "sub").mkdir(exist_ok=True)
        with self.assertRaises(ManifestError):
            load_manifest(mf)
        dup = self.tmp / "dup"
        (dup / "ok").mkdir(parents=True)
        entry = {"id": "s1", "title": "t", "description": "d", "path": "ok", "presets": []}
        (dup / "manifest.json").write_text(json.dumps({"version": 1, "samples": [entry, entry]}))
        with self.assertRaises(ManifestError):
            load_manifest(dup / "manifest.json")


class TestStore(Base):
    def test_U3_store_init(self):
        self.assertEqual(self.one("PRAGMA user_version")[0], 1)
        self.assertEqual(self.one("PRAGMA journal_mode")[0], "wal")
        self.assertEqual(self.cfg.db_path.stat().st_mode & 0o777, 0o600)
        raw = sqlite3.connect(self.cfg.db_path)
        raw.execute("PRAGMA user_version = 2")
        raw.close()
        with self.assertRaises(StoreError) as ctx:
            Store(self.cfg.db_path).initialize()
        self.assertEqual(str(ctx.exception), "schema_version")
        other = Store(self.tmp / "fresh" / "x.sqlite3")
        with mock.patch.object(Store, "_enable_wal", return_value="delete"):
            with self.assertRaises(StoreError) as ctx:
                other.initialize()
        self.assertEqual(str(ctx.exception), "wal")


class TestCharge(Base):
    patch = {"quotas": {"usd_cap": 0.0004, "session_tokens_per_day": 1000}}

    def test_U4_single_charge_and_precedence(self):
        sess = self.new_session()
        pk, _ = self.admit(sess)
        result = self.budget(pk, sess).charge(1000, 500)
        self.assertEqual(result, "budget_global_usd")
        task = self.one("SELECT tokens_in, tokens_out, cost_micros FROM tasks WHERE pk=?", pk)
        self.assertEqual(tuple(task), (1000, 500, 450))
        self.assertEqual(self.one("SELECT tokens FROM session_usage WHERE session_pk=?", sess)[0], 1500)
        g = self.one("SELECT tokens_in, tokens_out, cost_micros FROM global_usage")
        self.assertEqual(tuple(g), (1000, 500, 450))
        self.assertEqual(self.one("SELECT usd_spent_micros FROM breaker")[0], 450)

    def test_U5_rounding(self):
        self.assertEqual(cost_micros(1, 0, self.cfg.inference), 1)
        self.assertEqual(cost_micros(0, 0, self.cfg.inference), 0)


class TestBreaker(Base):
    def test_U6_open_cancels_queued(self):
        sess = self.new_session()
        pk, _ = self.admit(sess)
        with self.store.write_tx(self.conn):
            self.assertTrue(self.acct.open_breaker_in_tx(self.conn, "admin", "admin"))
            self.assertFalse(self.acct.open_breaker_in_tx(self.conn, "admin", "admin"))
        row = self.one("SELECT status, end_reason FROM tasks WHERE pk=?", pk)
        self.assertEqual(tuple(row), ("cancelled", "budget_breaker_admin"))
        self.assertIsNone(claim_next(self.store, self.conn, 4, self.clock))

    def _daily_breaker(self):
        sess = self.new_session()
        pk, _ = self.admit(sess)
        with self.store.write_tx(self.conn):
            self.acct.open_breaker_in_tx(self.conn, "global_daily_tokens", "charge")
        return sess, pk

    def test_U6b_rollover(self):
        self._daily_breaker()
        with self.store.write_tx(self.conn):
            self.assertFalse(self.acct.rollover_in_tx(self.conn))
        self.assertEqual(self.one("SELECT state FROM breaker")[0], "open")
        self.clock.set_ms(at_utc(2100, 1, 2, 0, 0, 1))
        pool = mock.Mock()
        Scheduler(self.store, self.acct, self.cfg, self.clock, pool, __import__("threading").Event()).tick()
        self.assertEqual(self.one("SELECT state FROM breaker")[0], "closed")

    def test_U6c_usd_upgrade_survives_rollover(self):
        cfg = load_config(make_env(self.tmp / "u6c", patch={"quotas": {
            "global_tokens_per_day": 100, "usd_cap": 0.0004}})[0]) if (self.tmp / "u6c").mkdir() is None else None
        clock = FakeClock()
        store = Store(self.tmp / "u6c" / "data" / "airlock.sqlite3")
        store.initialize()
        acct = Accounting(cfg, clock)
        conn = store.connect(busy_timeout_ms=5000)
        self.addCleanup(conn.close)
        with store.write_tx(conn):
            conn.execute("INSERT INTO sessions(token_hash, created_at, expires_at) VALUES (?,?,?)",
                         (os.urandom(32), clock.now_ms(), clock.now_ms() + 10**9))
        b = TaskBudget(store, acct, conn, 0, 1, clock.monotonic() + 100, clock)
        self.assertEqual(b.charge(60, 60), "budget_global_tokens")
        self.assertEqual(conn.execute("SELECT reason FROM breaker").fetchone()[0], "global_daily_tokens")
        self.assertEqual(b.charge(1000, 500), "budget_global_usd")
        clock.set_ms(clock.now_ms() + 2 * 86_400_000)
        with store.write_tx(conn):
            acct.rollover_in_tx(conn)
        state = tuple(conn.execute("SELECT state, reason FROM breaker").fetchone())
        self.assertEqual(state, ("open", "global_usd_cap"))
        with store.write_tx(conn):
            self.assertEqual(acct.close_breaker_in_tx(conn, "admin"), "refused")


class TestDurability(Base):
    def test_U7_crash_after_charge(self):
        sess = self.new_session()
        pk, _ = self.admit(sess)
        code = ("import sys, os\nsys.path.insert(0, sys.argv[1])\n"
                "from airlock.service.config import load_config\n"
                "from airlock.service.store import Store\n"
                "from airlock.service.accounting import Accounting, TaskBudget\n"
                "from airlock.service.clock import SystemClock\n"
                "cfg = load_config(__import__('pathlib').Path(sys.argv[2]))\n"
                "store = Store(cfg.db_path); c = SystemClock(); conn = store.connect(busy_timeout_ms=5000)\n"
                "b = TaskBudget(store, Accounting(cfg, c), conn, int(sys.argv[3]), int(sys.argv[4]), "
                "c.monotonic() + 100, c)\n"
                "b.charge(100, 50)\nos._exit(9)\n")
        proc = subprocess.run([sys.executable, "-c", code, str(ROOT), str(self.cfg_path), str(pk), str(sess)],
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True,
                              timeout=60, check=False)
        self.assertEqual(proc.returncode, 9, proc.stderr)
        self.assertEqual(self.one("SELECT tokens_in FROM tasks WHERE pk=?", pk)[0], 100)

    def test_U8_charge_failure_then_finalize_reconciles(self):
        sess = self.new_session()
        pk, _ = self.admit(sess)
        blocker = self.store.connect(busy_timeout_ms=50)
        self.addCleanup(blocker.close)
        budget_conn = self.store.connect(busy_timeout_ms=50)
        self.addCleanup(budget_conn.close)
        budget = TaskBudget(self.store, self.acct, budget_conn, pk, sess,
                            self.clock.monotonic() + 100, self.clock)
        blocker.execute("BEGIN IMMEDIATE")
        # The retry count lives in airlock.service.store and is read at call time by the charge path.
        with mock.patch("airlock.service.store.WORKER_TX_ATTEMPTS", 1):
            self.assertEqual(budget.charge(100, 50), "budget_accounting_error")
        blocker.execute("ROLLBACK")
        self.assertTrue(budget.failed)
        self.assertEqual(self.global_tokens(), 0)
        task = ClaimedTask(pk, "x" * 32, sess, "s1", "do it")
        self.set_status(pk, "running")
        outcome = make_outcome("agent_finished", tokens_in=100, tokens_out=50)
        finalize(self.store, self.acct, self.conn, task, outcome, self.clock, 10**6, True)
        self.assertEqual(self.global_tokens(), 150)

    def test_U8b_no_double_count(self):
        sess = self.new_session()
        pk, _ = self.admit(sess)
        b = self.budget(pk, sess)
        b.charge(100, 50)
        b.charge(100, 50)
        self.set_status(pk, "running")
        task = ClaimedTask(pk, "x" * 32, sess, "s1", "do it")
        finalize(self.store, self.acct, self.conn, task,
                 make_outcome(tokens_in=200, tokens_out=100), self.clock, 10**6, True)
        self.assertEqual(self.global_tokens(), 300)

    def test_U9_fresh_should_stop(self):
        sess = self.new_session()
        pk, _ = self.admit(sess)
        b = self.budget(pk, sess)
        self.assertIsNone(b.should_stop())
        other = self.store.connect(busy_timeout_ms=5000)
        self.addCleanup(other.close)
        with self.store.write_tx(other):
            self.acct.open_breaker_in_tx(other, "admin", "admin")
        self.assertEqual(b.should_stop(), "budget_breaker_admin")

    def test_U13b_late_charge_after_purge(self):
        sess = self.new_session()
        pk, _ = self.admit(sess)
        b = self.budget(pk, sess)
        with self.store.write_tx(self.conn):
            self.conn.execute("DELETE FROM sessions WHERE pk=?", (sess,))
        b.charge(10, 0)
        self.assertEqual(self.global_tokens(), 10)

    def test_U17_watchdog(self):
        # Design: 636.6 / 936.6 hold under the default agent and inference timings, so build
        # a config that leaves wall_clock_s (300) and request_timeout_s (120) at their defaults.
        default_cfg = load_config(make_env(self.tmp / "u17", patch={
            "agent": {"wall_clock_s": 300}, "inference": {"request_timeout_s": 120}})[0])
        self.assertAlmostEqual(default_cfg.hard_deadline_s, 636.6, places=3)
        self.assertAlmostEqual(default_cfg.stuck_after_s, 936.6, places=3)
        # The formula over this config's own values.
        expected = (self.cfg.agent.wall_clock_s + self.cfg.inference.request_timeout_s
                    + self.cfg.agent.limits.command_timeout_s + 36.6 + 120.0)
        self.assertAlmostEqual(self.cfg.hard_deadline_s, expected, places=3)
        self.assertAlmostEqual(self.cfg.stuck_after_s, expected + 300.0, places=3)
        sess = self.new_session()
        pk, _ = self.admit(sess)
        b = self.budget(pk, sess)
        self.clock.set_monotonic(self.clock.monotonic() + 1001.0)
        self.assertEqual(b.should_stop(), "budget_watchdog")


class TestReportAndFinalize(Base):
    def test_U10_report(self):
        proof = DestroyProof("abc123def456", True, None)
        outcome = make_outcome("sandbox_error", proof=True)
        events = [(1, {"type": "tool_call", "tool": "finish", "step": 1, "args": {}, "args_truncated": False}),
                  (2, {"type": "tool_result", "tool": "run_command", "step": 2, "limit_hit": None})]
        report = build_report(outcome, events, events_complete=True, cost_micros=0)
        self.assertTrue(report["contained"])
        self.assertEqual(report["sandbox"], "destroyed")
        self.assertIn("sandbox_killed", [h["limit"] for h in report["limit_hits"]])
        self.assertEqual(report["tools_used"]["finish"], 1)
        events[1][1]["limit_hit"] = "memory"
        report = build_report(outcome, events, events_complete=True, cost_micros=0)
        self.assertIn("memory", [h["limit"] for h in report["limit_hits"]])
        self.assertNotIn("oom", json.dumps(report).lower())
        self.assertIsNotNone(proof)

    def _run(self, outcome, events_types=()):
        sess = self.new_session()
        pk, tid = self.admit(sess)
        self.set_status(pk, "running")
        with self.store.write_tx(self.conn):
            for i, t in enumerate(events_types, 1):
                self.conn.execute("UPDATE tasks SET last_seq=? WHERE pk=?", (i, pk))
                self.conn.execute("INSERT INTO task_events VALUES (?,?,?,?,?)",
                                  (pk, i, "task_finished", 1, json.dumps({"type": "task_finished", "reason": t})))
        task = ClaimedTask(pk, tid, sess, "s1", "do it")
        reason = finalize(self.store, self.acct, self.conn, task, outcome, self.clock, 100, True)
        return pk, reason

    def test_U11_finalize(self):
        pk, reason = self._run(make_outcome("internal_error"), ["agent_finished"])
        self.assertEqual(reason, "internal_error")
        self.assertEqual(self.one("SELECT end_reason FROM tasks WHERE pk=?", pk)[0], "internal_error")
        pk, _ = self._run(make_outcome("agent_finished"))
        self.assertEqual(tuple(self.one("SELECT review_state FROM tasks WHERE pk=?", pk)), ("none",))
        self.assertIsNone(self.one("SELECT 1 FROM task_diffs WHERE task_pk=?", pk))
        pk, _ = self._run(make_outcome("agent_finished", diff_text="diff\n"))
        self.assertEqual(self.one("SELECT review_state FROM tasks WHERE pk=?", pk)[0], "pending")
        self.assertIsNotNone(self.one("SELECT 1 FROM task_diffs WHERE task_pk=?", pk))
        pk, _ = self._run(make_outcome("agent_finished", diff_text="x" * 101))
        self.assertIsNone(self.one("SELECT 1 FROM task_diffs WHERE task_pk=?", pk))
        pk, reason = self._run(None)
        self.assertEqual(reason, "internal_error")


class TestRestartPurge(Base):
    HEX = ["a" * 64, "b" * 64]

    def test_U12_restart(self):
        set_docker_ps(self.docker_dir, self.HEX)
        sess = self.new_session()
        q, _ = self.admit(sess)
        r, _ = self.admit(sess)
        self.set_status(r, "running")
        with LogCapture() as logs:
            svc = Service(self.cfg, run_task_fn=FakeRunTask(), start_workers=False)
            svc.start()
        self.addCleanup(svc.stop)
        rm = [c for c in docker_calls(self.docker_dir) if c[:2] == ["rm", "-f"]]
        self.assertEqual(sorted(rm), sorted([["rm", "-f", h] for h in self.HEX]))
        statuses = {row[0] for row in self.conn.execute("SELECT status FROM tasks")}
        self.assertEqual(statuses, {"interrupted"})
        for h in self.HEX:
            self.assertNotIn(h, logs.text)
        set_docker_ps(self.docker_dir, ["not-hex"])
        with self.assertRaises(StartupError) as ctx:
            Service(self.cfg, run_task_fn=FakeRunTask(), start_workers=False).start()
        self.assertEqual(str(ctx.exception), "leftover_list")

    def test_U13_purge(self):
        now = self.clock.now_ms()
        sess = self.new_session()
        old, _ = self.admit(sess)
        recent, _ = self.admit(sess)
        self.set_status(old, "running", created_ms=now - 24 * 3600_000)
        self.set_status(recent, "running", created_ms=now - 22 * 3600_000)
        with self.store.write_tx(self.conn):
            for seq in (1, 2, 3):
                self.conn.execute("INSERT INTO task_events VALUES (?,?,?,?,?)", (old, seq, "tool_call", now, "{}"))
        # An expired session with no active task: the task is created while the session is valid,
        # finished, and only then does the session expire.
        expired = self.new_session()
        exp_task, _ = self.admit(expired)
        with self.store.write_tx(self.conn):
            self.conn.execute("UPDATE tasks SET status='running', started_at=? WHERE pk=?", (now, exp_task))
            self.conn.execute("UPDATE tasks SET status='finished', end_reason='agent_finished', "
                              "finished_at=? WHERE pk=?", (now, exp_task))
        self.expire_session(expired)
        counts = purge_now(self.store, self.conn, self.cfg, self.clock)
        self.assertGreaterEqual(counts.tasks, 1)
        self.assertIsNone(self.one("SELECT 1 FROM tasks WHERE pk=?", old))
        self.assertIsNone(self.one("SELECT 1 FROM task_events WHERE task_pk=?", old))
        self.assertIsNotNone(self.one("SELECT 1 FROM tasks WHERE pk=?", recent))
        self.assertIsNone(self.one("SELECT 1 FROM sessions WHERE pk=?", expired))
        self.assertIsNone(self.one("SELECT 1 FROM tasks WHERE pk=?", exp_task))
        # An expired session that still has a running task is kept.
        busy = self.new_session()
        btask, _ = self.admit(busy)
        self.set_status(btask, "running")
        self.expire_session(busy)
        purge_now(self.store, self.conn, self.cfg, self.clock)
        self.assertIsNotNone(self.one("SELECT 1 FROM sessions WHERE pk=?", busy))
        self.assertIsNotNone(self.one("SELECT 1 FROM tasks WHERE pk=?", btask))

    def test_U13_purge_at_startup(self):
        now = self.clock.now_ms()
        sess = self.new_session()
        pk, _ = self.admit(sess)
        with self.store.write_tx(self.conn):
            self.conn.execute("UPDATE tasks SET status='finished', end_reason='agent_finished', "
                              "finished_at=?, created_at=? WHERE pk=?", (now, now - 24 * 3600_000, pk))
        svc = Service(self.cfg, run_task_fn=FakeRunTask(), start_workers=False)
        svc.start()
        self.addCleanup(svc.stop)
        self.assertEqual(self.one("SELECT count(*) FROM tasks")[0], 0)

    def test_U21_claim_bound_and_fifo(self):
        sess = self.new_session()
        pks = [self.admit(sess)[0] for _ in range(3)]
        self.set_status(pks[0], "running")
        self.set_status(pks[1], "running")
        self.assertIsNone(claim_next(self.store, self.conn, 2, self.clock))
        with self.store.write_tx(self.conn):
            self.conn.execute("UPDATE tasks SET status='queued', started_at=NULL WHERE pk=?", (pks[1],))
        first = claim_next(self.store, self.conn, 4, self.clock)
        second = claim_next(self.store, self.conn, 4, self.clock)
        self.assertEqual((first.pk, second.pk), (pks[1], pks[2]))


class TestRateAndClient(unittest.TestCase):
    def test_U14_client_key_and_limiter(self):
        self.assertEqual(client_key("203.0.113.9", "198.51.100.7", True), "203.0.113.9")
        self.assertEqual(client_key("127.0.0.1", "198.51.100.1, 198.51.100.7", True), "198.51.100.7")
        self.assertEqual(client_key("127.0.0.1", "garbage", True), "invalid")
        self.assertEqual(client_key("::ffff:203.0.113.9", None, False), "203.0.113.9")
        self.assertEqual(client_key("2001:db8::1", None, False), client_key("2001:db8::2", None, False))
        now = [3600.0 * 10]
        rl = RateLimiter(clock_s=lambda: now[0])
        self.assertEqual([rl.allow("tasks", "a", 3) for _ in range(4)], [True, True, True, False])
        now[0] += 3600
        self.assertTrue(rl.allow("tasks", "a", 3))
        small = RateLimiter(clock_s=lambda: now[0], max_keys=2)
        self.assertTrue(small.allow("tasks", "k1", 5))
        self.assertTrue(small.allow("tasks", "k2", 5))
        self.assertFalse(small.allow("tasks", "k3", 5))

    def test_U16_cancel_strings(self):
        for reason in CANCEL_REASONS:
            with self.subTest(reason=reason):
                self.assertRegex(reason, _CANCEL_RE)
                self.assertNotIn(reason, END_REASONS)
                self.assertEqual(_check_cancel(reason), reason)


class TestLogs(Base):
    def test_U15_logs(self):
        events = five_events() + [{"type": "tool_call", "step": 9, "tool": "PAYLOADTEXT77",
                                   "args": {}, "args_truncated": False}]
        fake = FakeRunTask(events=events)
        stderr = io.StringIO()
        with LogCapture() as logs, contextlib.redirect_stderr(stderr):
            svc = Service(self.cfg, run_task_fn=fake)
            svc.start()
            self.addCleanup(svc.stop)
            port = svc.address[1]
            cookie = open_session(port)
            status, body, _ = jpost(port, "/tasks", {"sample_id": "s1", "instruction": "CANARYINS42"}, cookie)
            self.assertEqual(status, 202)
            wait_task_done(port, cookie, body["task"]["id"])
            jget(port, "/samples")
        blob = logs.text + stderr.getvalue()
        for needle in ("CANARYINS42", "127.0.0.1", "PAYLOADTEXT77", KEY):
            self.assertNotIn(needle, blob)


class TestAdmin(Base):
    patch = {"quotas": {"usd_cap": 0.0004}}

    def run_admin(self, *args: str) -> tuple[int, dict]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = admin.main(["--config", str(self.cfg_path), *args])
        return code, json.loads(out.getvalue())

    def audit(self) -> list[tuple]:
        return [tuple(r) for r in self.conn.execute("SELECT action, result FROM admin_audit ORDER BY pk")]

    def test_U18_admin(self):
        code, status = self.run_admin("status")
        self.assertEqual((code, status["breaker"]["state"]), (0, "closed"))
        self.assertEqual(self.run_admin("breaker", "open")[0], 0)
        self.assertEqual(self.audit(), [("breaker_open", "ok")])
        self.assertEqual(self.run_admin("breaker", "close")[0], 0)
        # Both tasks are admitted while the breaker is closed; the USD cap is crossed afterwards.
        sess = self.new_session()
        pk, _ = self.admit(sess)
        stuck_pk, _ = self.admit(sess)
        now = self.clock.now_ms()
        self.set_status(stuck_pk, "running", started_ms=now - int((self.cfg.stuck_after_s + 60) * 1000))
        self.budget(pk, sess).charge(1000, 500)  # crosses the USD cap and opens the breaker
        code, _ = self.run_admin("breaker", "close")
        self.assertEqual(code, 3)
        self.assertEqual(self.audit()[-1], ("breaker_close", "refused"))
        code, usage = self.run_admin("usage")
        self.assertEqual((code, usage["tokens_in"]), (0, 1000))
        self.assertEqual(self.run_admin("purge")[0], 0)
        self.assertEqual(self.audit()[-1][0], "purge")
        code, stuck = self.run_admin("stuck")
        self.assertEqual(len(stuck["stuck"]), 1)
        self.assertEqual(len(list_stuck(self.conn, self.cfg, self.clock)), 1)


if __name__ == "__main__":
    unittest.main()
