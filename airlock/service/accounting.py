"""Budget, quotas and breakers. Every ledger write of one charge happens in ONE write transaction."""
from __future__ import annotations

import logging
import sqlite3
from typing import Literal

from . import store as _store
from .clock import Clock, utc_day
from .config import InferenceConfig, ServiceConfig
from .store import Busy, Store

_log = logging.getLogger("airlock.service")

CANCEL_REASONS: frozenset[str] = frozenset({
    "budget_session_tokens", "budget_global_tokens", "budget_global_usd",
    "budget_breaker_admin", "budget_watchdog", "budget_accounting_error"})
BREAKER_REASONS: frozenset[str] = frozenset({"global_daily_tokens", "global_usd_cap", "admin"})
BREAKER_TO_CANCEL: dict[str, str] = {
    "global_daily_tokens": "budget_global_tokens",
    "global_usd_cap": "budget_global_usd",
    "admin": "budget_breaker_admin"}
MAX_CHARGE_TOKENS: int = 10**12        # per argument; larger or invalid -> treated as accounting error


def cost_micros(tokens_in: int, tokens_out: int, inference: InferenceConfig) -> int:
    """Integer micro-USD, rounded up."""
    return (tokens_in * inference.price_in_micros_per_mtok
            + tokens_out * inference.price_out_micros_per_mtok + 999_999) // 1_000_000


class Refusal(Exception):
    """Admission refused. .code is a key of httpapi.ERRORS. No other attributes, no text."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Accounting:
    def __init__(self, cfg: ServiceConfig, clock: Clock) -> None:
        self._cfg = cfg
        self._clock = clock

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _global_tokens(conn: sqlite3.Connection, day: str) -> int:
        row = conn.execute("SELECT tokens_in + tokens_out FROM global_usage WHERE day = ?",
                           (day,)).fetchone()
        return int(row[0]) if row else 0

    @staticmethod
    def _session_tokens(conn: sqlite3.Connection, session_pk: int, day: str) -> int:
        row = conn.execute("SELECT tokens FROM session_usage WHERE session_pk = ? AND day = ?",
                           (session_pk, day)).fetchone()
        return int(row[0]) if row else 0

    # ------------------------------------------------------------------ T2 charge

    def charge_in_tx(self, conn: sqlite3.Connection, task_pk: int, session_pk: int,
                     tokens_in: int, tokens_out: int) -> str | None:
        """Add one LLM call's tokens to the task, the session day, the global day and the USD
        total. Must run inside Store.write_tx. Returns a cancel string or None."""
        cfg = self._cfg
        now = self._clock.now_ms()
        day = utc_day(now)
        cost = cost_micros(tokens_in, tokens_out, cfg.inference)
        # A purged task row is tolerated (0 rows): the spend is still global spend.
        conn.execute("UPDATE tasks SET tokens_in = tokens_in + ?, tokens_out = tokens_out + ?, "
                     "cost_micros = cost_micros + ? WHERE pk = ?",
                     (tokens_in, tokens_out, cost, task_pk))
        # Guarded by EXISTS so a purged session cannot turn the whole charge into an FK failure.
        conn.execute("INSERT INTO session_usage(session_pk, day, tasks, tokens) "
                     "SELECT ?, ?, 0, ? WHERE EXISTS (SELECT 1 FROM sessions WHERE pk = ?) "
                     "ON CONFLICT(session_pk, day) DO UPDATE SET tokens = tokens + excluded.tokens",
                     (session_pk, day, tokens_in + tokens_out, session_pk))
        conn.execute("INSERT INTO global_usage(day, tokens_in, tokens_out, cost_micros) "
                     "VALUES (?, ?, ?, ?) ON CONFLICT(day) DO UPDATE SET "
                     "tokens_in = tokens_in + excluded.tokens_in, "
                     "tokens_out = tokens_out + excluded.tokens_out, "
                     "cost_micros = cost_micros + excluded.cost_micros",
                     (day, tokens_in, tokens_out, cost))
        conn.execute("UPDATE breaker SET usd_spent_micros = usd_spent_micros + ?, "
                     "tokens_lifetime = tokens_lifetime + ? WHERE id = 1",
                     (cost, tokens_in + tokens_out))

        global_tokens = self._global_tokens(conn, day)
        brk = conn.execute("SELECT state, reason, usd_spent_micros FROM breaker WHERE id = 1").fetchone()
        state, reason, usd_spent = brk[0], brk[1], int(brk[2])
        session_tokens = self._session_tokens(conn, session_pk, day)

        usd_cap = cfg.quotas.usd_cap_micros
        token_cap = cfg.quotas.global_tokens_per_day
        if usd_spent >= usd_cap:
            if state == "closed":
                self.open_breaker_in_tx(conn, "global_usd_cap", "charge")
                state, reason = "open", "global_usd_cap"
            elif reason != "global_usd_cap":
                # The USD breaker never auto-closes, so an open daily/admin breaker is upgraded.
                conn.execute("UPDATE breaker SET reason = 'global_usd_cap' WHERE id = 1")
                conn.execute("INSERT INTO breaker_log(at, action, reason, actor) "
                             "VALUES (?, 'upgrade', 'global_usd_cap', 'charge')", (now,))
                reason = "global_usd_cap"
        elif global_tokens >= token_cap and state == "closed":
            self.open_breaker_in_tx(conn, "global_daily_tokens", "charge")
            state, reason = "open", "global_daily_tokens"

        # State-based result (not only on the crossing call): bounds the overshoot.
        if usd_spent >= usd_cap:
            return "budget_global_usd"
        if global_tokens >= token_cap:
            return "budget_global_tokens"
        if state == "open":
            return BREAKER_TO_CANCEL[reason]
        if session_tokens >= cfg.quotas.session_tokens_per_day:
            return "budget_session_tokens"
        return None

    # ------------------------------------------------------------------ T1 admission

    def admit_in_tx(self, conn: sqlite3.Connection, *, session_pk: int, task_id: str,
                    sample_id: str, preset_id: str | None, instruction: str) -> int:
        """Quota checks and the task insert in one transaction. Returns the task pk or raises
        Refusal (the caller's write_tx then rolls back, so no row is written)."""
        quotas = self._cfg.quotas
        now = self._clock.now_ms()
        day = utc_day(now)
        if conn.execute("SELECT 1 FROM sessions WHERE pk = ? AND expires_at > ?",
                        (session_pk, now)).fetchone() is None:
            raise Refusal("unauthenticated")
        if conn.execute("SELECT state FROM breaker WHERE id = 1").fetchone()[0] == "open":
            raise Refusal("service_paused")
        usage = conn.execute("SELECT tasks, tokens FROM session_usage WHERE session_pk = ? AND day = ?",
                             (session_pk, day)).fetchone()
        used_tasks, used_tokens = (int(usage[0]), int(usage[1])) if usage else (0, 0)
        if used_tasks >= quotas.session_tasks_per_day:
            raise Refusal("session_task_quota")
        if used_tokens >= quotas.session_tokens_per_day:
            raise Refusal("session_token_quota")
        active = conn.execute("SELECT count(*) FROM tasks WHERE session_pk = ? "
                              "AND status IN ('queued', 'running')", (session_pk,)).fetchone()[0]
        if active >= quotas.session_max_active:
            raise Refusal("too_many_active")
        queued = conn.execute("SELECT count(*) FROM tasks WHERE status = 'queued'").fetchone()[0]
        if queued >= quotas.max_queued:
            raise Refusal("queue_full")
        cur = conn.execute("INSERT INTO tasks(id, session_pk, sample_id, preset_id, instruction, "
                           "status, created_at) VALUES (?, ?, ?, ?, ?, 'queued', ?)",
                           (task_id, session_pk, sample_id, preset_id, instruction, now))
        task_pk = int(cur.lastrowid)
        conn.execute("INSERT INTO session_usage(session_pk, day, tasks, tokens) VALUES (?, ?, 1, 0) "
                     "ON CONFLICT(session_pk, day) DO UPDATE SET tasks = tasks + 1", (session_pk, day))
        conn.execute("INSERT INTO global_usage(day, tasks_admitted) VALUES (?, 1) "
                     "ON CONFLICT(day) DO UPDATE SET tasks_admitted = tasks_admitted + 1", (day,))
        return task_pk

    # ------------------------------------------------------------------ breaker

    def open_breaker_in_tx(self, conn: sqlite3.Connection, reason: str, actor: str) -> bool:
        """True iff the closed->open transition happened (then it is logged and queued tasks are
        cancelled in the same transaction)."""
        if reason not in BREAKER_REASONS:
            raise ValueError("invalid breaker reason")
        now = self._clock.now_ms()
        cur = conn.execute("UPDATE breaker SET state = 'open', reason = ?, opened_at = ?, "
                           "opened_day = ? WHERE id = 1 AND state = 'closed'",
                           (reason, now, utc_day(now)))
        if cur.rowcount != 1:
            return False
        conn.execute("INSERT INTO breaker_log(at, action, reason, actor) VALUES (?, 'open', ?, ?)",
                     (now, reason, actor))
        cancelled = conn.execute("UPDATE tasks SET status = 'cancelled', end_reason = ?, "
                                 "finished_at = ? WHERE status = 'queued'",
                                 (BREAKER_TO_CANCEL[reason], now)).rowcount
        _log.warning("breaker opened reason=%s actor=%s cancelled=%d", reason, actor, cancelled)
        return True

    def close_breaker_in_tx(self, conn: sqlite3.Connection,
                            actor: str) -> Literal["closed", "noop", "refused"]:
        now = self._clock.now_ms()
        brk = conn.execute("SELECT state, usd_spent_micros FROM breaker WHERE id = 1").fetchone()
        if brk[0] == "closed":
            return "noop"
        if (int(brk[1]) >= self._cfg.quotas.usd_cap_micros
                or self._global_tokens(conn, utc_day(now)) >= self._cfg.quotas.global_tokens_per_day):
            return "refused"
        conn.execute("UPDATE breaker SET state = 'closed', reason = NULL, opened_at = NULL, "
                     "opened_day = NULL WHERE id = 1")
        conn.execute("INSERT INTO breaker_log(at, action, reason, actor) VALUES (?, 'close', NULL, ?)",
                     (now, actor))
        _log.warning("breaker closed actor=%s", actor)
        return "closed"

    def rollover_in_tx(self, conn: sqlite3.Connection) -> bool:
        """Close a daily-token breaker once the UTC day has changed, unless a cap is still hit."""
        now = self._clock.now_ms()
        day = utc_day(now)
        brk = conn.execute("SELECT state, reason, opened_day, usd_spent_micros FROM breaker "
                           "WHERE id = 1").fetchone()
        if brk[0] != "open" or brk[1] != "global_daily_tokens":
            return False
        if not (brk[2] < day):
            return False
        if int(brk[3]) >= self._cfg.quotas.usd_cap_micros:
            return False
        if self._global_tokens(conn, day) >= self._cfg.quotas.global_tokens_per_day:
            return False
        conn.execute("UPDATE breaker SET state = 'closed', reason = NULL, opened_at = NULL, "
                     "opened_day = NULL WHERE id = 1")
        conn.execute("INSERT INTO breaker_log(at, action, reason, actor) "
                     "VALUES (?, 'close', 'global_daily_tokens', 'scheduler')", (now,))
        _log.warning("breaker closed at day rollover")
        return True

    # ------------------------------------------------------------------ reconcile / read

    def reconcile_in_tx(self, conn: sqlite3.Connection, task_pk: int, session_pk: int,
                        outcome_in: int, outcome_out: int) -> None:
        """Charge only what the outcome reports beyond what the task row already holds."""
        row = conn.execute("SELECT tokens_in, tokens_out FROM tasks WHERE pk = ?", (task_pk,)).fetchone()
        if row is None:
            return          # task purged: its earlier charges already reached the global ledgers
        delta_in = max(0, outcome_in - int(row[0]))
        delta_out = max(0, outcome_out - int(row[1]))
        if delta_in > 0 or delta_out > 0:
            self.charge_in_tx(conn, task_pk, session_pk, delta_in, delta_out)

    def stop_reason(self, conn: sqlite3.Connection, session_pk: int) -> str | None:
        """Read-only (autocommit): breaker open -> its cancel string, else session cap, else None."""
        brk = conn.execute("SELECT state, reason FROM breaker WHERE id = 1").fetchone()
        if brk[0] == "open":
            return BREAKER_TO_CANCEL[brk[1]]
        day = utc_day(self._clock.now_ms())
        if self._session_tokens(conn, session_pk, day) >= self._cfg.quotas.session_tokens_per_day:
            return "budget_session_tokens"
        return None


def _valid_tokens(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_CHARGE_TOKENS


class TaskBudget:
    """One per task; implements airlock.agent.Budget on the worker thread's connection."""

    def __init__(self, store: Store, accounting: Accounting, conn: sqlite3.Connection,
                 task_pk: int, session_pk: int, hard_deadline_mono: float, clock: Clock) -> None:
        self._store = store
        self._acct = accounting
        self._conn = conn
        self._task_pk = task_pk
        self._session_pk = session_pk
        self._deadline = hard_deadline_mono
        self._clock = clock
        self.failed = False

    def _commit_charge(self, tokens_in: int, tokens_out: int) -> str | None:
        attempts = max(1, _store.WORKER_TX_ATTEMPTS)
        for attempt in range(attempts):
            try:
                with self._store.write_tx(self._conn):
                    return self._acct.charge_in_tx(self._conn, self._task_pk, self._session_pk,
                                                   tokens_in, tokens_out)
            except Busy:
                if attempt + 1 >= attempts:
                    raise
        raise Busy()        # unreachable: the loop returns or raises

    def charge(self, tokens_in: int, tokens_out: int) -> str | None:
        """NEVER raises. Committed before it returns. A failure is logged by class name only and
        answered with budget_accounting_error (finalize reconciles the spend)."""
        try:
            if not (_valid_tokens(tokens_in) and _valid_tokens(tokens_out)):
                raise ValueError("invalid charge")
            result = self._commit_charge(tokens_in, tokens_out)
            if result is None and self._clock.monotonic() >= self._deadline:
                return "budget_watchdog"
            return result
        except Exception as exc:
            self.failed = True
            _log.error("charge failed task_pk=%d error=%s", self._task_pk, type(exc).__name__)
            return "budget_accounting_error"

    def should_stop(self) -> str | None:
        """NEVER raises. Not cached: every call re-reads the breaker."""
        try:
            if self._clock.monotonic() >= self._deadline:
                return "budget_watchdog"
            return self._acct.stop_reason(self._conn, self._session_pk)
        except Exception as exc:
            _log.error("should_stop failed task_pk=%d error=%s", self._task_pk, type(exc).__name__)
            return "budget_accounting_error"
