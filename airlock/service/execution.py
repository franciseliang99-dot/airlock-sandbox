"""Event sink, report builder, task finalization and the executor that calls M2."""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

from airlock.agent import END_REASONS, OpenAICompatClient, TaskOutcome
from airlock.agent import events as agent_events
from airlock.agent.events import EVENT_FIELDS, EVENT_MAX_BYTES

from . import store as _store
from .accounting import CANCEL_REASONS, Accounting, TaskBudget
from .clock import Clock
from .config import ServiceConfig
from .manifest import Manifest
from .store import Busy, Store

_log = logging.getLogger("airlock.service")

STORED_EVENT_TYPES: frozenset[str] = frozenset(EVENT_FIELDS)
EVENT_PAYLOAD_MAX: int = EVENT_MAX_BYTES        # 32768
_ALL_END_REASONS: frozenset[str] = frozenset(END_REASONS) | CANCEL_REASONS
_TOOL_KEYS = ("list_dir", "read_file", "write_file", "run_command", "finish", "unknown")


@dataclass(frozen=True)
class ClaimedTask:
    pk: int
    id: str
    session_pk: int
    sample_id: str
    instruction: str


class EventRejected(Exception):
    """The event is not storable (unknown type or too large). Fixed text, no event content."""


class EventSink:
    """M2's sink: assigns seq per task and appends to SQLite (T4). Raises on any failure so that
    M2 marks its emitter broken."""

    def __init__(self, store: Store, conn: sqlite3.Connection, task_pk: int, clock: Clock) -> None:
        self._store = store
        self._conn = conn
        self._task_pk = task_pk
        self._clock = clock
        self.broken = False

    def __call__(self, event: dict) -> None:
        try:
            self._write(event)
        except Exception:
            self.broken = True
            raise

    def _write(self, event: dict) -> None:
        if not isinstance(event, dict) or event.get("type") not in STORED_EVENT_TYPES:
            raise EventRejected("event type is not storable")
        payload = json.dumps(event, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        if len(payload) > EVENT_PAYLOAD_MAX:
            raise EventRejected("event is too large")
        attempts = max(1, _store.WORKER_TX_ATTEMPTS)
        for attempt in range(attempts):
            try:
                with self._store.write_tx(self._conn):
                    cur = self._conn.execute("UPDATE tasks SET last_seq = last_seq + 1 WHERE pk = ?",
                                             (self._task_pk,))
                    if cur.rowcount != 1:
                        raise EventRejected("task row is missing")
                    seq = self._conn.execute("SELECT last_seq FROM tasks WHERE pk = ?",
                                             (self._task_pk,)).fetchone()[0]
                    self._conn.execute("INSERT INTO task_events(task_pk, seq, type, created_at, payload) "
                                       "VALUES (?, ?, ?, ?, ?)",
                                       (self._task_pk, seq, event["type"], self._clock.now_ms(), payload))
                return
            except Busy:
                if attempt + 1 >= attempts:
                    raise


# ---------------------------------------------------------------------- report

def stored_end_reason(outcome: TaskOutcome | None) -> str:
    """The reason that is persisted: the outcome's, if it is a known one, else internal_error."""
    if outcome is None:
        return "internal_error"
    reason = outcome.reason
    return reason if isinstance(reason, str) and reason in _ALL_END_REASONS else "internal_error"


def _short(value: object) -> str:
    return str(value)[:64] if isinstance(value, str) else "unknown"


def _int_or_none(value: object) -> int | None:
    return value if type(value) is int else None


def build_report(outcome: TaskOutcome | None, events: list[tuple[int, dict]],
                 *, events_complete: bool, cost_micros: int) -> dict:
    """Blast-radius report. Counts each event type independently (a tool_call is not assumed to
    be followed by a result) and never asserts the absence of a limit."""
    end_reason = stored_end_reason(outcome)
    tools_used = {name: 0 for name in _TOOL_KEYS}
    blocked: dict[tuple[str, str], dict] = {}
    hits: dict[str, dict] = {}
    for seq, event in events:
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if kind == "tool_call":
            name = event.get("tool")
            key = name if isinstance(name, str) and name in tools_used and name != "unknown" else "unknown"
            tools_used[key] += 1
        elif kind == "action_blocked":
            reason, source = _short(event.get("blocked_reason")), _short(event.get("source"))
            entry = blocked.get((reason, source))
            if entry is None:
                blocked[(reason, source)] = {"reason": reason, "source": source, "count": 1,
                                             "first_seq": seq}
            else:
                entry["count"] += 1
        elif kind == "tool_result":
            limit = event.get("limit_hit")
            if limit in ("timeout", "memory", "pids"):
                entry = hits.get(limit)
                if entry is None:
                    hits[limit] = {"limit": limit, "count": 1, "first_seq": seq}
                else:
                    entry["count"] += 1
    limit_hits = list(hits.values())
    if end_reason in ("step_limit", "wall_timeout"):
        limit_hits.append({"limit": end_reason, "count": 1, "first_seq": None})
    if end_reason in CANCEL_REASONS:
        limit_hits.append({"limit": "budget", "count": 1, "first_seq": None})
    proof = outcome.destroy_proof if outcome is not None else None
    if end_reason == "sandbox_error" and proof is not None:
        # A memory bomb kills the whole sandbox: shown as contained, whatever the late OOM label did.
        limit_hits.append({"limit": "sandbox_killed", "count": 1, "first_seq": None})

    peak = outcome.peak if outcome is not None and isinstance(outcome.peak, dict) else {}
    if proof is None:
        sandbox, destroy_proof = "none", None
    else:
        sandbox = "destroyed" if proof.verified else "destroy_failed"
        destroy_proof = {"container_ref": str(proof.container_ref)[:64],
                         "verified": bool(proof.verified),
                         "error_class": None if proof.error_class is None else str(proof.error_class)[:64]}
    if outcome is None or outcome.diff is None:
        diff = {"state": "none", "size_bytes": 0, "sha256": None, "files": [],
                "files_truncated": False}
    else:
        diff = agent_events.artifact_collected(outcome.diff)
        diff.pop("type", None)
    return {
        "end_reason": end_reason,
        "steps_used": outcome.steps_used if outcome is not None else 0,
        "tokens_in": outcome.tokens_in if outcome is not None else 0,
        "tokens_out": outcome.tokens_out if outcome is not None else 0,
        "cost_usd_micros": cost_micros,
        "tools_used": tools_used,
        "blocked_actions": list(blocked.values()),
        "limit_hits": limit_hits,
        "resource_peak": {"memory_bytes": _int_or_none(peak.get("memory_bytes")),
                          "pids": _int_or_none(peak.get("pids")),
                          "cpu_ms": _int_or_none(peak.get("cpu_ms"))},
        "sandbox": sandbox,
        "destroy_proof": destroy_proof,
        "contained": sandbox != "destroy_failed",
        "diff": diff,
        "events_complete": bool(events_complete),
    }


# ---------------------------------------------------------------------- finalize (T6)

def _read_events(conn: sqlite3.Connection, task_pk: int) -> tuple[list[tuple[int, dict]], bool]:
    out: list[tuple[int, dict]] = []
    complete = True
    for row in conn.execute("SELECT seq, payload FROM task_events WHERE task_pk = ? ORDER BY seq",
                            (task_pk,)):
        try:
            parsed = json.loads(row[1])
        except ValueError:
            complete = False
            continue
        if isinstance(parsed, dict):
            out.append((int(row[0]), parsed))
    return out, complete


def _storable_diff(outcome: TaskOutcome | None, diff_max_bytes: int) -> tuple[str, bytes] | None:
    if outcome is None or outcome.diff is None:
        return None
    diff = outcome.diff
    if diff.state != "ok" or not isinstance(diff.diff_text, str):
        return None
    try:
        encoded = diff.diff_text.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if not 0 < len(encoded) <= diff_max_bytes:
        return None
    return diff.diff_text, encoded


def _token_count(value: object) -> int:
    return value if type(value) is int and value >= 0 else 0


def _finalize_tx(store: Store, accounting: Accounting, conn: sqlite3.Connection,
                 task: ClaimedTask, outcome: TaskOutcome | None, clock: Clock,
                 diff_max_bytes: int, events: list[tuple[int, dict]], complete: bool) -> str:
    end_reason = stored_end_reason(outcome)
    storable = _storable_diff(outcome, diff_max_bytes)
    with store.write_tx(conn):
        if outcome is not None:
            accounting.reconcile_in_tx(conn, task.pk, task.session_pk,
                                       _token_count(outcome.tokens_in), _token_count(outcome.tokens_out))
        row = conn.execute("SELECT cost_micros FROM tasks WHERE pk = ?", (task.pk,)).fetchone()
        if row is None:
            return end_reason                 # purged while it ran: nothing left to update
        report = build_report(outcome, events, events_complete=complete, cost_micros=int(row[0]))
        if storable is None and report["diff"]["state"] == "ok":
            report["diff"]["state"] = "too_large"     # reported "ok" but not stored: say so
        steps = outcome.steps_used if outcome is not None and type(outcome.steps_used) is int else None
        cur = conn.execute(
            "UPDATE tasks SET status = 'finished', end_reason = ?, steps_used = ?, finished_at = ?, "
            "report_json = ?, review_state = ? WHERE pk = ? AND status = 'running'",
            (end_reason, steps, clock.now_ms(), json.dumps(report, ensure_ascii=True),
             "pending" if storable is not None else "none", task.pk))
        if cur.rowcount == 1 and storable is not None:
            text, encoded = storable
            files = agent_events.artifact_collected(outcome.diff)["files"]    # type: ignore[union-attr]
            conn.execute("INSERT INTO task_diffs(task_pk, diff_text, size_bytes, sha256, files_json) "
                         "VALUES (?, ?, ?, ?, ?)",
                         (task.pk, text, len(encoded), hashlib.sha256(encoded).hexdigest(),
                          json.dumps(files, ensure_ascii=True)))
    return end_reason


def finalize(store: Store, accounting: Accounting, conn: sqlite3.Connection, task: ClaimedTask,
             outcome: TaskOutcome | None, clock: Clock, diff_max_bytes: int,
             events_complete: bool) -> str:
    """T6. Final state comes from the TaskOutcome only, never from stored events. Retries Busy;
    the whole transaction (reconcile, report, update, diff) is repeated, so nothing double counts."""
    try:
        events, readable = _read_events(conn, task.pk)
    except sqlite3.Error:
        events, readable = [], False
    complete = events_complete and readable
    attempts = max(1, _store.WORKER_TX_ATTEMPTS)
    for attempt in range(attempts):
        try:
            return _finalize_tx(store, accounting, conn, task, outcome, clock, diff_max_bytes,
                                events, complete)
        except Busy:
            if attempt + 1 >= attempts:
                raise
    raise Busy()                      # unreachable


# ---------------------------------------------------------------------- executor

class TaskExecutor:
    def __init__(self, store: Store, accounting: Accounting, cfg: ServiceConfig, manifest: Manifest,
                 key_provider: Callable[[], str], clock: Clock,
                 run_task_fn: Callable[..., TaskOutcome],
                 sandbox_factory: Callable[..., object]) -> None:
        self._store = store
        self._acct = accounting
        self._cfg = cfg
        self._manifest = manifest
        self._key_provider = key_provider
        self._clock = clock
        self._run_task = run_task_fn
        self._sandbox_factory = sandbox_factory

    def execute(self, conn: sqlite3.Connection, task: ClaimedTask) -> None:
        """NEVER raises an Exception. Any failure while building or running -> outcome None ->
        the task is finalized as internal_error. Only the exception class name is logged."""
        cfg = self._cfg
        sink: EventSink | None = None
        outcome: TaskOutcome | None = None
        try:
            sample = self._manifest.get_sample(task.sample_id)
            if sample is None:
                raise LookupError("sample")
            inference = cfg.inference
            client = OpenAICompatClient(
                base_url=inference.base_url, model=inference.model,
                api_key_provider=self._key_provider, request_timeout_s=inference.request_timeout_s,
                max_retries=inference.max_retries)
            sink = EventSink(self._store, conn, task.pk, self._clock)
            budget = TaskBudget(self._store, self._acct, conn, task.pk, task.session_pk,
                                self._clock.monotonic() + cfg.hard_deadline_s, self._clock)
            result = self._run_task(task.instruction, sample.path, client=client, config=cfg.agent,
                                    sink=sink, budget=budget, sandbox_factory=self._sandbox_factory)
            if not isinstance(result, TaskOutcome):
                raise TypeError("run_task result")
            outcome = result
        except Exception as exc:
            outcome = None
            _log.error("task run failed task=%s error=%s", task.id, type(exc).__name__)
        complete = sink is not None and not sink.broken
        diff_max = cfg.agent.limits.diff_max_bytes
        try:
            reason = finalize(self._store, self._acct, conn, task, outcome, self._clock, diff_max,
                              complete)
            _log.info("task finished task=%s reason=%s", task.id, reason)
        except Exception as exc:
            _log.error("finalize failed task=%s error=%s", task.id, type(exc).__name__)
