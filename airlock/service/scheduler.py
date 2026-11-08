"""Queue claim, purge, restart recovery, the worker pool and the scheduler tick."""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass

from .accounting import Accounting
from .clock import Clock, iso_ms
from .config import ServiceConfig
from .execution import ClaimedTask, TaskExecutor
from .store import BUSY_MS_WORKER, Store

_log = logging.getLogger("airlock.service")


@dataclass(frozen=True)
class PurgeCounts:
    tasks: int
    sessions: int
    diffs: int


def claim_next(store: Store, conn: sqlite3.Connection, max_running: int,
               clock: Clock) -> ClaimedTask | None:
    """T3: FIFO claim. Refuses while the breaker is open or max_running tasks are running."""
    if conn.execute("SELECT 1 FROM tasks WHERE status = 'queued' LIMIT 1").fetchone() is None:
        return None                       # cheap read: idle workers do not take the write lock
    with store.write_tx(conn):
        brk = conn.execute("SELECT state FROM breaker WHERE id = 1").fetchone()
        if brk is None or brk[0] != "closed":
            return None
        running = conn.execute("SELECT count(*) FROM tasks WHERE status = 'running'").fetchone()[0]
        if running >= max_running:
            return None
        row = conn.execute("SELECT pk, id, session_pk, sample_id, instruction FROM tasks "
                           "WHERE status = 'queued' ORDER BY pk LIMIT 1").fetchone()
        if row is None:
            return None
        cur = conn.execute("UPDATE tasks SET status = 'running', started_at = ? "
                           "WHERE pk = ? AND status = 'queued'", (clock.now_ms(), row[0]))
        if cur.rowcount != 1:
            return None
        return ClaimedTask(pk=int(row[0]), id=row[1], session_pk=int(row[2]), sample_id=row[3],
                           instruction=row[4])


def purge_now(store: Store, conn: sqlite3.Connection, cfg: ServiceConfig,
              clock: Clock) -> PurgeCounts:
    """T7: rejected diffs, tasks past retention (cascade: events, diffs), expired sessions that
    have no active task (cascade: their remaining tasks and usage)."""
    now = clock.now_ms()
    cutoff = now - cfg.retention.task_retention_s * 1000
    with store.write_tx(conn):
        diffs = conn.execute("DELETE FROM task_diffs WHERE task_pk IN "
                             "(SELECT pk FROM tasks WHERE review_state = 'rejected')").rowcount
        tasks = conn.execute("DELETE FROM tasks WHERE created_at <= ?", (cutoff,)).rowcount
        sessions = conn.execute(
            "DELETE FROM sessions WHERE expires_at <= ? AND NOT EXISTS "
            "(SELECT 1 FROM tasks t WHERE t.session_pk = sessions.pk "
            "AND t.status IN ('queued', 'running'))", (now,)).rowcount
    counts = PurgeCounts(tasks=tasks, sessions=sessions, diffs=diffs)
    if tasks or sessions or diffs:
        store.checkpoint(conn)
    return counts


def recover_interrupted(store: Store, conn: sqlite3.Connection, clock: Clock) -> int:
    """T8: tasks left queued or running by a previous process become interrupted."""
    with store.write_tx(conn):
        return conn.execute("UPDATE tasks SET status = 'interrupted', end_reason = 'service_restart', "
                            "finished_at = ? WHERE status IN ('queued', 'running')",
                            (clock.now_ms(),)).rowcount


def list_stuck(conn: sqlite3.Connection, cfg: ServiceConfig, clock: Clock) -> list[dict]:
    now = clock.now_ms()
    limit = now - int(cfg.stuck_after_s * 1000)
    rows = conn.execute("SELECT id, started_at FROM tasks WHERE status = 'running' "
                        "AND started_at < ? ORDER BY pk", (limit,)).fetchall()
    return [{"id": r[0], "started_at": iso_ms(int(r[1])), "age_s": (now - int(r[1])) // 1000}
            for r in rows]


class WorkerPool:
    def __init__(self, store: Store, executor: TaskExecutor, size: int, clock: Clock,
                 stop: threading.Event) -> None:
        self._store = store
        self._executor = executor
        self._size = size
        self._clock = clock
        self._stop_event = stop
        self._cond = threading.Condition()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for index in range(self._size):
            thread = threading.Thread(target=self._loop, name=f"airlock-worker-{index}", daemon=True)
            thread.start()
            self._threads.append(thread)

    def wake(self) -> None:
        with self._cond:
            self._cond.notify_all()

    def join(self, timeout_s: float) -> None:
        end = time.monotonic() + timeout_s
        for thread in self._threads:
            thread.join(max(0.0, end - time.monotonic()))

    def _loop(self) -> None:
        conn: sqlite3.Connection | None = None
        try:
            conn = self._store.connect(busy_timeout_ms=BUSY_MS_WORKER)
            while not self._stop_event.is_set():
                try:
                    task = claim_next(self._store, conn, self._size, self._clock)
                except Exception as exc:
                    _log.error("claim failed error=%s", type(exc).__name__)
                    task = None
                if task is None:
                    with self._cond:
                        self._cond.wait(1.0)
                    continue
                self._executor.execute(conn, task)
        except Exception as exc:
            _log.error("worker stopped error=%s", type(exc).__name__)
        finally:
            if conn is not None:
                conn.close()


class Scheduler(threading.Thread):
    TICK_S: float = 5.0

    def __init__(self, store: Store, accounting: Accounting, cfg: ServiceConfig, clock: Clock,
                 pool: WorkerPool, stop: threading.Event) -> None:
        super().__init__(name="airlock-scheduler", daemon=True)
        self._store = store
        self._accounting = accounting
        self._cfg = cfg
        self._clock = clock
        self._pool = pool
        self._stop_event = stop
        self._last_purge = clock.monotonic()

    def run(self) -> None:
        while not self._stop_event.wait(self.TICK_S):
            try:
                self.tick()
            except Exception as exc:
                _log.error("scheduler tick failed error=%s", type(exc).__name__)

    def tick(self) -> None:
        """Day rollover of the daily-token breaker, periodic purge, stuck count, worker wake-up.
        Uses a short-lived connection so it can be called from any thread."""
        try:
            conn = self._store.connect(busy_timeout_ms=BUSY_MS_WORKER)
        except Exception as exc:
            _log.error("scheduler connect failed error=%s", type(exc).__name__)
            self._pool.wake()
            return
        try:
            try:
                with self._store.write_tx(conn):
                    self._accounting.rollover_in_tx(conn)
            except Exception as exc:
                _log.error("rollover failed error=%s", type(exc).__name__)
            now = self._clock.monotonic()
            if now - self._last_purge >= self._cfg.retention.purge_interval_s:
                self._last_purge = now
                try:
                    counts = purge_now(self._store, conn, self._cfg, self._clock)
                    _log.info("purge tasks=%d sessions=%d diffs=%d", counts.tasks, counts.sessions,
                              counts.diffs)
                except Exception as exc:
                    _log.error("purge failed error=%s", type(exc).__name__)
            try:
                stuck = list_stuck(conn, self._cfg, self._clock)
                if stuck:
                    _log.warning("stuck tasks count=%d", len(stuck))
            except Exception as exc:
                _log.error("stuck scan failed error=%s", type(exc).__name__)
        finally:
            conn.close()
        self._pool.wake()
