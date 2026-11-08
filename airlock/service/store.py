"""SQLite store: schema, connections and the explicit write-transaction primitive."""
from __future__ import annotations

import contextlib
import logging
import os
import pathlib
import sqlite3
from collections.abc import Iterator

_log = logging.getLogger("airlock.service")

SCHEMA_VERSION: int = 1
MIN_SQLITE: tuple[int, int, int] = (3, 24, 0)    # UPSERT; checked at start, fail closed
BUSY_MS_HTTP: int = 5_000
BUSY_MS_WORKER: int = 30_000
BUSY_MS_ADMIN: int = 10_000
WORKER_TX_ATTEMPTS: int = 3

# No semicolon may appear inside a comment or literal: the script is split on semicolons.
SCHEMA_SQL = """
CREATE TABLE sessions (
  pk          INTEGER PRIMARY KEY,
  token_hash  BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX sessions_expires ON sessions(expires_at);

CREATE TABLE tasks (
  pk            INTEGER PRIMARY KEY AUTOINCREMENT,
  id            TEXT    NOT NULL UNIQUE CHECK (length(id) = 32),
  session_pk    INTEGER NOT NULL REFERENCES sessions(pk) ON DELETE CASCADE,
  sample_id     TEXT    NOT NULL,
  preset_id     TEXT,
  instruction   TEXT    NOT NULL CHECK (length(instruction) BETWEEN 1 AND 2000),
  status        TEXT    NOT NULL CHECK (status IN ('queued','running','finished','cancelled','interrupted')),
  end_reason    TEXT,
  review_state  TEXT    NOT NULL DEFAULT 'none' CHECK (review_state IN ('none','pending','approved','rejected')),
  created_at    INTEGER NOT NULL,
  started_at    INTEGER,
  finished_at   INTEGER,
  decided_at    INTEGER,
  tokens_in     INTEGER NOT NULL DEFAULT 0 CHECK (tokens_in  >= 0),
  tokens_out    INTEGER NOT NULL DEFAULT 0 CHECK (tokens_out >= 0),
  cost_micros   INTEGER NOT NULL DEFAULT 0 CHECK (cost_micros >= 0),
  steps_used    INTEGER CHECK (steps_used IS NULL OR steps_used >= 0),
  last_seq      INTEGER NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  report_json   TEXT,
  CHECK ((status IN ('queued','running')) = (end_reason IS NULL)),
  CHECK ((status IN ('queued','running')) = (finished_at IS NULL)),
  CHECK (review_state = 'none' OR status = 'finished'),
  CHECK ((review_state IN ('approved','rejected')) = (decided_at IS NOT NULL))
);
CREATE INDEX tasks_status_pk  ON tasks(status, pk);
CREATE INDEX tasks_session    ON tasks(session_pk, status);
CREATE INDEX tasks_created    ON tasks(created_at);

CREATE TABLE task_events (
  task_pk     INTEGER NOT NULL REFERENCES tasks(pk) ON DELETE CASCADE,
  seq         INTEGER NOT NULL CHECK (seq >= 1),
  type        TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  payload     TEXT    NOT NULL CHECK (length(payload) <= 32768),
  PRIMARY KEY (task_pk, seq)
) WITHOUT ROWID;

CREATE TABLE task_diffs (
  task_pk     INTEGER PRIMARY KEY REFERENCES tasks(pk) ON DELETE CASCADE,
  diff_text   TEXT    NOT NULL,
  size_bytes  INTEGER NOT NULL CHECK (size_bytes >= 0),
  sha256      TEXT,
  files_json  TEXT    NOT NULL
);

CREATE TABLE session_usage (
  session_pk  INTEGER NOT NULL REFERENCES sessions(pk) ON DELETE CASCADE,
  day         TEXT    NOT NULL,
  tasks       INTEGER NOT NULL DEFAULT 0 CHECK (tasks  >= 0),
  tokens      INTEGER NOT NULL DEFAULT 0 CHECK (tokens >= 0),
  PRIMARY KEY (session_pk, day)
) WITHOUT ROWID;

CREATE TABLE global_usage (
  day             TEXT PRIMARY KEY,
  tokens_in       INTEGER NOT NULL DEFAULT 0 CHECK (tokens_in  >= 0),
  tokens_out      INTEGER NOT NULL DEFAULT 0 CHECK (tokens_out >= 0),
  cost_micros     INTEGER NOT NULL DEFAULT 0 CHECK (cost_micros >= 0),
  tasks_admitted  INTEGER NOT NULL DEFAULT 0 CHECK (tasks_admitted >= 0)
) WITHOUT ROWID;

CREATE TABLE breaker (
  id                INTEGER PRIMARY KEY CHECK (id = 1),
  state             TEXT    NOT NULL CHECK (state IN ('closed','open')),
  reason            TEXT    CHECK (reason IN ('global_daily_tokens','global_usd_cap','admin')),
  opened_at         INTEGER,
  opened_day        TEXT,
  usd_spent_micros  INTEGER NOT NULL DEFAULT 0 CHECK (usd_spent_micros >= 0),
  tokens_lifetime   INTEGER NOT NULL DEFAULT 0 CHECK (tokens_lifetime >= 0),
  CHECK ((state = 'open') = (reason IS NOT NULL AND opened_at IS NOT NULL AND opened_day IS NOT NULL))
);
INSERT INTO breaker (id, state) VALUES (1, 'closed');

CREATE TABLE breaker_log (
  pk      INTEGER PRIMARY KEY,
  at      INTEGER NOT NULL,
  action  TEXT    NOT NULL CHECK (action IN ('open','upgrade','close')),
  reason  TEXT,
  actor   TEXT    NOT NULL CHECK (actor IN ('charge','scheduler','admin'))
);

CREATE TABLE admin_audit (
  pk      INTEGER PRIMARY KEY,
  at      INTEGER NOT NULL,
  action  TEXT    NOT NULL CHECK (action IN ('breaker_open','breaker_close','purge')),
  result  TEXT    NOT NULL CHECK (result IN ('ok','noop','refused')),
  detail  TEXT
);
"""

_STATEMENTS: tuple[str, ...] = tuple(s.strip() for s in SCHEMA_SQL.split(";") if s.strip())


class StoreError(Exception):
    """Startup / integrity failure. str() is a fixed check name."""


class Busy(Exception):
    """BEGIN IMMEDIATE could not get the write lock within busy_timeout."""


def _is_busy(exc: sqlite3.Error) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    if code is not None:
        return (code & 0xFF) in (5, 6)          # SQLITE_BUSY, SQLITE_LOCKED
    return "database is locked" in str(exc)


class Store:
    def __init__(self, db_path: pathlib.Path) -> None:
        self.db_path = pathlib.Path(db_path)

    # ------------------------------------------------------------------ startup

    def _enable_wal(self, conn: sqlite3.Connection) -> str:
        row = conn.execute("PRAGMA journal_mode=WAL").fetchone()
        return str(row[0]).lower() if row else ""

    def initialize(self) -> None:
        """Create data_dir 0700 and the DB file 0600; verify version, WAL, schema and integrity.
        Raises StoreError(<check name>)."""
        if sqlite3.sqlite_version_info < MIN_SQLITE:
            raise StoreError("sqlite_version")
        data_dir = self.db_path.parent
        try:
            created = not data_dir.exists()
            data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            if created:
                os.chmod(data_dir, 0o700)
            if not self.db_path.exists():
                fd = os.open(str(self.db_path), os.O_RDWR | os.O_CREAT, 0o600)
                os.close(fd)
        except OSError:
            raise StoreError("db_open") from None
        try:
            conn = self.connect(busy_timeout_ms=BUSY_MS_ADMIN)
        except (sqlite3.Error, StoreError):
            raise StoreError("db_open") from None
        try:
            try:
                mode = self._enable_wal(conn)
            except sqlite3.Error:
                raise StoreError("wal") from None
            if mode != "wal":
                raise StoreError("wal")
            try:
                self._ensure_schema(conn)
                rows = conn.execute("PRAGMA quick_check").fetchall()
                if len(rows) != 1 or rows[0][0] != "ok":
                    raise StoreError("integrity")
                if conn.execute("SELECT count(*) FROM breaker WHERE id = 1").fetchone()[0] != 1:
                    raise StoreError("integrity")
            except Busy:
                raise StoreError("db_open") from None
            except sqlite3.Error:
                raise StoreError("integrity") from None
        finally:
            conn.close()

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            return
        if version != 0:
            raise StoreError("schema_version")
        with self.write_tx(conn):
            # Re-read under the write lock: another process may have created the schema.
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == SCHEMA_VERSION:
                return
            if version != 0:
                raise StoreError("schema_version")
            tables = conn.execute("SELECT count(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0]
            if tables:
                raise StoreError("schema_version")
            for statement in _STATEMENTS:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        _log.info("schema created version=%d", SCHEMA_VERSION)

    # ------------------------------------------------------------------ connections

    def connect(self, *, busy_timeout_ms: int) -> sqlite3.Connection:
        """Autocommit connection (isolation_level=None) bound to the calling thread."""
        conn = sqlite3.connect(str(self.db_path), isolation_level=None, check_same_thread=True,
                               timeout=busy_timeout_ms / 1000.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            conn.close()
            raise StoreError("db_open")
        return conn

    @contextlib.contextmanager
    def write_tx(self, conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE ... COMMIT; ROLLBACK on any exception. A busy or locked database
        becomes Busy (no driver text kept)."""
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            if _is_busy(exc):
                raise Busy() from None
            raise
        try:
            yield conn
        except BaseException as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                _log.error("rollback failed")
            if isinstance(exc, sqlite3.OperationalError) and _is_busy(exc):
                raise Busy() from None
            raise
        else:
            try:
                conn.execute("COMMIT")
            except sqlite3.OperationalError as exc:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    _log.error("rollback failed")
                if _is_busy(exc):
                    raise Busy() from None
                raise

    def checkpoint(self, conn: sqlite3.Connection) -> None:
        """PRAGMA wal_checkpoint(TRUNCATE); best effort, never raises."""
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        except sqlite3.Error:
            _log.warning("checkpoint failed")
