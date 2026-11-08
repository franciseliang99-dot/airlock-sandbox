"""Local admin CLI: python3 -m airlock.service.admin --config <path> <command>."""
from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
import sys

from airlock.service.accounting import Accounting
from airlock.service.clock import SystemClock, iso_ms, utc_day
from airlock.service.config import ConfigError, load_config
from airlock.service.scheduler import list_stuck, purge_now
from airlock.service.store import BUSY_MS_ADMIN, SCHEMA_VERSION, Busy, Store


def _out(obj: object) -> None:
    print(json.dumps(obj, sort_keys=True))


def _audit(conn: sqlite3.Connection, clock: SystemClock, action: str, result: str,
           detail: dict) -> None:
    conn.execute("INSERT INTO admin_audit(at, action, result, detail) VALUES (?,?,?,?)",
                 (clock.now_ms(), action, result, json.dumps(detail, sort_keys=True)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m airlock.service.admin")
    parser.add_argument("--config", required=True, type=pathlib.Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    usage = sub.add_parser("usage")
    usage.add_argument("--day")
    breaker = sub.add_parser("breaker")
    breaker.add_argument("action", choices=("open", "close"))
    sub.add_parser("purge")
    sub.add_parser("stuck")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        _out({"error": "config", "detail": str(exc)})
        return 2
    if not cfg.db_path.exists():
        _out({"error": "no_database"})
        return 2
    clock = SystemClock()
    store = Store(cfg.db_path)
    acct = Accounting(cfg, clock)
    conn = None
    try:
        conn = store.connect(busy_timeout_ms=BUSY_MS_ADMIN)
        if conn.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            _out({"error": "schema_version"})
            return 2
        if args.command == "status":
            b = conn.execute("SELECT state, reason, opened_at, usd_spent_micros FROM breaker "
                             "WHERE id = 1").fetchone()
            counts = dict(conn.execute("SELECT status, count(*) FROM tasks GROUP BY status").fetchall())
            _out({"breaker": {"state": b[0], "reason": b[1],
                              "opened_at": None if b[2] is None else iso_ms(b[2]),
                              "usd_spent_micros": b[3]},
                  "tasks": counts, "stuck": len(list_stuck(conn, cfg, clock))})
            return 0
        if args.command == "usage":
            day = args.day or utc_day(clock.now_ms())
            row = conn.execute("SELECT tokens_in, tokens_out, cost_micros, tasks_admitted "
                               "FROM global_usage WHERE day = ?", (day,)).fetchone()
            vals = tuple(row) if row else (0, 0, 0, 0)
            _out({"day": day, "tokens_in": vals[0], "tokens_out": vals[1],
                  "cost_micros": vals[2], "tasks_admitted": vals[3]})
            return 0
        if args.command == "stuck":
            _out({"stuck": list_stuck(conn, cfg, clock)})
            return 0
        if args.command == "purge":
            counts = purge_now(store, conn, cfg, clock)
            detail = {"tasks": counts.tasks, "sessions": counts.sessions, "diffs": counts.diffs}
            with store.write_tx(conn):
                _audit(conn, clock, "purge", "ok", detail)
            _out({"purged": detail})
            return 0
        if args.action == "open":
            with store.write_tx(conn):
                opened = acct.open_breaker_in_tx(conn, "admin", "admin")
                result = "ok" if opened else "noop"
                _audit(conn, clock, "breaker_open", result, {})
            _out({"breaker_open": result})
            return 0
        with store.write_tx(conn):
            outcome = acct.close_breaker_in_tx(conn, "admin")
            result = {"closed": "ok", "noop": "noop", "refused": "refused"}[outcome]
            _audit(conn, clock, "breaker_close", result, {})
        _out({"breaker_close": result})
        return 3 if result == "refused" else 0
    except Busy:
        _out({"error": "db_busy"})
        return 5
    except sqlite3.Error as exc:
        _out({"error": "internal", "detail": type(exc).__name__})
        return 1
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
