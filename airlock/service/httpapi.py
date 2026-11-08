"""The JSON API: routes, CSRF, body parsing, auth, ownership and the loopback HTTP server."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
import socket
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .accounting import Accounting, Refusal
from .clock import Clock, iso_ms, seconds_to_next_utc_midnight, utc_day
from .config import ServiceConfig
from .manifest import Manifest, validate_instruction
from .ratelimit import RateLimiter, client_key
from .store import BUSY_MS_HTTP, Busy, Store

_log = logging.getLogger("airlock.service")

API_PREFIX: str = "/api/v1"
MAX_BODY_BYTES: int = 16_384
COOKIE_NAME: str = "airlock_session"
TOKEN_RE: str = r"[A-Za-z0-9_-]{43}"           # base64url(32 bytes), no padding
TASK_ID_RE: str = r"[0-9a-f]{32}"              # secrets.token_hex(16)
MAX_CONCURRENT_HANDLERS: int = 64
SOCKET_TIMEOUT_S: float = 10.0
EVENTS_PAGE_BYTES: int = 1_048_576
_DRAIN_MAX_BYTES = 1 << 20

ERRORS: dict[str, tuple[int, str]] = {
    "bad_request": (400, "Malformed request."),
    "invalid_json":(400, "Request body is not valid JSON."),
    "unauthenticated": (401, "A valid session is required."),
    "csrf_rejected": (403, "Request refused."),
    "not_found": (404, "Not found."),
    "no_diff": (404, "No diff is available for this task."),
    "method_not_allowed": (405, "Method not allowed."),
    "request_timeout": (408, "Request timed out."),
    "review_required": (409, "Approve the diff before downloading the patch."),
    "already_decided": (409, "A review decision was already recorded."),
    "not_reviewable": (409, "This task has nothing to review."),
    "length_required": (411, "Content-Length is required."),
    "payload_too_large": (413, "Request body is too large."),
    "unsupported_media_type": (415, "Content-Type must be application/json."),
    "validation_failed": (422, "Request fields are invalid."),
    "rate_limited": (429, "Too many requests from this client."),
    "session_task_quota": (429, "Daily task quota for this session is used up."),
    "session_token_quota": (429, "Daily token quota for this session is used up."),
    "too_many_active": (429, "This session already has the maximum number of active tasks."),
    "queue_full": (503, "The task queue is full. Try again shortly."),
    "service_paused": (503, "The service is not accepting tasks right now."),
    "service_busy": (503, "The service is busy. Try again shortly."),
    "internal_error": (500, "Internal error."),
}


class ApiError(Exception):
    def __init__(self, code: str, retry_after_s: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.retry_after_s = retry_after_s


class _DuplicateKey(Exception):
    pass


@dataclass(frozen=True)
class AppContext:
    cfg: ServiceConfig
    store: Store
    accounting: Accounting
    manifest: Manifest
    limiter: RateLimiter
    clock: Clock
    wake: Callable[[], None]


_ROUTES: tuple[tuple[str, str, str, str], ...] = (
    ("POST", r"/sessions", "/sessions", "_post_sessions"),
    ("GET", r"/session", "/session", "_get_session"),
    ("GET", r"/samples", "/samples", "_get_samples"),
    ("POST", r"/tasks", "/tasks", "_post_tasks"),
    ("GET", r"/tasks/([^/]+)", "/tasks/{id}", "_get_task"),
    ("GET", r"/tasks/([^/]+)/events", "/tasks/{id}/events", "_get_events"),
    ("GET", r"/tasks/([^/]+)/diff", "/tasks/{id}/diff", "_get_diff"),
    ("POST", r"/tasks/([^/]+)/review", "/tasks/{id}/review", "_post_review"),
    ("GET", r"/tasks/([^/]+)/patch", "/tasks/{id}/patch", "_get_patch"),
)
_UINT_RE = re.compile(r"[0-9]{1,10}")
_STATUS_TO_CODE = {400: "bad_request", 414: "bad_request", 431: "bad_request",
                   404: "not_found", 405: "method_not_allowed", 501: "method_not_allowed",
                   408: "request_timeout", 413: "payload_too_large"}
_PAUSE_LABEL = {"global_daily_tokens": "daily_limit", "global_usd_cap": "spend_limit",
                "admin": "maintenance"}
_TASK_COLS = ("pk, id, sample_id, preset_id, instruction, status, end_reason, review_state, "
              "created_at, started_at, finished_at, steps_used, tokens_in, tokens_out, "
              "last_seq, report_json")


def _no_dups(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise _DuplicateKey
        out[key] = value
    return out


def _reject_constant(_: str) -> object:
    raise ValueError("non-finite number")


def _iso_or_none(value: int | None) -> str | None:
    return None if value is None else iso_ms(int(value))


def _error_body(code: str) -> bytes:
    _, message = ERRORS[code]
    return json.dumps({"error": {"code": code, "message": message}},
                      separators=(",", ":")).encode("utf-8")


def make_handler(ctx: AppContext) -> type:
    cfg = ctx.cfg
    gate = threading.BoundedSemaphore(MAX_CONCURRENT_HANDLERS)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        timeout = SOCKET_TIMEOUT_S
        sys_version = ""

        def version_string(self) -> str:
            return "airlock"

        # The stdlib access log carries the client address and the raw path; the only log line
        # is written by _finish() with method, route template and status.
        def log_message(self, format: str, *args: object) -> None:
            return

        def log_error(self, format: str, *args: object) -> None:
            return

        def handle(self) -> None:
            self.request_version = "HTTP/1.0"
            self.requestline = ""
            self.command = "-"
            if not gate.acquire(blocking=False):
                self.close_connection = True
                self._write_error("service_busy", 5)
                return
            try:
                super().handle()
            finally:
                gate.release()

        def send_error(self, code: int, message: str | None = None,
                       explain: str | None = None) -> None:
            self.request_version = "HTTP/1.0"
            self.close_connection = True
            name = _STATUS_TO_CODE.get(code)
            if name is None:
                name = "internal_error" if code >= 500 else "bad_request"
            self._write_error(name, None)

        # ---- low-level writers -------------------------------------------------------
        def _write(self, status: int, body: bytes, ctype: str,
                   extra: list[tuple[str, str]] | None = None) -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                for key, value in extra or []:
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except OSError:
                self.close_connection = True

        def _write_error(self, code: str, retry_after_s: int | None) -> None:
            status = ERRORS[code][0]
            extra = [] if retry_after_s is None else [("Retry-After", str(int(retry_after_s)))]
            self._write(status, _error_body(code), "application/json; charset=utf-8", extra)
            self._status = status

        def _json(self, status: int, obj: object,
                  extra: list[tuple[str, str]] | None = None) -> None:
            body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            self._write(status, body, "application/json; charset=utf-8", extra)
            self._status = status

        # ---- request plumbing --------------------------------------------------------
        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def do_HEAD(self) -> None:
            self._dispatch("HEAD")

        def do_PUT(self) -> None:
            self._dispatch("PUT")

        def do_DELETE(self) -> None:
            self._dispatch("DELETE")

        def do_PATCH(self) -> None:
            self._dispatch("PATCH")

        def do_OPTIONS(self) -> None:
            self._dispatch("OPTIONS")

        def _dispatch(self, method: str) -> None:
            self._conn: sqlite3.Connection | None = None
            self._body_done = False
            self._status = 500
            template = "-"
            self._raw_query = ""
            try:
                try:
                    path, _, query = self.path.partition("?")
                    query = query.partition("#")[0]
                    path = path.partition("#")[0]
                    self._raw_query = query
                    if method == "POST":
                        self._check_csrf()
                    handler_name, params, template = self._route(method, path)
                    getattr(self, handler_name)(*params)
                except ApiError as exc:
                    if method == "POST" and not self._body_done:
                        self._drain()
                    self._write_error(exc.code, exc.retry_after_s)
                except Busy:
                    self._write_error("service_busy", 5)
                except Exception as exc:  # noqa: BLE001 - class name only, never the text
                    _log.error("request failed: %s", type(exc).__name__)
                    self._write_error("internal_error", None)
            finally:
                if self._conn is not None:
                    try:
                        self._conn.close()
                    except sqlite3.Error:
                        pass
                _log.info("http %s %s %d", method, template, self._status)

        def _route(self, method: str, path: str) -> tuple[str, tuple[str, ...], str]:
            if not path.startswith(API_PREFIX + "/"):
                raise ApiError("not_found")
            rest = path[len(API_PREFIX):]
            matched = False
            for verb, pattern, template, name in _ROUTES:
                m = re.fullmatch(pattern, rest)
                if m is None:
                    continue
                matched = True
                if verb == method:
                    return name, m.groups(), template
            raise ApiError("method_not_allowed" if matched else "not_found")

        def _check_csrf(self) -> None:
            if self.headers.get("X-Airlock") != "1":
                raise ApiError("csrf_rejected")
            origin = self.headers.get("Origin")
            if origin is not None and origin != cfg.public_origin:
                raise ApiError("csrf_rejected")

        def _drain(self) -> None:
            try:
                if self.headers.get("Transfer-Encoding") is not None:
                    return
                length = int(self.headers.get("Content-Length") or 0)
                remaining = length if 0 < length <= _DRAIN_MAX_BYTES else 0
                while remaining > 0:
                    chunk = self.rfile.read(min(remaining, 65536))
                    if not chunk:
                        break
                    remaining -= len(chunk)
            except (OSError, ValueError):
                pass
            self._body_done = True

        def _read_body(self, allow_empty: bool = True) -> dict:
            self._body_done = False
            if self.headers.get("Transfer-Encoding") is not None:
                raise ApiError("length_required")
            raw_len = self.headers.get("Content-Length")
            if raw_len is None:
                length = 0
            elif _UINT_RE.fullmatch(raw_len):
                length = int(raw_len)
            else:
                raise ApiError("bad_request")
            if length > MAX_BODY_BYTES:
                raise ApiError("payload_too_large")
            if length == 0:
                self._body_done = True
                if allow_empty:
                    return {}
                raise ApiError("validation_failed")
            ctype = re.sub(r"\s+", "", (self.headers.get("Content-Type") or "").lower())
            if ctype not in ("application/json", "application/json;charset=utf-8"):
                raise ApiError("unsupported_media_type")
            data = self.rfile.read(length)
            self._body_done = True
            if len(data) != length:
                raise ApiError("bad_request")
            try:
                text = data.decode("utf-8")
                value = json.loads(text, object_pairs_hook=_no_dups,
                                   parse_constant=_reject_constant)
            except _DuplicateKey:
                raise ApiError("validation_failed") from None
            except (UnicodeDecodeError, ValueError, RecursionError):
                raise ApiError("invalid_json") from None
            if not isinstance(value, dict):
                raise ApiError("validation_failed")
            return value

        def _expect_no_query(self) -> None:
            if self._raw_query:
                raise ApiError("validation_failed")

        def _db(self) -> sqlite3.Connection:
            if self._conn is None:
                conn = ctx.store.connect(busy_timeout_ms=BUSY_MS_HTTP)
                conn.row_factory = sqlite3.Row
                self._conn = conn
            return self._conn

        def _client(self) -> str:
            header = cfg.trusted_proxy_header
            value = self.headers.get(header) if header else None
            return client_key(self.client_address[0], value, header is not None)

        def _authenticate(self) -> tuple[int, int]:
            tokens: list[str] = []
            for line in self.headers.get_all("Cookie") or []:
                for part in line.split(";"):
                    name, _, value = part.strip().partition("=")
                    if name == COOKIE_NAME:
                        tokens.append(value)
            if len(tokens) != 1 or not re.fullmatch(TOKEN_RE, tokens[0]):
                raise ApiError("unauthenticated")
            digest = hashlib.sha256(tokens[0].encode("ascii")).digest()
            row = self._db().execute(
                "SELECT pk, expires_at FROM sessions WHERE token_hash = ? AND expires_at > ?",
                (digest, ctx.clock.now_ms())).fetchone()
            if row is None:
                raise ApiError("unauthenticated")
            return int(row["pk"]), int(row["expires_at"])

        def _load_owned_task(self, task_id: str, session_pk: int,
                             conn: sqlite3.Connection | None = None) -> sqlite3.Row:
            if not re.fullmatch(TASK_ID_RE, task_id):
                raise ApiError("not_found")
            row = (conn or self._db()).execute(
                f"SELECT {_TASK_COLS} FROM tasks WHERE id = ? AND session_pk = ?",
                (task_id, session_pk)).fetchone()
            if row is None:
                raise ApiError("not_found")
            return row

        def _hour_retry(self) -> int:
            return 3600 - (ctx.clock.now_ms() // 1000) % 3600

        # ---- routes ------------------------------------------------------------------
        def _post_sessions(self) -> None:
            body = self._read_body()
            if body:
                raise ApiError("validation_failed")
            self._expect_no_query()
            if not ctx.limiter.allow("sessions", self._client(),
                                     cfg.quotas.ip_sessions_per_hour):
                raise ApiError("rate_limited", self._hour_retry())
            token = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
            digest = hashlib.sha256(token.encode("ascii")).digest()
            now = ctx.clock.now_ms()
            expires = now + cfg.retention.session_ttl_s * 1000
            conn = self._db()
            with ctx.store.write_tx(conn):
                conn.execute("INSERT INTO sessions(token_hash, created_at, expires_at) "
                             "VALUES (?, ?, ?)", (digest, now, expires))
            cookie = (f"{COOKIE_NAME}={token}; Max-Age={cfg.retention.session_ttl_s}; Path=/api; "
                      "HttpOnly; SameSite=Strict" + ("; Secure" if cfg.cookie_secure else ""))
            self._json(201, {"session": {"expires_at": iso_ms(expires)}},
                       [("Set-Cookie", cookie)])

        def _get_session(self) -> None:
            session_pk, expires = self._authenticate()
            self._expect_no_query()
            conn = self._db()
            day = utc_day(ctx.clock.now_ms())
            usage = conn.execute("SELECT tasks, tokens FROM session_usage "
                                 "WHERE session_pk = ? AND day = ?", (session_pk, day)).fetchone()
            used_tasks = int(usage["tasks"]) if usage else 0
            used_tokens = int(usage["tokens"]) if usage else 0
            active = conn.execute("SELECT count(*) FROM tasks WHERE session_pk = ? AND "
                                  "status IN ('queued','running')", (session_pk,)).fetchone()[0]
            queued = conn.execute("SELECT count(*) FROM tasks WHERE status = 'queued'").fetchone()[0]
            running = conn.execute("SELECT count(*) FROM tasks WHERE status = 'running'").fetchone()[0]
            breaker = conn.execute("SELECT state, reason FROM breaker WHERE id = 1").fetchone()
            paused = breaker["state"] == "open"
            queue_full = queued >= cfg.quotas.max_queued
            q = cfg.quotas
            self._json(200, {
                "session": {"expires_at": iso_ms(expires)},
                "quota": {"day": day, "tasks_used": used_tasks, "tasks_limit": q.session_tasks_per_day,
                          "tasks_remaining": max(0, q.session_tasks_per_day - used_tasks),
                          "tokens_used": used_tokens, "tokens_limit": q.session_tokens_per_day,
                          "tokens_remaining": max(0, q.session_tokens_per_day - used_tokens),
                          "active_tasks": int(active), "active_limit": q.session_max_active},
                "service": {"accepting_tasks": not paused and not queue_full,
                            "pause_reason": _PAUSE_LABEL.get(breaker["reason"]) if paused else None,
                            "queue_full": queue_full, "queued": int(queued),
                            "queue_limit": q.max_queued, "running": int(running),
                            "running_limit": q.max_running}})

        def _get_samples(self) -> None:
            self._expect_no_query()
            self._json(200, ctx.manifest.public_view())

        def _post_tasks(self) -> None:
            body = self._read_body(allow_empty=False)
            session_pk, _ = self._authenticate()
            self._expect_no_query()
            keys = set(body)
            if keys not in ({"sample_id", "instruction"}, {"sample_id", "preset_id"}):
                raise ApiError("validation_failed")
            sample_id = body["sample_id"]
            sample = ctx.manifest.get_sample(sample_id) if isinstance(sample_id, str) else None
            if sample is None:
                raise ApiError("validation_failed")
            preset_id: str | None = None
            if "preset_id" in body:
                preset = next((p for p in sample.presets if p.id == body["preset_id"]), None) \
                    if isinstance(body["preset_id"], str) else None
                if preset is None:
                    raise ApiError("validation_failed")
                preset_id, instruction = preset.id, preset.instruction
            else:
                try:
                    instruction = validate_instruction(body["instruction"])
                except ValueError:
                    raise ApiError("validation_failed") from None
            if not ctx.limiter.allow("tasks", self._client(), cfg.quotas.ip_tasks_per_hour):
                raise ApiError("rate_limited", self._hour_retry())
            conn = self._db()
            task_id = secrets.token_hex(16)
            try:
                with ctx.store.write_tx(conn):
                    pk = ctx.accounting.admit_in_tx(
                        conn, session_pk=session_pk, task_id=task_id, sample_id=sample.id,
                        preset_id=preset_id, instruction=instruction)
            except Refusal as refusal:
                raise ApiError(refusal.code, self._refusal_retry(refusal.code, conn)) from None
            ctx.wake()
            position = conn.execute("SELECT count(*) FROM tasks WHERE status = 'queued' AND pk <= ?",
                                    (pk,)).fetchone()[0]
            self._json(202, {"task": {"id": task_id, "status": "queued",
                                      "queue_position": int(position)}},
                       [("Location", f"{API_PREFIX}/tasks/{task_id}")])

        def _refusal_retry(self, code: str, conn: sqlite3.Connection) -> int | None:
            if code in ("session_task_quota", "session_token_quota"):
                return seconds_to_next_utc_midnight(ctx.clock.now_ms())
            if code in ("too_many_active", "queue_full"):
                return 30
            if code == "service_paused":
                try:
                    row = conn.execute("SELECT reason FROM breaker WHERE id = 1").fetchone()
                except sqlite3.Error:
                    return None
                if row is not None and row["reason"] == "global_daily_tokens":
                    return seconds_to_next_utc_midnight(ctx.clock.now_ms())
            return None

        def _get_task(self, task_id: str) -> None:
            session_pk, _ = self._authenticate()
            self._expect_no_query()
            row = self._load_owned_task(task_id, session_pk)
            position = None
            if row["status"] == "queued":
                position = int(self._db().execute(
                    "SELECT count(*) FROM tasks WHERE status = 'queued' AND pk <= ?",
                    (row["pk"],)).fetchone()[0])
            report = json.loads(row["report_json"]) if row["report_json"] else None
            self._json(200, {"task": {
                "id": row["id"], "sample_id": row["sample_id"], "preset_id": row["preset_id"],
                "instruction": row["instruction"], "status": row["status"],
                "end_reason": row["end_reason"], "review_state": row["review_state"],
                "created_at": _iso_or_none(row["created_at"]),
                "started_at": _iso_or_none(row["started_at"]),
                "finished_at": _iso_or_none(row["finished_at"]),
                "queue_position": position,
                "counters": {"steps_used": row["steps_used"], "tokens_in": row["tokens_in"],
                             "tokens_out": row["tokens_out"], "last_seq": row["last_seq"]},
                "report": report}})

        def _get_events(self, task_id: str) -> None:
            session_pk, _ = self._authenticate()
            params: dict[str, int] = {}
            if self._raw_query:
                for part in self._raw_query.split("&"):
                    key, eq, value = part.partition("=")
                    if (not eq or key not in ("after_seq", "limit") or key in params
                            or not _UINT_RE.fullmatch(value)):
                        raise ApiError("validation_failed")
                    params[key] = int(value)
            after, limit = params.get("after_seq", 0), params.get("limit", 100)
            if after > 2**31 - 1 or not 1 <= limit <= 200:
                raise ApiError("validation_failed")
            row = self._load_owned_task(task_id, session_pk)
            rows = self._db().execute(
                "SELECT seq, type, created_at, payload FROM task_events "
                "WHERE task_pk = ? AND seq > ? ORDER BY seq LIMIT ?",
                (row["pk"], after, limit + 1)).fetchall()
            events: list[dict] = []
            size = 0
            has_more = len(rows) > limit
            for item in rows[:limit]:
                size += len(item["payload"].encode("utf-8"))
                if events and size > EVENTS_PAGE_BYTES:
                    has_more = True
                    break
                events.append({"seq": item["seq"], "type": item["type"],
                               "created_at": iso_ms(item["created_at"]),
                               "event": json.loads(item["payload"])})
            fresh = self._db().execute("SELECT status, last_seq FROM tasks WHERE pk = ?",
                                       (row["pk"],)).fetchone()
            self._json(200, {"events": events,
                             "next_after_seq": events[-1]["seq"] if events else after,
                             "last_seq": int(fresh["last_seq"]), "has_more": has_more,
                             "terminal": fresh["status"] not in ("queued", "running")})

        def _get_diff(self, task_id: str) -> None:
            session_pk, _ = self._authenticate()
            self._expect_no_query()
            row = self._load_owned_task(task_id, session_pk)
            diff = self._db().execute(
                "SELECT diff_text, size_bytes, sha256, files_json FROM task_diffs WHERE task_pk = ?",
                (row["pk"],)).fetchone()
            if diff is None:
                raise ApiError("no_diff")
            self._json(200, {"diff": {"text": diff["diff_text"], "size_bytes": diff["size_bytes"],
                                      "sha256": diff["sha256"],
                                      "files": json.loads(diff["files_json"]),
                                      "review_state": row["review_state"]}})

        def _post_review(self, task_id: str) -> None:
            body = self._read_body(allow_empty=False)
            session_pk, _ = self._authenticate()
            self._expect_no_query()
            if set(body) != {"decision"} or body["decision"] not in ("approve", "reject"):
                raise ApiError("validation_failed")
            decision = "approved" if body["decision"] == "approve" else "rejected"
            conn = self._db()
            with ctx.store.write_tx(conn):
                row = self._load_owned_task(task_id, session_pk, conn)
                cur = conn.execute(
                    "UPDATE tasks SET review_state = ?, decided_at = ? "
                    "WHERE pk = ? AND review_state = 'pending'",
                    (decision, ctx.clock.now_ms(), row["pk"]))
                if cur.rowcount != 1:
                    state = conn.execute("SELECT review_state FROM tasks WHERE pk = ?",
                                         (row["pk"],)).fetchone()["review_state"]
                    raise ApiError("already_decided" if state in ("approved", "rejected")
                                   else "not_reviewable")
                if decision == "rejected":
                    conn.execute("DELETE FROM task_diffs WHERE task_pk=?", (row["pk"],))
            if decision == "rejected":
                ctx.store.checkpoint(conn)
            self._json(200, {"review_state": decision})

        def _get_patch(self, task_id: str) -> None:
            session_pk, _ = self._authenticate()
            self._expect_no_query()
            row = self._load_owned_task(task_id, session_pk)
            if row["review_state"] == "pending":
                raise ApiError("review_required")
            diff = self._db().execute("SELECT diff_text FROM task_diffs WHERE task_pk = ?",
                                      (row["pk"],)).fetchone()
            if row["review_state"] != "approved" or diff is None:
                raise ApiError("no_diff")
            self._write(200, diff["diff_text"].encode("utf-8"), "text/x-diff; charset=utf-8",
                        [("Content-Disposition", f'attachment; filename="airlock-{row["id"]}.patch"')])
            self._status = 200

    return Handler


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def handle_error(self, request: object, client_address: object) -> None:
        _log.error("connection handler failed")


class ApiServer:
    def __init__(self, ctx: AppContext) -> None:
        self._ctx = ctx
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> tuple[str, int]:
        cfg = self._ctx.cfg

        class Bound(_Server):
            address_family = socket.AF_INET6 if cfg.listen_host == "::1" else socket.AF_INET

        self._server = Bound((cfg.listen_host, cfg.listen_port), make_handler(self._ctx))
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.2},
                                        name="airlock-http", daemon=True)
        self._thread.start()
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def shutdown(self) -> None:
        server, self._server = self._server, None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if self._thread is not None:
            self._thread.join(5.0)
