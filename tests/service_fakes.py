"""Shared helpers for the airlock.service tests."""
from __future__ import annotations

import copy
import http.client
import json
import logging
import os
import pathlib
import stat
import sys
import threading
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = pathlib.Path(__file__).resolve().parent
for _p in (str(ROOT), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from airlock.sandbox import DestroyProof, DiffResult  # noqa: E402
from airlock.agent import TaskOutcome  # noqa: E402

KEY = "CANARYKEY91"
API = "/api/v1"
ORIGIN = "https://airlock.example.invalid"
DEFAULT_SAMPLES = [
    ("s1", {"a.txt": "one\n"}, [("p1", "preset instruction one")]),
    ("s2", {"b.txt": "two\n"}, [("q1", "preset instruction two")]),
]


def _merge(base: dict, patch: dict) -> dict:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def make_env(tmp: pathlib.Path, *, patch: dict | None = None, real_docker: bool = False,
             samples: list | None = None, base_url: str = "http://127.0.0.1:9/v1"):
    """Write a manifest with sample dirs, a fake docker dir and a config file.

    Returns (config path, manifest path, fake docker dir)."""
    tmp = pathlib.Path(tmp)
    samples_dir = tmp / "samples"
    entries = []
    for sid, files, presets in samples or DEFAULT_SAMPLES:
        d = samples_dir / sid
        d.mkdir(parents=True, exist_ok=True)
        for name, text in files.items():
            (d / name).write_text(text, encoding="utf-8")
        entries.append({"id": sid, "title": f"Sample {sid}", "description": "A sample.", "path": sid,
                        "presets": [{"id": pid, "title": f"Preset {pid}", "description": "A preset.",
                                     "instruction": text} for pid, text in presets]})
    manifest = samples_dir / "manifest.json"
    manifest.write_text(json.dumps({"version": 1, "samples": entries}), encoding="utf-8")
    docker_dir = tmp / "fakebin"
    docker_dir.mkdir(exist_ok=True)
    script = docker_dir / "docker"
    script.write_text(f"#!{sys.executable}\n" + (TESTS / "fake_docker.py").read_text(encoding="utf-8"),
                      encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    set_docker_ps(docker_dir, [])
    cfg = {
        "listen": {"host": "127.0.0.1", "port": 0},
        "public_origin": ORIGIN, "cookie_secure": False, "trusted_proxy_header": None,
        "data_dir": str(tmp / "data"), "samples_manifest": "samples/manifest.json",
        "docker_cmd": ["docker"] if real_docker else [str(script)],
        "remove_leftover_containers": True,
        "inference": {"base_url": base_url, "model": "test-model", "action_mode": "text",
                      "api_key_env": "AIRLOCK_INFERENCE_KEY", "api_key_file": None,
                      "request_timeout_s": 20, "max_retries": 0,
                      "price_in_usd_per_mtok": 0.15, "price_out_usd_per_mtok": 0.60},
        "agent": {"max_steps": 25, "wall_clock_s": 240, "max_tokens": 1024,
                  "image": "airlock-sandbox:dev", "runtime": "runsc", "limits": {}},
        "quotas": {"session_tasks_per_day": 10, "session_tokens_per_day": 200000,
                   "session_max_active": 3, "global_tokens_per_day": 2000000, "usd_cap": 150,
                   "max_queued": 20, "max_running": 4, "ip_sessions_per_hour": 100000,
                   "ip_tasks_per_hour": 100000},
        "retention": {"task_retention_s": 82800, "session_ttl_s": 43200, "purge_interval_s": 300},
    }
    # The config file lives next to the samples dir so the relative manifest path resolves.
    cfg_path = tmp / "config.json"
    cfg_path.write_text(json.dumps(_merge(cfg, copy.deepcopy(patch or {}))), encoding="utf-8")
    return cfg_path, manifest, docker_dir


def set_docker_ps(docker_dir: pathlib.Path, ids: list[str]) -> None:
    rules = [{"sub": "info", "rc": 0, "stdout_text": '{"runsc":{}}'},
             {"sub": "image", "rc": 0, "stdout_text": "sha256:abc\n"},
             {"sub": "ps", "rc": 0, "stdout_text": "".join(i + "\n" for i in ids)}]
    (docker_dir / "script.json").write_text(json.dumps(rules), encoding="utf-8")


def docker_calls(docker_dir: pathlib.Path) -> list[list[str]]:
    path = docker_dir / "calls.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)["argv"] for line in path.read_text(encoding="utf-8").splitlines() if line]


class FakeClock:
    def __init__(self, now_ms: int | None = None) -> None:
        self._now = int(time.time() * 1000) if now_ms is None else now_ms
        self._mono = 1000.0

    def now_ms(self) -> int:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def set_ms(self, now_ms: int) -> None:
        self._now = now_ms

    def advance_ms(self, delta: int) -> None:
        self._now += delta

    def set_monotonic(self, value: float) -> None:
        self._mono = value


def at_utc(year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0) -> int:
    return int(datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc).timestamp() * 1000)


def make_outcome(reason: str = "agent_finished", *, diff_text: str | None = None, steps: int = 1,
                 tokens_in: int = 0, tokens_out: int = 0, proof: bool = True,
                 verified: bool = True) -> TaskOutcome:
    diff = None
    if diff_text is not None:
        diff = DiffResult("ok", diff_text, len(diff_text.encode("utf-8")), "0" * 64,
                          [{"path": "a.txt", "change": "modified", "lines_added": 1, "lines_removed": 0}])
    elif reason == "agent_finished":
        diff = DiffResult("no_changes", "", 0, None, [])
    return TaskOutcome(reason=reason, steps_used=steps, tokens_in=tokens_in, tokens_out=tokens_out,
                       diff=diff, destroy_proof=DestroyProof("abc123def456", verified, None) if proof else None,
                       peak={"memory_bytes": None, "pids": None, "cpu_ms": None},
                       summary="done" if reason == "agent_finished" else None)


def five_events() -> list[dict]:
    return [{"type": "tool_call", "step": i, "tool": "list_dir", "args": {"path": "."},
             "args_truncated": False} for i in range(1, 6)]


class FakeRunTask:
    """Scripted stand-in for airlock.agent.run_task (same keyword signature)."""

    def __init__(self, *, events=(), charges=(), outcome: TaskOutcome | None = None,
                 raises: Exception | None = None, block: threading.Event | None = None,
                 started: threading.Event | None = None) -> None:
        self.events, self.charges, self.outcome = list(events), list(charges), outcome
        self.raises, self.block, self.started = raises, block, started
        self.instructions: list[str] = []
        self.charge_results: list[str | None] = []

    def __call__(self, instruction, sample_repo, *, client, config, sink, budget, sandbox_factory):
        self.instructions.append(instruction)
        if self.started is not None:
            self.started.set()
        for event in self.events:
            sink(event)
        for tin, tout in self.charges:
            result = budget.charge(tin, tout)
            self.charge_results.append(result)
            if result:
                break
        if self.block is not None:
            self.block.wait(30)
        if self.raises is not None:
            raise self.raises
        return self.outcome or make_outcome()


class LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []
        self._fmt = logging.Formatter("%(name)s %(message)s")

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self._fmt.format(record))

    def __enter__(self) -> "LogCapture":
        logger = logging.getLogger("airlock")
        self._old = logger.level
        logger.setLevel(logging.DEBUG)
        logger.addHandler(self)
        return self

    def __exit__(self, *exc) -> None:
        logger = logging.getLogger("airlock")
        logger.removeHandler(self)
        logger.setLevel(self._old)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def api(port: int, method: str, path: str, *, body=None, cookie: str | None = None,
        headers: dict | None = None, raw: bytes | None = None, csrf: bool = True,
        content_type: str = "application/json"):
    """http.client request (never urllib: environment proxies). Returns (status, headers, bytes)."""
    h: dict[str, str] = {}
    if method == "POST" and csrf:
        h["X-Airlock"] = "1"
    if cookie:
        h["Cookie"] = f"airlock_session={cookie}"
    data = raw if raw is not None else (json.dumps(body).encode("utf-8") if body is not None else None)
    if data is not None:
        h["Content-Type"] = content_type
    h.update(headers or {})
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request(method, path, body=data, headers=h)
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
    finally:
        conn.close()


def jget(port: int, path: str, cookie: str | None = None):
    status, headers, payload = api(port, "GET", API + path, cookie=cookie)
    return status, json.loads(payload) if payload[:1] == b"{" else payload, headers


def jpost(port: int, path: str, body, cookie: str | None = None, **kw):
    status, headers, payload = api(port, "POST", API + path, body=body, cookie=cookie, **kw)
    return status, json.loads(payload) if payload[:1] == b"{" else payload, headers


def open_session(port: int) -> str:
    status, headers, _ = api(port, "POST", API + "/sessions")
    assert status == 201, status
    return headers["set-cookie"].split(";")[0].split("=", 1)[1]

def wait_for(predicate, timeout: float = 20.0, interval: float = 0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("condition not reached in time")


def wait_task_done(port: int, cookie: str, task_id: str, timeout: float = 60.0) -> dict:
    def done():
        _, body, _ = jget(port, f"/tasks/{task_id}", cookie)
        return body["task"] if body["task"]["status"] not in ("queued", "running") else None
    return wait_for(done, timeout)


def db_bytes(data_dir: pathlib.Path) -> bytes:
    out = b""
    for name in ("airlock.sqlite3", "airlock.sqlite3-wal"):
        p = data_dir / name
        if p.exists():
            out += p.read_bytes()
    return out


def env_with_key():
    from unittest import mock
    return mock.patch.dict(os.environ, {"AIRLOCK_INFERENCE_KEY": KEY})
