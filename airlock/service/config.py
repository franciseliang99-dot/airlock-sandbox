"""Service configuration: strict JSON loading, validation and derived watchdog values."""
from __future__ import annotations

import dataclasses
import json
import math
import os
import pathlib
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal
from typing import Literal

from airlock.agent import AgentConfig
from airlock.agent.client import _MODEL_RE, _validate_base_url
from airlock.sandbox import Limits, SandboxError
from airlock.sandbox.runner import _validate_create_inputs

CMD_OVERHEAD_S: float = 36.6          # = 10 + 15 + 1.6 + 10 (one sandbox command bound beyond its timeout)
TEARDOWN_ALLOWANCE_S: float = 120.0   # collect_diff + destroy, approximate
STUCK_GRACE_S: float = 300.0
MAX_TASK_RETENTION_S: int = 82_800    # 23 h, hard upper bound
SAFE_UNPREFIXED_ENV_RE = r"[A-Z][A-Z0-9_]{0,63}"

_ORIGIN_RE = re.compile(
    r"https?://(?:[a-z0-9](?:[a-z0-9.-]{0,252}[a-z0-9])?|\[[0-9a-f:]{2,45}\])(?::[0-9]{1,5})?")
_HEADER_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_KEY_RE = re.compile(r"[\x21-\x7e]{1,512}")
_ENV_RE = re.compile(SAFE_UNPREFIXED_ENV_RE)


class ConfigError(Exception):
    """str() names the offending key path only (e.g. "invalid quotas.max_running"); never a value."""


@dataclass(frozen=True)
class InferenceConfig:
    base_url: str
    model: str
    api_key_env: str | None            # exactly one of api_key_env / api_key_file is not None
    api_key_file: pathlib.Path | None
    request_timeout_s: float
    max_retries: int
    price_in_micros_per_mtok: int      # ceil(USD per 1M input tokens * 1_000_000), >= 1
    price_out_micros_per_mtok: int


@dataclass(frozen=True)
class QuotaConfig:
    session_tasks_per_day: int
    session_tokens_per_day: int
    session_max_active: int
    global_tokens_per_day: int
    usd_cap_micros: int
    max_queued: int
    max_running: int
    ip_sessions_per_hour: int
    ip_tasks_per_hour: int


@dataclass(frozen=True)
class RetentionConfig:
    task_retention_s: int              # 600..82800
    session_ttl_s: int                 # 600..43200
    purge_interval_s: int              # 10..600


@dataclass(frozen=True)
class ServiceConfig:
    listen_host: Literal["127.0.0.1", "::1"]
    listen_port: int                   # 0..65535 (0 = ephemeral, tests)
    public_origin: str                 # scheme://host[:port], no path/query/fragment
    cookie_secure: bool
    trusted_proxy_header: str | None
    data_dir: pathlib.Path
    manifest_path: pathlib.Path        # resolved against the config file's directory
    docker_cmd: tuple[str, ...]
    remove_leftover_containers: bool
    inference: InferenceConfig
    agent: AgentConfig                 # built and validated by M2's AgentConfig.__post_init__
    quotas: QuotaConfig
    retention: RetentionConfig

    @property
    def db_path(self) -> pathlib.Path:
        return self.data_dir / "airlock.sqlite3"

    @property
    def hard_deadline_s(self) -> float:
        """Worst-case task duration: wall clock + one abandoned LLM call + one command bound
        + collect/destroy. Approximate by construction."""
        return (self.agent.wall_clock_s + self.inference.request_timeout_s
                + self.agent.limits.command_timeout_s + CMD_OVERHEAD_S + TEARDOWN_ALLOWANCE_S)

    @property
    def stuck_after_s(self) -> float:
        return self.hard_deadline_s + STUCK_GRACE_S


# ---------------------------------------------------------------------- strict JSON helpers

class _DuplicateKey(Exception):
    pass


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise _DuplicateKey()
        out[key] = value
    return out


def _reject_constant(name: str) -> object:
    raise ValueError("non-finite number")


def _section(value: object, path: str, required: set[str], optional: set[str]) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"invalid {path}")
    keys = set(value)
    if not keys <= required | optional:
        raise ConfigError(f"unknown key in {path}")
    missing = required - keys
    if missing:
        raise ConfigError(f"missing key in {path}")
    return value


def _int(value: object, path: str, low: int, high: int) -> int:
    if type(value) is not int or not (low <= value <= high):
        raise ConfigError(f"invalid {path}")
    return value


def _number(value: object, path: str, low: float, high: float, *, low_open: bool = False) -> float:
    if type(value) not in (int, float):
        raise ConfigError(f"invalid {path}")
    if isinstance(value, float) and not math.isfinite(value):
        raise ConfigError(f"invalid {path}")
    if value > high or (value <= low if low_open else value < low):
        raise ConfigError(f"invalid {path}")
    return value  # type: ignore[return-value]


def _bool(value: object, path: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"invalid {path}")
    return value


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ConfigError(f"invalid {path}")
    return value


def _ceil_micros(value: float) -> int:
    return int((Decimal(str(value)) * 1_000_000).to_integral_value(rounding=ROUND_CEILING))


def _price_micros(value: object, path: str) -> int:
    number = _number(value, path, 0, 1000, low_open=True)
    return max(1, _ceil_micros(number))


def _agent_error(exc: ValueError) -> ConfigError:
    text = str(exc)
    name = text[len("invalid "):] if text.startswith("invalid ") else ""
    if re.fullmatch(r"[a-z_]{1,40}", name):
        return ConfigError(f"invalid agent.{name}")
    return ConfigError("invalid agent")


_QUOTA_DEFAULTS: dict[str, int | float] = {
    "session_tasks_per_day": 10, "session_tokens_per_day": 200_000, "session_max_active": 3,
    "global_tokens_per_day": 2_000_000, "usd_cap": 150, "max_queued": 20, "max_running": 4,
    "ip_sessions_per_hour": 10, "ip_tasks_per_hour": 30}
_QUOTA_RANGES: dict[str, tuple[int, int]] = {
    "session_tasks_per_day": (1, 1000), "session_tokens_per_day": (1, 10**9),
    "session_max_active": (1, 200), "global_tokens_per_day": (1, 10**10),
    "max_queued": (1, 200), "max_running": (1, 16),
    "ip_sessions_per_hour": (1, 100_000), "ip_tasks_per_hour": (1, 100_000)}


def _load_quotas(raw: object) -> QuotaConfig:
    section = _section(raw, "quotas", set(), set(_QUOTA_DEFAULTS))
    values: dict[str, int] = {}
    for name, (low, high) in _QUOTA_RANGES.items():
        values[name] = _int(section.get(name, _QUOTA_DEFAULTS[name]), f"quotas.{name}", low, high)
    usd = _number(section.get("usd_cap", _QUOTA_DEFAULTS["usd_cap"]), "quotas.usd_cap", 0, 100_000,
                  low_open=True)
    usd_micros = max(1, _ceil_micros(usd))
    return QuotaConfig(usd_cap_micros=usd_micros, **values)


def _load_retention(raw: object) -> RetentionConfig:
    section = _section(raw, "retention", set(), {"task_retention_s", "session_ttl_s",
                                                  "purge_interval_s"})
    return RetentionConfig(
        task_retention_s=_int(section.get("task_retention_s", MAX_TASK_RETENTION_S),
                              "retention.task_retention_s", 600, MAX_TASK_RETENTION_S),
        session_ttl_s=_int(section.get("session_ttl_s", 43_200), "retention.session_ttl_s",
                           600, 43_200),
        purge_interval_s=_int(section.get("purge_interval_s", 300), "retention.purge_interval_s",
                              10, 600))


def _load_inference(raw: object, base_dir: pathlib.Path) -> tuple[InferenceConfig, str]:
    section = _section(
        raw, "inference",
        {"base_url", "model", "price_in_usd_per_mtok", "price_out_usd_per_mtok"},
        {"action_mode", "api_key_env", "api_key_file", "request_timeout_s", "max_retries"})
    try:
        base_url = _validate_base_url(section["base_url"])
    except ValueError:
        raise ConfigError("invalid inference.base_url") from None
    model = section["model"]
    if not isinstance(model, str) or not _MODEL_RE.fullmatch(model):
        raise ConfigError("invalid inference.model")
    action_mode = section.get("action_mode", "text")
    if action_mode not in ("native", "text") or not isinstance(action_mode, str):
        raise ConfigError("invalid inference.action_mode")

    file_raw = section.get("api_key_file")
    if "api_key_env" in section:
        env_raw = section["api_key_env"]
    elif file_raw is not None:
        env_raw = None                  # choosing a file switches the default env source off
    else:
        env_raw = "AIRLOCK_INFERENCE_KEY"
    if (env_raw is None) == (file_raw is None):
        raise ConfigError("invalid inference.api_key_env/api_key_file")
    key_env: str | None = None
    key_file: pathlib.Path | None = None
    if env_raw is not None:
        if not isinstance(env_raw, str) or not _ENV_RE.fullmatch(env_raw):
            raise ConfigError("invalid inference.api_key_env")
        key_env = env_raw
    else:
        key_file = base_dir / _text(file_raw, "inference.api_key_file")

    timeout = _number(section.get("request_timeout_s", 120), "inference.request_timeout_s", 0.1, 600)
    retries = _int(section.get("max_retries", 2), "inference.max_retries", 0, 5)
    return InferenceConfig(
        base_url=base_url, model=model, api_key_env=key_env, api_key_file=key_file,
        request_timeout_s=float(timeout), max_retries=retries,
        price_in_micros_per_mtok=_price_micros(section["price_in_usd_per_mtok"],
                                               "inference.price_in_usd_per_mtok"),
        price_out_micros_per_mtok=_price_micros(section["price_out_usd_per_mtok"],
                                                "inference.price_out_usd_per_mtok")), action_mode


def _load_agent(raw: object, action_mode: str, docker_cmd: tuple[str, ...]) -> AgentConfig:
    section = _section(raw, "agent", set(), {"max_steps", "wall_clock_s", "max_tokens", "image",
                                              "runtime", "limits"})
    limit_names = {f.name for f in dataclasses.fields(Limits)}
    limits_raw = _section(section.get("limits", {}), "agent.limits", set(), limit_names)
    limit_values: dict[str, int | float] = {}
    for name, value in limits_raw.items():
        ok = type(value) in (int, float) if name == "cpus" else type(value) is int
        if not ok:
            raise ConfigError(f"invalid agent.limits.{name}")
        limit_values[name] = value
    kwargs: dict[str, object] = {"action_mode": action_mode, "limits": Limits(**limit_values)}
    for key in ("max_steps", "wall_clock_s", "max_tokens", "image", "runtime"):
        if key in section:
            kwargs[key] = section[key]
    try:
        agent = AgentConfig(**kwargs)  # type: ignore[arg-type]
    except ValueError as exc:
        raise _agent_error(exc) from None
    try:
        _validate_create_inputs(agent.limits, agent.image, agent.runtime, docker_cmd)
    except SandboxError:
        raise ConfigError("invalid agent.limits") from None
    return agent


def load_config(path: pathlib.Path) -> ServiceConfig:
    """Strict: unknown keys at any level, wrong JSON types, bool-for-int, out-of-range values,
    duplicate JSON keys -> ConfigError. Also validates the limits via M1's input validator
    (SandboxError -> ConfigError). Never reads the inference key."""
    path = pathlib.Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise ConfigError("config unreadable") from None
    try:
        raw = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except _DuplicateKey:
        raise ConfigError("duplicate key in config") from None
    except (ValueError, RecursionError):
        raise ConfigError("config is not valid JSON") from None
    base_dir = path.resolve().parent

    top = _section(raw, "config", {"public_origin", "data_dir", "inference"},
                   {"listen", "cookie_secure", "trusted_proxy_header", "samples_manifest",
                    "docker_cmd", "remove_leftover_containers", "agent", "quotas", "retention"})
    listen = _section(top.get("listen", {}), "listen", set(), {"host", "port"})
    host = listen.get("host", "127.0.0.1")
    if host not in ("127.0.0.1", "::1") or not isinstance(host, str):
        raise ConfigError("invalid listen.host")
    port = _int(listen.get("port", 8080), "listen.port", 0, 65535)

    origin = top["public_origin"]
    if not isinstance(origin, str) or not _ORIGIN_RE.fullmatch(origin):
        raise ConfigError("invalid public_origin")
    cookie_secure = _bool(top.get("cookie_secure", True), "cookie_secure")
    header = top.get("trusted_proxy_header", "X-Forwarded-For")
    if header is not None and (not isinstance(header, str) or not _HEADER_RE.fullmatch(header)):
        raise ConfigError("invalid trusted_proxy_header")

    data_dir = pathlib.Path(_text(top["data_dir"], "data_dir"))
    if not data_dir.is_absolute():
        raise ConfigError("invalid data_dir")
    manifest_path = base_dir / _text(top.get("samples_manifest", "samples/manifest.json"),
                                     "samples_manifest")

    docker_raw = top.get("docker_cmd", ["docker"])
    if (not isinstance(docker_raw, list) or not docker_raw
            or any(not isinstance(item, str) or not item or "\x00" in item for item in docker_raw)):
        raise ConfigError("invalid docker_cmd")
    docker_cmd = tuple(docker_raw)
    remove_leftovers = _bool(top.get("remove_leftover_containers", True),
                             "remove_leftover_containers")

    inference, action_mode = _load_inference(top["inference"], base_dir)
    agent = _load_agent(top.get("agent", {}), action_mode, docker_cmd)
    return ServiceConfig(
        listen_host=host, listen_port=port, public_origin=origin,  # type: ignore[arg-type]
        cookie_secure=cookie_secure, trusted_proxy_header=header, data_dir=data_dir,
        manifest_path=manifest_path, docker_cmd=docker_cmd,
        remove_leftover_containers=remove_leftovers, inference=inference, agent=agent,
        quotas=_load_quotas(top.get("quotas", {})),
        retention=_load_retention(top.get("retention", {})))


def _read_key(inference: InferenceConfig) -> str:
    if inference.api_key_env is not None:
        value = os.environ.get(inference.api_key_env)
        if value is None:
            raise ConfigError("inference key unavailable")
    else:
        assert inference.api_key_file is not None
        try:
            fd = os.open(str(inference.api_key_file), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            raise ConfigError("inference key file unreadable") from None
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ConfigError("inference key file permissions")
            data = handle.read(4096)
        try:
            value = data.decode("ascii")
        except UnicodeDecodeError:
            raise ConfigError("inference key is invalid") from None
    value = value.strip()
    if not _KEY_RE.fullmatch(value):
        raise ConfigError("inference key is invalid")
    return value


def make_key_provider(inference: InferenceConfig) -> Callable[[], str]:
    """Reads the key once (env var or file; a file with any group/other permission bit ->
    ConfigError). The key lives only in the closure cell: never in an attribute, repr, log or
    exception text."""
    key = _read_key(inference)

    def provider() -> str:
        return key

    return provider
