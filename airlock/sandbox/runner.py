"""Sandbox runner: starts one gVisor container, runs the four agent tools through
`docker exec`, builds a capped diff inside the container, and proves destruction."""
from __future__ import annotations

import hashlib
import json
import logging
import pathlib
import secrets
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from types import TracebackType

from . import _argv, _consts, _diff, _policy, _scripts, _seed
from ._proc import _Proc, _run_capped

_log = logging.getLogger("airlock.sandbox")


@dataclass(frozen=True)
class Limits:
    memory_bytes: int = 512 * 1024**2
    cpus: float = 1.0
    pids: int = 256            # runtime threads count against the same limit
    work_tmpfs_bytes: int = 200 * 1024**2
    command_timeout_s: int = 60
    output_max_bytes: int = 64 * 1024      # per tool result, stdout+stderr combined
    file_read_max_bytes: int = 256 * 1024
    file_write_max_bytes: int = 256 * 1024
    diff_max_bytes: int = 2 * 1024**2


@dataclass(frozen=True)
class ToolResult:
    ok: bool                   # False when blocked or the command failed to start
    exit_code: int | None      # None when not executed
    output: str                # decoded UTF-8 with errors="replace", truncated to the cap
    output_bytes: int          # bytes before truncation
    truncated: bool
    duration_ms: int
    blocked_reason: str | None # one of: "path_escape", "forbidden_tool", "too_large", None
    limit_hit: str | None      # one of: "timeout", "memory", "pids", None


@dataclass(frozen=True)
class DiffResult:
    state: str                 # "ok" | "no_changes" | "too_large"
    diff_text: str             # "" unless state == "ok"
    size_bytes: int
    sha256: str | None         # sha256 of diff_text.encode("utf-8") when state == "ok"
    files: list[dict]          # [{"path","change","lines_added","lines_removed"}]


@dataclass(frozen=True)
class DestroyProof:
    container_ref: str         # opaque: first 12 hex of the container id
    verified: bool             # True only if inspect afterwards reports "no such container"
    error_class: str | None


class SandboxError(Exception):
    """Raised only by create() and collect_diff(). Messages are fixed runner text
    (step names / error classes); they never contain agent input, paths, or docker output."""


class _StepFailed(Exception):
    def __init__(self, step: str) -> None:
        super().__init__(step)
        self.step = step


def _fixed(message: str, reason: str | None = None) -> ToolResult:
    """Result for calls that never started an exec: runner-authored text only."""
    return ToolResult(False, None, message, len(message.encode("utf-8")), False, 0, reason, None)


def _validate_create_inputs(limits: object, image: object, runtime: object,
                            docker: object) -> tuple[str, ...]:
    if not isinstance(limits, Limits):
        raise SandboxError("invalid limits")
    for field, (low, high) in _consts.LIMIT_BOUNDS.items():
        value = getattr(limits, field)
        type_ok = type(value) in (int, float) if field == "cpus" else type(value) is int
        if not type_ok or not (low <= value <= high):
            raise SandboxError("invalid limits")
    if not isinstance(image, str) or not _consts.IMAGE_RE.fullmatch(image):
        raise SandboxError("invalid image")
    if not isinstance(runtime, str) or not _consts.RUNTIME_RE.fullmatch(runtime):
        raise SandboxError("invalid runtime")
    if isinstance(docker, (str, bytes)) or not isinstance(docker, Sequence) or len(docker) == 0:
        raise SandboxError("invalid docker command")
    items = tuple(docker)
    if any(not isinstance(item, str) or not item for item in items):
        raise SandboxError("invalid docker command")
    return items


def _is_empty(value: object) -> bool:
    return value is None or (isinstance(value, (list, dict)) and not value)


def _is_int(value: object, expected: int) -> bool:
    return type(value) is int and value == expected


def _host_config_matches(data: object, runtime: str, limits: Limits) -> bool:
    """True only if the daemon reports exactly the isolation settings we asked for."""
    if not isinstance(data, dict):
        return False
    hc = data.get("HostConfig")
    cfg = data.get("Config")
    if not isinstance(hc, dict) or not isinstance(cfg, dict):
        return False
    cap_drop = hc.get("CapDrop")
    security_opt = hc.get("SecurityOpt")
    tmpfs = hc.get("Tmpfs")
    mounts = data.get("Mounts")
    if not isinstance(cap_drop, list) or "ALL" not in cap_drop:
        return False
    if not isinstance(security_opt, list) or not any(
            isinstance(s, str) and s in _consts.NNP_FORMS for s in security_opt):
        return False
    if not isinstance(tmpfs, dict) or set(tmpfs) != {"/work", "/tmp"}:
        return False
    if not (_is_empty(mounts) or (isinstance(mounts, list) and all(
            isinstance(m, dict) and m.get("Type") == "tmpfs" for m in mounts))):
        return False
    return (
        hc.get("Runtime") == runtime
        and hc.get("NetworkMode") == "none"
        and hc.get("ReadonlyRootfs") is True
        and hc.get("Privileged") is False
        and _is_empty(hc.get("CapAdd"))
        and _is_int(hc.get("Memory"), limits.memory_bytes)
        and _is_int(hc.get("MemorySwap"), limits.memory_bytes)
        and _is_int(hc.get("PidsLimit"), limits.pids)
        and _is_int(hc.get("NanoCpus"), round(limits.cpus * 1e9))
        and hc.get("IpcMode") == "none"
        and hc.get("Init") is True
        and _is_empty(hc.get("Binds"))
        and _is_empty(hc.get("Mounts"))
        and _is_empty(hc.get("PortBindings"))
        and cfg.get("User") == _consts.CONTAINER_USER
    )


def _int_or_none(text: str | None) -> int | None:
    if text is None or not text.isascii() or not text.isdigit():
        return None
    return int(text)


def _failure_class(p: _Proc) -> str:
    if p.start_error is not None:
        return p.start_error
    if p.timed_out:
        return "timeout"
    return "nonzero_exit"


class Sandbox:
    TOOLS = ("list_dir", "read_file", "write_file", "run_command")

    # tool name -> bound-method name; set(_DISPATCH) == set(TOOLS) == set(_policy.ARG_SCHEMAS)
    _DISPATCH: dict[str, str] = {
        "list_dir": "_list_dir",
        "read_file": "_read_file",
        "write_file": "_write_file",
        "run_command": "_run_command",
    }

    def __init__(self, *, _cid: str, _name: str, _limits: Limits, _docker: tuple[str, ...],
                 _baseline: str, _keep_pids: tuple[int, ...]) -> None:
        """Internal. Use Sandbox.create()."""
        self._cid = _cid
        self._name = _name
        self._limits = _limits
        self._docker = _docker
        self._baseline = _baseline
        self._keep_pids = _keep_pids
        self._dead = False
        self._destroyed = False
        self._op_lock = threading.Lock()
        self._destroy_lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle

    @classmethod
    def create(cls, sample_repo: pathlib.Path, limits: Limits = Limits(),
               image: str = "airlock-sandbox:dev", runtime: str = "runsc",
               docker: Sequence[str] = ("docker",)) -> "Sandbox":
        """Start, verify and seed one sandbox.

        Inputs are validated and the seed archive is built before any docker call. If
        `docker run` fails, `rm -f <name>` is still issued before SandboxError is raised;
        any failure after it succeeded destroys the container first.
        """
        docker_t = _validate_create_inputs(limits, image, runtime, docker)
        try:
            repo = pathlib.Path(sample_repo)
            seed_tar = _seed.build_seed_tar(repo)
        except _seed.SeedError as exc:
            raise SandboxError(f"seed refused: {exc.kind}") from None
        except (OSError, TypeError):
            raise SandboxError("seed refused: unreadable") from None

        name = _consts.NAME_PREFIX + secrets.token_hex(_consts.NAME_HEX_BYTES)
        run_argv = _argv.build_run_argv(docker_t, name=name, limits=limits, image=image,
                                        runtime=runtime)
        p = _run_capped(run_argv, stdin=None, timeout_s=_consts.DOCKER_RUN_TIMEOUT_S,
                        cap=_consts.CTL_OUTPUT_CAP, merge_stderr=False)
        match = None
        if p.start_error is None and not p.timed_out and p.returncode == 0:
            match = _consts.CID_RE.fullmatch(p.out)
        if match is None:
            cls._force_remove(docker_t, name)
            _log.warning("create step=run failed error_class=%s", _failure_class(p))
            raise SandboxError("create failed: run")

        cid = match.group(1).decode("ascii")
        sandbox = cls(_cid=cid, _name=name, _limits=limits, _docker=docker_t,
                      _baseline="", _keep_pids=(1,))
        git = ["git", *_consts.GIT_SAFE_FLAGS]
        try:
            sandbox._verify_host_config(runtime)
            sandbox._ctl("seed", ["tar", "-x", "-f", "-", "-C", _consts.WORK_ROOT],
                         stdin=seed_tar, timeout_s=_consts.SEED_TIMEOUT_S)
            sandbox._ctl("git_init", [*git, "-c", f"init.defaultBranch={_consts.BASELINE_BRANCH}",
                                      "init", "-q", _consts.WORK_ROOT])
            sandbox._ctl("git_add", [*git, "-C", _consts.WORK_ROOT, "add", "-A", "-f"])
            sandbox._ctl("git_commit", [
                *git, "-c", f"user.name={_consts.GIT_AUTHOR_NAME}",
                "-c", f"user.email={_consts.GIT_AUTHOR_EMAIL}",
                "-C", _consts.WORK_ROOT, "commit", "-q", "--allow-empty", "--no-verify",
                "-m", "airlock baseline"])
            sha = sandbox._ctl("baseline", [*git, "-C", _consts.WORK_ROOT, "rev-parse",
                                            "--verify", "HEAD^{commit}"])
            sha_match = _consts.SHA1_RE.fullmatch(sha.out)
            if sha_match is None:
                raise _StepFailed("baseline")
            sandbox._baseline = sha_match.group(1).decode("ascii")
            pid_proc = sandbox._ctl("main_pid", ["pgrep", "-x", "sleep"])
            pid_match = _consts.PID_RE.fullmatch(pid_proc.out)
            if pid_match is None or int(pid_match.group(1)) == 1:
                raise _StepFailed("main_pid")
            sandbox._keep_pids = (1, int(pid_match.group(1)))
        except _StepFailed as exc:
            sandbox.destroy()
            raise SandboxError(f"create failed: {exc.step}") from None
        except SandboxError:
            sandbox.destroy()
            raise
        except Exception:
            sandbox.destroy()
            raise SandboxError("create failed: internal") from None
        except BaseException:
            sandbox.destroy()
            raise
        _log.info("create container_ref=%s", cid[:12])
        return sandbox

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> bool:
        self.destroy()
        return False

    def destroy(self) -> DestroyProof:
        """Never raises. Idempotent: every call re-runs rm -f and inspect.

        verified=True only when inspect exits non-zero and its stderr says the container
        does not exist. error_class is None when verified, else one of ERROR_CLASSES.
        """
        ref = self._cid[:12]
        try:
            self._destroyed = True          # set first: new calls are refused immediately
            with self._destroy_lock:        # destroy never takes _op_lock
                proof = self._destroy_locked(ref)
        except Exception:
            proof = DestroyProof(ref, False, "internal_error")
        _log.info("destroy container_ref=%s verified=%s error_class=%s",
                  ref, proof.verified, proof.error_class)
        return proof

    def _destroy_locked(self, ref: str) -> DestroyProof:
        rm = _run_capped(_argv.build_rm_argv(self._docker, self._cid), stdin=None,
                         timeout_s=_consts.DOCKER_CTL_TIMEOUT_S, cap=_consts.CTL_OUTPUT_CAP,
                         merge_stderr=False)
        if rm.start_error is not None:
            return DestroyProof(ref, False, "docker_unavailable")
        rm_class: str | None = None
        if rm.timed_out:
            rm_class = "rm_timeout"
        elif rm.returncode != 0:
            rm_class = "rm_failed"
        ins = _run_capped(_argv.build_inspect_argv(self._docker, self._cid, "{{.Id}}"),
                          stdin=None, timeout_s=_consts.INSPECT_TIMEOUT_S,
                          cap=_consts.CTL_OUTPUT_CAP, merge_stderr=False)
        if ins.start_error is not None:
            return DestroyProof(ref, False, "docker_unavailable")
        if ins.timed_out:
            return DestroyProof(ref, False, "inspect_timeout")
        if ins.returncode == 0:
            return DestroyProof(ref, False, rm_class or "still_present")
        if _consts.NO_SUCH_RE.search(ins.err):
            return DestroyProof(ref, True, None)
        return DestroyProof(ref, False, "inspect_failed")

    @staticmethod
    def _force_remove(docker: tuple[str, ...], ref: str) -> None:
        """rm -f by name or id; never raises."""
        try:
            p = _run_capped(_argv.build_rm_argv(docker, ref), stdin=None,
                            timeout_s=_consts.DOCKER_CTL_TIMEOUT_S, cap=_consts.CTL_OUTPUT_CAP,
                            merge_stderr=False)
            if p.start_error is not None or p.timed_out or p.returncode != 0:
                _log.warning("force_remove failed error_class=%s", _failure_class(p))
        except Exception:
            _log.warning("force_remove failed error_class=internal_error")

    # ------------------------------------------------------------------ plumbing

    def _exec(self, cmd: Sequence[str], *, stdin: bytes | None, timeout_s: float, cap: int,
              merge: bool) -> _Proc:
        argv = _argv.build_exec_argv(self._docker, self._cid, cmd, stdin=stdin is not None)
        return _run_capped(argv, stdin=stdin, timeout_s=timeout_s, cap=cap, merge_stderr=merge)

    def _ctl(self, step: str, cmd: Sequence[str], *, stdin: bytes | None = None,
             timeout_s: float | None = None) -> _Proc:
        """Control exec used while seeding; any failure becomes _StepFailed(step)."""
        p = self._exec(cmd, stdin=stdin,
                       timeout_s=_consts.SEED_TIMEOUT_S if timeout_s is None else timeout_s,
                       cap=_consts.CTL_OUTPUT_CAP, merge=False)
        if p.start_error is not None or p.timed_out or p.returncode != 0 or p.stdin_error:
            _log.warning("create step=%s failed error_class=%s", step, _failure_class(p))
            raise _StepFailed(step)
        return p

    def _inspect(self, fmt: str, cap: int, timeout_s: float = _consts.INSPECT_TIMEOUT_S) -> _Proc:
        return _run_capped(_argv.build_inspect_argv(self._docker, self._cid, fmt), stdin=None,
                           timeout_s=timeout_s, cap=cap, merge_stderr=False)

    def _verify_host_config(self, runtime: str) -> None:
        """Fail closed unless the daemon reports the isolation settings we requested."""
        p = self._inspect("{{json .}}", _consts.INSPECT_OUTPUT_CAP)
        if (p.start_error is not None or p.timed_out or p.returncode != 0
                or p.out_total > _consts.INSPECT_OUTPUT_CAP):
            raise SandboxError("create failed: verify")
        try:
            data = json.loads(p.out)
        except ValueError:
            raise SandboxError("create failed: verify") from None
        if not _host_config_matches(data, runtime, self._limits):
            raise SandboxError("create failed: verify")

    def _container_state(self, timeout_s: float = _consts.INSPECT_TIMEOUT_S
                         ) -> tuple[str, bool | None]:
        p = self._inspect("{{.State.Running}} {{.State.OOMKilled}}", _consts.CTL_OUTPUT_CAP,
                          timeout_s)
        if p.start_error is not None or p.timed_out or p.returncode != 0:
            return ("unknown", None)
        words = p.out.decode("ascii", "replace").split()
        if len(words) != 2 or words[0] not in ("true", "false") or words[1] not in ("true", "false"):
            return ("unknown", None)
        return ("running" if words[0] == "true" else "stopped", words[1] == "true")

    def _settled_state(self, p: _Proc) -> tuple[str, bool | None]:
        """Container state after a failed exec. A kill (rc 128/137) can be recorded by docker a
        moment after the exec returns, so poll briefly until it shows as an OOM stop. The whole
        poll, re-probes included, is bounded by OOM_SETTLE_S of elapsed time."""
        state, oom = self._container_state()
        if p.timed_out or p.returncode not in (128, 137):
            return state, oom
        end = time.monotonic() + _consts.OOM_SETTLE_S
        while not (state == "stopped" and oom is True):
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(_consts.OOM_SETTLE_STEP_S, remaining))
            state, oom = self._container_state(max(0.1, end - time.monotonic()))
        return state, oom

    def _reap(self) -> None:
        """Kill every process except init and the main sleep; failures are only logged."""
        try:
            cmd = ["sh", "-c", _scripts.REAP_SCRIPT, "airlock-reap",
                   *(str(pid) for pid in self._keep_pids)]
            p = self._exec(cmd, stdin=None, timeout_s=_consts.REAP_TIMEOUT_S,
                           cap=_consts.CTL_OUTPUT_CAP, merge=False)
            if p.start_error is not None or p.timed_out or p.returncode != 0:
                _log.warning("reap failed error_class=%s", _failure_class(p))
        except Exception:
            _log.warning("reap failed error_class=internal_error")

    # ------------------------------------------------------------------ tools

    def call(self, tool: str, args: dict) -> ToolResult:
        """Never raises. Validation happens before any docker invocation.

        output is the raw exec output whenever an exec was started and a fixed runner
        message otherwise. A call made while another operation holds the lock returns
        "sandbox busy"; after destroy() it returns "sandbox destroyed".
        """
        try:
            return self._call(tool, args)
        except Exception:
            _log.error("call failed error_class=internal_error")
            return _fixed("internal error")

    def _call(self, tool: object, args: object) -> ToolResult:
        if self._destroyed:
            return _fixed("sandbox destroyed")
        v = _policy.validate_call(tool, args,
                                  file_write_max_bytes=self._limits.file_write_max_bytes)
        if isinstance(v, _policy.Rejection):
            known = tool if isinstance(tool, str) and tool in _policy.ARG_SCHEMAS else "-"
            _log.info("call tool=%s blocked_reason=%s", known, v.blocked_reason)
            return _fixed(v.message, v.blocked_reason)
        if self._dead:
            return _fixed("sandbox not running")
        if not self._op_lock.acquire(blocking=False):
            return _fixed("sandbox busy")
        try:
            if self._destroyed:
                return _fixed("sandbox destroyed")
            result = getattr(self, self._DISPATCH[v.tool])(v)
        finally:
            self._op_lock.release()
        _log.info("call tool=%s ok=%s exit_code=%s limit_hit=%s blocked_reason=%s "
                  "duration_ms=%d output_bytes=%d", v.tool, result.ok, result.exit_code,
                  result.limit_hit, result.blocked_reason, result.duration_ms,
                  result.output_bytes)
        return result

    def _finish(self, p: _Proc, *, classify: bool, reap_always: bool) -> ToolResult:
        """Turn an exec outcome into a ToolResult (shared by all four tools)."""
        if p.start_error is not None:
            return _fixed("docker unavailable")
        text = p.out.decode("utf-8", "replace")
        truncated = p.out_total > len(p.out)
        if p.timed_out or p.returncode != 0:
            state, oom = ("unknown", None) if self._destroyed else self._settled_state(p)
            if state == "stopped":
                self._dead = True
                memory = p.returncode == 137 or oom is True
                return ToolResult(False, None, text, p.out_total, truncated, p.duration_ms,
                                  None, "memory" if memory else None)
        if p.timed_out:
            result = ToolResult(False, None, text, p.out_total, truncated, p.duration_ms,
                                None, "timeout")
        else:
            limit = None
            if classify:
                limit = _policy.classify_limit(
                    rc=p.returncode, duration_ms=p.duration_ms,
                    timeout_s=self._limits.command_timeout_s, host_timed_out=False,
                    output_tail=p.tail)
            result = ToolResult(not p.stdin_error, p.returncode, text, p.out_total, truncated,
                                p.duration_ms, None, limit)
        if not self._destroyed and (reap_always or p.timed_out):
            self._reap()
        return result

    def _list_dir(self, v: _policy.Validated) -> ToolResult:
        p = self._exec(["ls", "-la", "--", v.path or _consts.WORK_ROOT], stdin=None,
                       timeout_s=_consts.FILE_OP_TIMEOUT_S, cap=self._limits.output_max_bytes,
                       merge=True)
        return self._finish(p, classify=False, reap_always=False)

    def _read_file(self, v: _policy.Validated) -> ToolResult:
        limits = self._limits
        p = self._exec(["head", "-c", str(limits.file_read_max_bytes + 1), "--",
                        v.path or _consts.WORK_ROOT], stdin=None,
                       timeout_s=_consts.FILE_OP_TIMEOUT_S, cap=limits.output_max_bytes,
                       merge=True)
        if (p.start_error is None and not p.timed_out and p.returncode == 0
                and p.out_total > limits.file_read_max_bytes):
            message = "file too large"
            return ToolResult(False, p.returncode, message, len(message), False,
                              p.duration_ms, "too_large", None)
        return self._finish(p, classify=False, reap_always=False)

    def _write_file(self, v: _policy.Validated) -> ToolResult:
        p = self._exec(["sh", "-c", _scripts.WRITE_SCRIPT, "airlock-write",
                        v.path or _consts.WORK_ROOT], stdin=v.content or b"",
                       timeout_s=_consts.FILE_OP_TIMEOUT_S, cap=self._limits.output_max_bytes,
                       merge=True)
        return self._finish(p, classify=False, reap_always=False)

    def _run_command(self, v: _policy.Validated) -> ToolResult:
        limits = self._limits
        p = self._exec(["bash", "-c", _scripts.RUN_WRAPPER, "airlock-run",
                        str(limits.command_timeout_s), v.command or ""], stdin=None,
                       timeout_s=limits.command_timeout_s + _consts.HOST_GRACE_S,
                       cap=limits.output_max_bytes, merge=True)
        return self._finish(p, classify=True, reap_always=True)

    # ------------------------------------------------------------------ diff

    def collect_diff(self) -> DiffResult:
        """Build the diff against the baseline inside the container.

        Raises SandboxError on docker failure, timeout, non-zero git exit, unparseable
        git output, a dead or destroyed sandbox, or a concurrent operation.
        """
        if self._destroyed or self._dead:
            raise SandboxError("diff failed: sandbox unavailable")
        if not self._op_lock.acquire(blocking=False):
            raise SandboxError("diff failed: busy")
        try:
            if self._destroyed:
                raise SandboxError("diff failed: sandbox unavailable")
            result = self._collect_diff_locked()
        finally:
            self._op_lock.release()
        _log.info("diff state=%s size_bytes=%d files=%d", result.state, result.size_bytes,
                  len(result.files))
        return result

    def _diff_exec(self, step: str, cmd: Sequence[str], cap: int) -> _Proc:
        p = self._exec(cmd, stdin=None, timeout_s=_consts.DIFF_TIMEOUT_S, cap=cap, merge=False)
        if p.start_error is not None or p.timed_out or p.returncode != 0:
            _log.warning("diff step=%s failed error_class=%s", step, _failure_class(p))
            raise SandboxError(f"diff failed: {step}")
        return p

    def _collect_diff_locked(self) -> DiffResult:
        git = ["git", *_consts.GIT_SAFE_FLAGS, "-C", _consts.WORK_ROOT]
        base = self._baseline
        self._diff_exec("add", [*git, "add", "-A", "-f"], _consts.CTL_OUTPUT_CAP)
        raw = self._diff_exec("raw", [*git, *_consts.DIFF_COMMON, "--raw", "-z", base],
                              _consts.NUMSTAT_MAX_BYTES)
        num = self._diff_exec("numstat", [*git, *_consts.DIFF_COMMON, "--numstat", "-z", base],
                              _consts.NUMSTAT_MAX_BYTES)
        patch = self._diff_exec(
            "patch", [*git, *_consts.DIFF_COMMON, "--binary", "--full-index",
                      "--src-prefix=a/", "--dst-prefix=b/", base],
            self._limits.diff_max_bytes)
        files: list[dict] = []
        if raw.out_total <= _consts.NUMSTAT_MAX_BYTES and num.out_total <= _consts.NUMSTAT_MAX_BYTES:
            try:
                files = _diff.build_files(_diff.parse_raw_z(raw.out),
                                          _diff.parse_numstat_z(num.out))
            except ValueError:
                raise SandboxError("diff failed: parse") from None
        if patch.out_total == 0:
            return DiffResult("no_changes", "", 0, None, [])
        if patch.out_total > self._limits.diff_max_bytes:
            return DiffResult("too_large", "", patch.out_total, None, files)
        text = patch.out.decode("utf-8", "replace")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return DiffResult("ok", text, patch.out_total, digest, files)

    # ------------------------------------------------------------------ peak

    def resource_peak(self) -> dict:
        """{"memory_bytes", "pids", "cpu_ms"}: sampled now; caller keeps the maximum.

        Best effort and never raises; each key is parsed independently and is None when
        its source is missing or not an integer.
        """
        empty: dict = {"memory_bytes": None, "pids": None, "cpu_ms": None}
        try:
            if self._destroyed or self._dead:
                return empty
            if not self._op_lock.acquire(blocking=False):
                return empty
            try:
                p = self._exec(["sh", "-c", _scripts.PEAK_SCRIPT, "airlock-peak"], stdin=None,
                               timeout_s=_consts.PEAK_TIMEOUT_S, cap=_consts.CTL_OUTPUT_CAP,
                               merge=False)
            finally:
                self._op_lock.release()
            if p.start_error is not None or p.timed_out or p.returncode != 0:
                return empty
            values: dict[str, str] = {}
            for line in p.out.decode("utf-8", "replace").splitlines():
                parts = line.split()
                if len(parts) == 2:
                    values[parts[0]] = parts[1]
            cpu_ns = _int_or_none(values.get("cpu_ns"))
            return {
                "memory_bytes": _int_or_none(values.get("memory_bytes")),
                "pids": _int_or_none(values.get("pids")),
                "cpu_ms": None if cpu_ns is None else cpu_ns // 1_000_000,
            }
        except Exception:
            _log.warning("resource_peak failed error_class=internal_error")
            return empty
