"""Pure builders for docker argv lists. Agent text only ever appears inside `cmd`."""
from __future__ import annotations

from collections.abc import Sequence

from . import _consts


def build_run_argv(docker: Sequence[str], *, name: str, limits, image: str,
                   runtime: str) -> list[str]:
    work = _consts.WORK_ROOT
    return [
        *docker, "run", "-d", "--pull", "never",
        "--name", name, "--label", _consts.LABEL,
        f"--runtime={runtime}", "--network", "none",
        "--memory", str(limits.memory_bytes), "--memory-swap", str(limits.memory_bytes),
        "--cpus", f"{limits.cpus:g}", "--pids-limit", str(limits.pids),
        "--read-only",
        "--tmpfs", f"{work}:rw,size={limits.work_tmpfs_bytes},uid=1000,gid=1000,mode=0755",
        "--tmpfs", _consts.TMP_TMPFS_SPEC,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", _consts.CONTAINER_USER, "--init", "--ipc", "none",
        "--log-driver", "none", "--workdir", work,
        image, "sleep", str(_consts.CONTAINER_LIFETIME_S),
    ]


def build_exec_argv(docker: Sequence[str], cid: str, cmd: Sequence[str], *,
                    stdin: bool) -> list[str]:
    return [*docker, "exec", *(["-i"] if stdin else []), "-w", _consts.WORK_ROOT, cid, *cmd]


def build_rm_argv(docker: Sequence[str], ref: str) -> list[str]:
    return [*docker, "rm", "-f", ref]


def build_inspect_argv(docker: Sequence[str], ref: str, fmt: str) -> list[str]:
    return [*docker, "inspect", "--type", "container", "--format", fmt, ref]
