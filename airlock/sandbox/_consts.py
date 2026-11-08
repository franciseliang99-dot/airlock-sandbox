"""Constants shared by the sandbox modules.

Every module imports this module (``from . import _consts``) and reads
``_consts.NAME`` at call time, so tests can patch values with
``unittest.mock.patch.object(_consts, "NAME", value)``.
"""
from __future__ import annotations

import re

WORK_ROOT = "/work"
CONTAINER_USER = "1000:1000"
NAME_PREFIX = "airlock-"
NAME_HEX_BYTES = 8                      # secrets.token_hex(8)
LABEL = "airlock=1"
CONTAINER_LIFETIME_S = 3600
TMP_TMPFS_SPEC = "/tmp:rw,size=16m"
DOCKER_RUN_TIMEOUT_S = 60
DOCKER_CTL_TIMEOUT_S = 30               # rm -f
INSPECT_TIMEOUT_S = 15
# After an exec dies with 128/137, docker may record the container stop / OOMKilled flag a
# moment later; poll this long before classifying.
OOM_SETTLE_S = 1.5
OOM_SETTLE_STEP_S = 0.25
FILE_OP_TIMEOUT_S = 15                  # list_dir / read_file / write_file execs
SEED_TIMEOUT_S = 60                     # each seeding exec
DIFF_TIMEOUT_S = 60                     # each diff exec
REAP_TIMEOUT_S = 10
PEAK_TIMEOUT_S = 10
HOST_GRACE_S = 10                       # host backstop = command_timeout_s + HOST_GRACE_S
KILL_WAIT_S = 5                         # wait after Popen.kill()
TIMEOUT_EXIT = 124
TIMEOUT_SLACK_MS = 500
CTL_OUTPUT_CAP = 64 * 1024
INSPECT_OUTPUT_CAP = 256 * 1024
STDERR_CAP_BYTES = 4096
TAIL_BYTES = 4096
READ_CHUNK = 65536
NUMSTAT_MAX_BYTES = 1024**2
MAX_PATH_BYTES = 4096
MAX_COMMAND_BYTES = 32 * 1024
SEED_MAX_TOTAL_BYTES = 64 * 1024**2
SEED_MAX_ENTRIES = 10_000
GIT_AUTHOR_NAME = "Airlock"
GIT_AUTHOR_EMAIL = "airlock@example.invalid"
BASELINE_BRANCH = "airlock"
ALLOWED_ENV_KEYS = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG")
DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"
IMAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}")
RUNTIME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
CID_RE = re.compile(rb"([0-9a-f]{64})\n?")
SHA1_RE = re.compile(rb"([0-9a-f]{40})\n?")
PID_RE = re.compile(rb"([0-9]+)\n?")
NO_SUCH_RE = re.compile(rb"No such (object|container)")
FORK_FAILURE_RE = re.compile(
    rb"fork: (retry: )?Resource temporarily unavailable|Out of memory|[Cc]an't fork|Cannot fork")
NNP_FORMS = frozenset({"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"})
ERROR_CLASSES = frozenset({"docker_unavailable", "rm_failed", "rm_timeout", "inspect_failed",
                           "inspect_timeout", "still_present", "internal_error"})
# (field, min, max) inclusive; ints must be `type(x) is int`, cpus int or float, not bool
LIMIT_BOUNDS = {
    "memory_bytes": (64 * 1024**2, 64 * 1024**3), "cpus": (0.01, 64.0), "pids": (64, 65536),
    "work_tmpfs_bytes": (1024**2, 16 * 1024**3), "command_timeout_s": (1, 3000),
    "output_max_bytes": (1024, 16 * 1024**2), "file_read_max_bytes": (1, 64 * 1024**2),
    "file_write_max_bytes": (1, 64 * 1024**2), "diff_max_bytes": (1, 256 * 1024**2),
}
GIT_SAFE_FLAGS = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                  "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
                  "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
                  "-c", "diff.relative=false")
DIFF_COMMON = ("diff", "--cached", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames")
