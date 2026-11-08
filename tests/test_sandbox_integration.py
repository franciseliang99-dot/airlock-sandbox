"""Integration tests: real Docker with the runsc runtime.

Skipped (not failed) when `docker info` does not list a runsc runtime. Build the image first:
    docker build -t airlock-sandbox:dev sandbox-image
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from airlock.sandbox import Limits, Sandbox  # noqa: E402
from airlock.sandbox._proc import _minimal_env  # noqa: E402

IMAGE = "airlock-sandbox:dev"
BUILD_HINT = "build the image first: docker build -t airlock-sandbox:dev sandbox-image"

_IMAGE_OK = False
_REPO: pathlib.Path | None = None
_CREATED_NAMES: list[str] = []


def _docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], env=_minimal_env(), capture_output=True,
                          timeout=timeout, check=False)


def setUpModule() -> None:
    global _IMAGE_OK, _REPO
    skip = "docker info does not list a runsc runtime; integration tests skipped"
    try:
        info = _docker("info", "--format", "{{json .Runtimes}}", timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        raise unittest.SkipTest(skip) from None
    try:
        runtimes = json.loads(info.stdout or b"{}")
    except ValueError:
        runtimes = {}
    if info.returncode != 0 or not isinstance(runtimes, dict) or "runsc" not in runtimes:
        raise unittest.SkipTest(skip)
    _IMAGE_OK = _docker("image", "inspect", IMAGE).returncode == 0
    _REPO = pathlib.Path(tempfile.mkdtemp(prefix="airlock-it-repo-"))
    (_REPO / "src").mkdir()
    (_REPO / "README.md").write_text("x\n", encoding="utf-8")
    (_REPO / "src" / "app.py").write_text("print(1)\n", encoding="utf-8")


def tearDownModule() -> None:
    if _REPO is not None:
        shutil.rmtree(_REPO, ignore_errors=True)
    leftovers = [n for n in _CREATED_NAMES if _docker("inspect", n).returncode == 0]
    if leftovers:
        # Report only; deleting is the owner's decision.
        sys.stderr.write(f"airlock integration: containers still present: {leftovers}\n")


class IntegrationCase(unittest.TestCase):
    def setUp(self) -> None:
        if not _IMAGE_OK:
            self.fail(BUILD_HINT)

    def make(self, limits: Limits = Limits()) -> Sandbox:
        sb = Sandbox.create(_REPO, limits=limits)
        self.addCleanup(sb.destroy)
        _CREATED_NAMES.append(sb._name)
        return sb

    def run_cmd(self, sb: Sandbox, command: str):
        return sb.call("run_command", {"command": command})


class TestIsolation(IntegrationCase):
    def test_i1_kernel_is_gvisor(self):
        r = self.run_cmd(self.make(), "dmesg")
        self.assertEqual(r.exit_code, 0)
        self.assertIn("gVisor", r.output)

    def test_i2_no_network(self):
        sb = self.make()
        r = self.run_cmd(sb, "python3 -c \"import socket;s=socket.socket();s.settimeout(3);"
                             "s.connect(('1.1.1.1',80))\"")
        self.assertNotEqual(r.exit_code, 0)
        self.assertIn("Error", r.output)
        control = self.run_cmd(sb, "python3 -c \"print(1)\"")
        self.assertEqual(control.exit_code, 0)

    def test_i3_env_canary_absent(self):
        key, value = "AIRLOCK_IT_CANARY", os.urandom(8).hex()
        patcher = mock.patch.dict(os.environ, {key: value})
        patcher.start()
        self.addCleanup(patcher.stop)
        r = self.run_cmd(self.make(), "env; tr '\\0' '\\n' </proc/1/environ")
        self.assertNotIn(key, r.output)
        self.assertNotIn(value, r.output)

    def test_i9_read_only_rootfs(self):
        sb = self.make()
        # The container user (uid 1000) cannot write /etc by file mode alone, so that case
        # proves nothing about the mount. /home/agent is owned by the agent on the rootfs:
        # only a read-only mount can make this touch fail.
        r = self.run_cmd(sb, "touch /home/agent/x")
        self.assertNotEqual(r.exit_code, 0)
        self.assertIn("Read-only file system", r.output)
        self.assertNotEqual(self.run_cmd(sb, "touch /etc/x").exit_code, 0)
        self.assertEqual(self.run_cmd(sb, "touch /work/ok").exit_code, 0)
        self.assertEqual(self.run_cmd(sb, "id -u").output.strip(), "1000")


class TestFilesAndDiff(IntegrationCase):
    def test_i4_round_trip_and_diff(self):
        sb = self.make()
        w = sb.call("write_file", {"path": "hello.txt", "content": "a\nb\n"})
        self.assertTrue(w.ok)
        self.assertEqual(w.exit_code, 0)
        self.assertEqual(sb.call("read_file", {"path": "hello.txt"}).output, "a\nb\n")
        d = sb.collect_diff()
        self.assertEqual(d.state, "ok")
        self.assertIn({"path": "hello.txt", "change": "added",
                       "lines_added": 2, "lines_removed": 0}, d.files)
        self.assertEqual(d.sha256, hashlib.sha256(d.diff_text.encode()).hexdigest())
        fresh = self.make()
        self.assertEqual(fresh.collect_diff().state, "no_changes")
        echo = self.run_cmd(fresh, "echo ok")
        self.assertLess(echo.duration_ms, 5000)

    def test_i5_symlink_in_diff(self):
        sb = self.make()
        self.run_cmd(sb, "ln -s /etc/passwd /work/link && echo hi > /work/f.txt")
        d = sb.collect_diff()
        self.assertEqual(d.state, "ok")
        self.assertIn("new file mode 120000", d.diff_text)
        self.assertIn("+/etc/passwd", d.diff_text)
        self.assertNotIn("root:", d.diff_text)
        paths = {f["path"] for f in d.files}
        self.assertTrue({"link", "f.txt"} <= paths)


class TestLimits(IntegrationCase):
    def test_i6_timeout(self):
        sb = self.make(Limits(command_timeout_s=3))
        started = time.monotonic()
        r = self.run_cmd(sb, "sleep 120")
        self.assertEqual(r.limit_hit, "timeout")
        self.assertLessEqual(time.monotonic() - started, 13)
        after = self.run_cmd(sb, "echo ok")
        self.assertTrue(after.ok)
        self.assertEqual(after.exit_code, 0)

    def test_i7_memory(self):
        r = self.run_cmd(self.make(), "python3 -c \"b=bytearray(900*1024*1024)\"")
        self.assertEqual(r.limit_hit, "memory")

    def test_i8_pids(self):
        sb = self.make()
        r = self.run_cmd(sb, "for i in $(seq 1 40); do sleep 60 & done; sleep 1; echo started")
        self.assertEqual(r.exit_code, 0)
        self.assertIn("started", r.output)
        sb2 = self.make(Limits(command_timeout_s=30))
        bomb = self.run_cmd(sb2, "sh -c 'i=0; while [ $i -lt 1000 ]; do sleep 60 & i=$((i+1)); done; wait'")
        self.assertTrue(bomb.limit_hit in ("pids", "memory", "timeout") or bomb.exit_code != 0)
        after = self.run_cmd(sb2, "echo ok")
        if after.ok:
            self.assertEqual(after.exit_code, 0)
            self.assertIn("ok", after.output)
        else:
            self.assertFalse(self.run_cmd(sb2, "echo ok").ok)

    def test_i11_tmpfs_size(self):
        r = self.run_cmd(self.make(), "dd if=/dev/zero of=/work/big bs=1M count=300")
        self.assertTrue(r.exit_code != 0 or r.limit_hit is not None)

    def test_i12_background_jobs(self):
        sb = self.make(Limits(command_timeout_s=5))
        r = self.run_cmd(sb, "sleep 300 & echo started")
        self.assertIsNone(r.limit_hit)
        self.assertEqual(r.exit_code, 0)
        self.assertLess(r.duration_ms, 4000)
        r2 = self.run_cmd(sb, "setsid sleep 300 >/dev/null 2>&1 & echo started")
        self.assertEqual(r2.exit_code, 0)
        r3 = self.run_cmd(sb, "pgrep -f 'slee[p] 300'")
        self.assertEqual(r3.exit_code, 1)

    def test_i13_timeout_decision_under_load(self):
        # Pins the wrapper's elapsed-time rule: the timeout verdict must not depend on the
        # watcher surviving to its own exit while another sandbox keeps the host CPUs busy.
        sb = self.make(Limits(command_timeout_s=1))
        hog = self.make(Limits(cpus=2.0, command_timeout_s=60))
        hog_errors: list[BaseException] = []

        def spin() -> None:
            try:
                self.run_cmd(hog, "for i in 1 2 3 4; do (while :; do :; done) & done; sleep 40")
            except BaseException as exc:  # reported in the main thread below
                hog_errors.append(exc)

        thread = threading.Thread(target=spin, daemon=True)
        thread.start()
        try:
            time.sleep(2)  # let the spinners start before measuring
            for n in range(8):
                r = self.run_cmd(sb, "sleep 30")
                self.assertEqual(r.limit_hit, "timeout", f"run {n}: {r!r}")
                after = self.run_cmd(sb, "echo ok")
                self.assertTrue(after.ok, f"run {n}: {after!r}")
                self.assertEqual(after.output.strip(), "ok", f"run {n}")
            for n in range(5):
                bg = self.run_cmd(sb, "sleep 30 & echo started")
                self.assertIsNone(bg.limit_hit, f"bg run {n}: {bg!r}")
        finally:
            hog.destroy()  # idempotent; ends the spin so the thread can finish
            thread.join(timeout=60)
        self.assertEqual(hog_errors, [])


class TestDestroy(IntegrationCase):
    def test_i10_destroy_proof(self):
        sb = self.make()
        ref = sb._cid[:12]
        proof = sb.destroy()
        self.assertTrue(proof.verified)
        self.assertEqual(proof.container_ref, ref)
        self.assertNotEqual(_docker("inspect", sb._name).returncode, 0)
        again = sb.destroy()
        self.assertTrue(again.verified)
        listing = _docker("ps", "-a", "-q", "--filter", "label=airlock=1",
                          "--filter", f"name=^/{sb._name}$")
        self.assertEqual(listing.stdout.strip(), b"")


if __name__ == "__main__":
    unittest.main()
