"""Unit tests for the sandbox runner. They use a fake docker CLI; no Docker is needed."""
from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import io
import json
import logging
import os
import pathlib
import re
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from airlock.sandbox import Limits, Sandbox, SandboxError  # noqa: E402
from airlock.sandbox import _consts, _policy, _proc, _scripts, _seed  # noqa: E402

FAKE_SOURCE = pathlib.Path(__file__).with_name("fake_docker.py")
FAKE_CID = "ab12" * 16
SANDBOX_DIR = ROOT / "airlock" / "sandbox"


def adjacent_pairs(argv):
    return {(argv[i], argv[i + 1]) for i in range(len(argv) - 1)}


class FakeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="airlock-ut-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.docker = self.tmp / "docker"
        source = FAKE_SOURCE.read_text(encoding="utf-8")
        self.docker.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
        self.docker.chmod(0o755)
        self.script = self.tmp / "script.json"
        self.calls_file = self.tmp / "calls.jsonl"
        self.repo = self.tmp / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "README.md").write_text("x\n", encoding="utf-8")
        (self.repo / "src" / "app.py").write_text("print(1)\n", encoding="utf-8")
        self.set_rules([])

    def set_rules(self, rules):
        self.script.write_text(json.dumps(rules), encoding="utf-8")

    def reset_calls(self):
        if self.calls_file.exists():
            self.calls_file.unlink()

    def calls(self):
        if not self.calls_file.exists():
            return []
        lines = self.calls_file.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def sub_argvs(self):
        return [c["argv"] for c in self.calls()]

    def exec_calls(self):
        return [c for c in self.calls() if c["argv"][0] == "exec"]

    def run_argv(self):
        return next(a for a in self.sub_argvs() if a[0] == "run")

    def create(self, **kwargs):
        sb = Sandbox.create(self.repo, docker=(str(self.docker),), **kwargs)
        self.addCleanup(sb.destroy)
        return sb


class TestFlagsAndEnv(FakeCase):
    def test_u1_run_argv_flags(self):
        self.create()
        run = self.run_argv()
        pairs = adjacent_pairs(run)
        expected = [
            ("--network", "none"), ("--memory", str(512 * 1024**2)),
            ("--memory-swap", str(512 * 1024**2)), ("--cpus", "1"), ("--pids-limit", "256"),
            ("--tmpfs", "/work:rw,size=209715200,uid=1000,gid=1000,mode=0755"),
            ("--tmpfs", "/tmp:rw,size=16m"), ("--cap-drop", "ALL"),
            ("--security-opt", "no-new-privileges"), ("--user", "1000:1000"),
            ("--ipc", "none"), ("--label", "airlock=1"),
        ]
        for pair in expected:
            self.assertIn(pair, pairs)
        for token in ("--runtime=runsc", "--read-only", "--init"):
            self.assertIn(token, run)
        name = run[run.index("--name") + 1]
        self.assertRegex(name, r"\Aairlock-[0-9a-f]{16}\Z")
        self.assertEqual(run[-3:], ["airlock-sandbox:dev", "sleep", "3600"])
        forbidden = {"-v", "--volume", "--mount", "--privileged", "-e", "--env", "--env-file",
                     "-p", "--publish", "--cap-add", "--device", "--pid", "--uts", "--userns"}
        self.assertEqual(forbidden & set(run), set())
        for token in run:
            for bad in ("docker.sock", "unconfined", "label=disable"):
                self.assertNotIn(bad, token)
        for call in self.exec_calls():
            argv = call["argv"]
            head = argv[:argv.index(FAKE_CID)]
            for bad in ("-e", "-u", "-t", "--privileged"):
                self.assertNotIn(bad, head)

    def test_u2_minimal_env_is_exact(self):
        parent = {"PATH": "/p", "HOME": "/h", "DOCKER_CONTEXT": "c",
                  "AIRLOCK_TEST_CANARY": "z", "LANG": "C"}
        self.assertEqual(_proc._minimal_env(parent),
                         {"PATH": "/p", "HOME": "/h", "DOCKER_CONTEXT": "c"})
        self.assertEqual(_proc._minimal_env({}), {"PATH": _consts.DEFAULT_PATH})

    def test_u2_recorded_env_has_no_canary(self):
        env = {"AIRLOCK_TEST_CANARY": "u2-canary-7f3a", "DOCKER_CONTEXT": "ctx"}
        with mock.patch.dict(os.environ, env):
            sb = self.create()
            sb.call("run_command", {"command": "echo hi"})
        calls = self.calls()
        self.assertGreater(len(calls), 3)
        # The fake interpreter itself may add platform keys (macOS text encoding, or the
        # C-locale coercion variable); only those are tolerated.
        tolerated = {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"}
        for call in calls:
            self.assertNotIn("AIRLOCK_TEST_CANARY", call["env"])
            self.assertEqual(call["env"].get("DOCKER_CONTEXT"), "ctx")
            self.assertLessEqual(set(call["env"]) - tolerated, set(_consts.ALLOWED_ENV_KEYS))


class TestPolicy(FakeCase):
    def test_u3_path_table(self):
        allowed = {"a.txt": "/work/a.txt", "./d/../a.txt": "/work/a.txt",
                   "/work/x": "/work/x", "": "/work"}
        for raw, want in allowed.items():
            self.assertEqual(_policy.resolve_work_path(raw), want, raw)
        blocked = ["/etc/passwd", "../x", "/work/../etc", "d/../../x", "/workx", "//work/x"]
        sb = self.create()
        before = len(self.calls())
        self.assertGreater(before, 0)
        for raw in blocked:
            self.assertIsNone(_policy.resolve_work_path(raw), raw)
            r = sb.call("read_file", {"path": raw})
            self.assertFalse(r.ok)
            self.assertIsNone(r.exit_code)
            self.assertEqual(r.blocked_reason, "path_escape")
        self.assertEqual(len(self.calls()), before)

    def test_u4_tool_validation(self):
        self.assertEqual(set(Sandbox.TOOLS), set(Sandbox._DISPATCH))
        self.assertEqual(set(Sandbox.TOOLS), set(_policy.ARG_SCHEMAS))
        sb = self.create()
        before = len(self.calls())
        self.assertGreater(before, 0)
        bad_calls = [
            ("rm_rf", {}), ("read_file", {}), ("read_file", {"path": "a", "extra": "1"}),
            ("read_file", {"path": 1}), ("read_file", ["a"]),
            ("write_file", {"path": "a", "content": "\ud800"}),
            ("run_command", {"command": "a\x00b"}), (None, {}),
        ]
        for tool, args in bad_calls:
            r = sb.call(tool, args)
            self.assertFalse(r.ok)
            self.assertIsNone(r.exit_code)
            self.assertEqual(r.blocked_reason, "forbidden_tool")
        self.assertEqual(len(self.calls()), before)

    def test_u14_classify_limit_table(self):
        rows = [
            (None, 70000, 60, True, b"", "timeout"),
            (124, 1200, 1, False, b"", "timeout"),
            (124, 10, 60, False, b"", None),
            (137, 40, 60, False, b"Killed\n", "memory"),
            (1, 900, 60, False, b"bash: fork: retry: Resource temporarily unavailable\n", "pids"),
            (2, 5, 60, False, b"sh: Out of memory\n", "pids"),
            (0, 5, 60, False, b"Out of memory", None),
            (1, 5, 60, False, b"error\n", None),
        ]
        for rc, dur, tmo, host, tail, want in rows:
            got = _policy.classify_limit(rc=rc, duration_ms=dur, timeout_s=tmo,
                                         host_timed_out=host, output_tail=tail)
            self.assertEqual(got, want, (rc, dur, tmo, host, tail))

    def test_u15_size_limits(self):
        sb = self.create()
        before = len(self.calls())
        limits = Limits()
        r = sb.call("write_file", {"path": "big.txt", "content": "a" * (limits.file_write_max_bytes + 1)})
        self.assertEqual(r.blocked_reason, "too_large")
        r = sb.call("run_command", {"command": "a" * (_consts.MAX_COMMAND_BYTES + 1)})
        self.assertEqual(r.blocked_reason, "too_large")
        self.assertEqual(len(self.calls()), before)
        r = sb.call("write_file", {"path": "big.txt", "content": "a" * limits.file_write_max_bytes})
        self.assertTrue(r.ok)
        last = self.exec_calls()[-1]
        self.assertEqual(last["stdin_len"], limits.file_write_max_bytes)
        cmd = last["argv"][last["argv"].index(FAKE_CID) + 1:]
        self.assertEqual(cmd, ["sh", "-c", _scripts.WRITE_SCRIPT, "airlock-write", "/work/big.txt"])

    def test_u15_read_too_large(self):
        n = Limits().file_read_max_bytes + 1
        self.set_rules([{"sub": "exec", "all_of": ["head"], "stdout_repeat": ["y", n]}])
        sb = self.create()
        r = sb.call("read_file", {"path": "big.bin"})
        self.assertFalse(r.ok)
        self.assertEqual(r.blocked_reason, "too_large")


class TestOutputAndDiff(FakeCase):
    def test_u5_output_truncation(self):
        self.set_rules([{"sub": "exec", "all_of": ["bash"], "stdout_repeat": ["x", 70000]}])
        sb = self.create()
        r = sb.call("run_command", {"command": "yes"})
        self.assertTrue(r.truncated)
        self.assertEqual(r.output_bytes, 70000)
        self.assertEqual(len(r.output), Limits().output_max_bytes)
        self.assertTrue(r.ok)
        self.assertEqual(r.exit_code, 0)
        self.set_rules([{"sub": "exec", "all_of": ["bash"], "stdout_text": "0123456789"}])
        r = sb.call("run_command", {"command": "echo"})
        self.assertFalse(r.truncated)
        self.assertEqual(r.output_bytes, 10)

    def test_u6_diff_too_large(self):
        self.set_rules([{"sub": "exec", "all_of": ["--binary"], "stdout_repeat": ["+", 1025]}])
        sb = self.create(limits=Limits(diff_max_bytes=1024))
        d = sb.collect_diff()
        self.assertEqual(d.state, "too_large")
        self.assertEqual(d.diff_text, "")
        self.assertIsNone(d.sha256)
        self.assertEqual(d.size_bytes, 1025)
        self.assertIsInstance(d.files, list)

    def test_u17_diff_results(self):
        sb = self.create()
        d = sb.collect_diff()
        self.assertEqual((d.state, d.size_bytes, d.sha256, d.files), ("no_changes", 0, None, []))

        raw = b":000000 100644 " + b"0" * 40 + b" " + b"1" * 40 + b" A\0h.txt\0"
        patch = b"diff --git a/h.txt b/h.txt\n+hi\n"
        self.set_rules([
            {"sub": "exec", "all_of": ["--raw"], "stdout_b64": base64.b64encode(raw).decode()},
            {"sub": "exec", "all_of": ["--numstat"], "stdout_text": "1\t0\th.txt\0"},
            {"sub": "exec", "all_of": ["--binary"], "stdout_b64": base64.b64encode(patch).decode()},
        ])
        d = sb.collect_diff()
        self.assertEqual(d.state, "ok")
        self.assertEqual(d.diff_text, patch.decode())
        self.assertEqual(d.sha256, hashlib.sha256(d.diff_text.encode()).hexdigest())
        self.assertEqual(d.files, [{"path": "h.txt", "change": "added",
                                    "lines_added": 1, "lines_removed": 0}])
        patch_call = next(c["argv"] for c in self.exec_calls() if "--binary" in c["argv"])
        for flag in ("--no-ext-diff", "--no-textconv", "--binary"):
            self.assertIn(flag, patch_call)
        self.assertEqual(patch_call[-1], sb._baseline)

        raw_bytes = b"diff --git a/b b/b\n+\xff\n"
        self.set_rules([{"sub": "exec", "all_of": ["--binary"],
                         "stdout_b64": base64.b64encode(raw_bytes).decode()}])
        d = sb.collect_diff()
        self.assertEqual(d.state, "ok")
        self.assertIn("\ufffd", d.diff_text)
        self.assertEqual(d.sha256, hashlib.sha256(d.diff_text.encode()).hexdigest())
        self.assertEqual(d.size_bytes, len(raw_bytes))

        self.set_rules([{"sub": "exec", "all_of": ["--raw"], "stdout_text": "garbage"}])
        with self.assertRaises(SandboxError):
            sb.collect_diff()


class TestDestroy(FakeCase):
    def test_u7_destroy_variants(self):
        sb = self.create()
        proof = sb.destroy()
        self.assertTrue(proof.verified)
        self.assertIsNone(proof.error_class)
        self.assertEqual(proof.container_ref, FAKE_CID[:12])
        argvs = self.sub_argvs()
        rm_index = argvs.index(["rm", "-f", FAKE_CID])
        inspect_index = max(i for i, a in enumerate(argvs) if a[0] == "inspect")
        self.assertLess(rm_index, inspect_index)
        self.assertTrue(sb.destroy().verified)  # (d) second call

    def test_u7_still_present(self):
        self.set_rules([{"sub": "inspect", "all_of": ["{{.Id}}"], "rc": 0, "stdout_text": FAKE_CID}])
        sb = self.create()
        proof = sb.destroy()
        self.assertFalse(proof.verified)
        self.assertEqual(proof.error_class, "still_present")

    def test_u7_docker_missing(self):
        sb = self.create()
        self.docker.unlink()
        proof = sb.destroy()
        self.assertFalse(proof.verified)
        self.assertEqual(proof.error_class, "docker_unavailable")

    def test_u7_context_manager(self):
        with self.assertRaises(RuntimeError):
            with Sandbox.create(self.repo, docker=(str(self.docker),)):
                raise RuntimeError("boom")
        self.assertIn(["rm", "-f", FAKE_CID], self.sub_argvs())

    def test_u12_destroy_does_not_wait_for_call(self):
        self.set_rules([{"sub": "exec", "all_of": ["bash"], "sleep_s": 4, "stdout_text": "done"}])
        sb = self.create()
        box = {}

        def worker():
            try:
                box["result"] = sb.call("run_command", {"command": "sleep 4"})
            except Exception as exc:  # recorded for the assertion below
                box["error"] = exc

        thread = threading.Thread(target=worker)
        thread.start()
        time.sleep(0.3)
        started = time.monotonic()
        proof = sb.destroy()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 2.0)
        self.assertTrue(proof.verified)
        thread.join(6)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", box)
        count = len(self.exec_calls())
        r = sb.call("run_command", {"command": "echo ok"})
        self.assertFalse(r.ok)
        self.assertIn("sandbox destroyed", r.output)
        self.assertEqual(len(self.exec_calls()), count)


class TestCreateFailures(FakeCase):
    def test_u8_seed_failure_removes_container(self):
        self.set_rules([{"sub": "exec", "all_of": ["tar"], "rc": 2}])
        with self.assertRaises(SandboxError) as cm:
            Sandbox.create(self.repo, docker=(str(self.docker),))
        self.assertIn("seed", str(cm.exception))
        self.assertNotIn(str(self.repo), str(cm.exception))
        argvs = self.sub_argvs()
        self.assertIn(["rm", "-f", FAKE_CID], argvs)
        rm_index = argvs.index(["rm", "-f", FAKE_CID])
        self.assertTrue(any(a[0] == "inspect" for a in argvs[rm_index:]))

    def test_u9_seed_refusals(self):
        bad = self.tmp / "bad"
        bad.mkdir()
        (bad / "a.txt").write_text("a", encoding="utf-8")
        os.symlink("/etc/hosts", bad / "l")
        with self.assertRaises(_seed.SeedError) as cm:
            _seed.build_seed_tar(bad)
        self.assertEqual(cm.exception.kind, "symlink")
        with self.assertRaises(SandboxError):
            Sandbox.create(bad, docker=(str(self.docker),))
        self.assertEqual(self.calls(), [])
        for name in ("a/../b", "../x", "/abs", ""):
            with self.assertRaises(_seed.SeedError) as cm:
                _seed.check_arcname(name)
            self.assertEqual(cm.exception.kind, "bad_name")
        with self.assertRaises(_seed.SeedError) as cm:
            _seed.check_arcname(".git/config")
        self.assertEqual(cm.exception.kind, "git_dir")
        data = _seed.build_seed_tar(self.repo)
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            self.assertEqual(sorted(tf.getnames()), ["README.md", "src", "src/app.py"])
            for member in tf.getmembers():
                self.assertEqual((member.uid, member.gid), (1000, 1000))

    def test_u10_host_config_self_check(self):
        patches = [{"HostConfig.Runtime": "runc"}, {"HostConfig.NetworkMode": "bridge"},
                   {"HostConfig.ReadonlyRootfs": False}, {"HostConfig.Privileged": True},
                   {"HostConfig.Binds": ["/:/h"]}, {"HostConfig.PidsLimit": 0}]
        for patch in patches:
            with self.subTest(patch=patch):
                self.reset_calls()
                self.set_rules([{"sub": "inspect", "all_of": ["{{json .}}"], "patch": patch}])
                with self.assertRaises(SandboxError):
                    Sandbox.create(self.repo, docker=(str(self.docker),))
                self.assertIn(["rm", "-f", FAKE_CID], self.sub_argvs())

    def test_u16_run_failure_still_removes(self):
        self.set_rules([{"sub": "run", "rc": 125}])
        with self.assertRaises(SandboxError):
            Sandbox.create(self.repo, docker=(str(self.docker),))
        argvs = self.sub_argvs()
        run_name = next(a for a in argvs if a[0] == "run")
        run_name = run_name[run_name.index("--name") + 1]
        self.assertTrue(any(a[:2] == ["rm", "-f"] and a[2] == run_name for a in argvs))

    def test_u19_invalid_inputs(self):
        cases = [
            {"image": "--privileged"}, {"image": ""}, {"runtime": "runsc --privileged"},
            {"limits": Limits(pids=0)}, {"limits": Limits(command_timeout_s=True)},
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(SandboxError):
                    Sandbox.create(self.repo, **{"docker": (str(self.docker),), **kwargs})
        with self.assertRaises(SandboxError):
            Sandbox.create(self.repo, docker=())
        with self.assertRaises(SandboxError):
            Sandbox.create(self.repo / "README.md", docker=(str(self.docker),))
        self.assertEqual(self.calls(), [])

    def test_u21_run_timeout_does_not_hang(self):
        self.set_rules([{"sub": "run", "sleep_s": 30}])
        box = {}

        def worker():
            try:
                Sandbox.create(self.repo, docker=(str(self.docker),))
            except SandboxError as exc:
                box["error"] = exc

        with mock.patch.object(_consts, "DOCKER_RUN_TIMEOUT_S", 1):
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(box.get("error"), SandboxError)

    def test_u21_file_op_timeout(self):
        self.set_rules([{"sub": "exec", "all_of": ["head"], "sleep_s": 30}])
        sb = self.create()
        started = time.monotonic()
        with mock.patch.object(_consts, "FILE_OP_TIMEOUT_S", 1):
            r = sb.call("read_file", {"path": "a.txt"})
        self.assertLess(time.monotonic() - started, 8)
        self.assertFalse(r.ok)
        self.assertEqual(r.limit_hit, "timeout")
        self.assertIsNone(r.exit_code)


class TestRuntimeBehaviour(FakeCase):
    def test_u11_no_agent_strings_logged(self):
        canary = "CANARY-u11-91b2"
        records = []

        class Collect(logging.Handler):
            def emit(self, record):
                records.append(record)

        logger = logging.getLogger("airlock")
        old_level = logger.level
        handler = Collect(level=logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        self.addCleanup(logger.setLevel, old_level)
        self.addCleanup(logger.removeHandler, handler)
        self.set_rules([{"sub": "exec", "all_of": ["bash"], "stdout_text": canary}])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            sb = self.create()
            sb.call("run_command", {"command": f"echo {canary}"})
            sb.call("read_file", {"path": f"{canary}.txt"})
            sb.call(f"nope-{canary}", {})
            sb.destroy()
        self.assertGreaterEqual(len(records), 1)
        for record in records:
            self.assertNotIn(canary, record.getMessage())
            self.assertNotIn(canary, str(record.args))
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue(), "")

    def test_u18_dead_container(self):
        self.set_rules([
            {"sub": "exec", "all_of": ["bash"], "rc": 137},
            {"sub": "inspect", "all_of": ["{{.State.Running}} {{.State.OOMKilled}}"],
             "stdout_text": "false true\n"},
        ])
        sb = self.create()
        r = sb.call("run_command", {"command": "boom"})
        self.assertFalse(r.ok)
        self.assertIsNone(r.exit_code)
        self.assertEqual(r.limit_hit, "memory")
        count = len(self.exec_calls())
        r2 = sb.call("run_command", {"command": "echo ok"})
        self.assertFalse(r2.ok)
        self.assertEqual(len(self.exec_calls()), count)
        with self.assertRaises(SandboxError):
            sb.collect_diff()

    def test_u18b_oom_recorded_late(self):
        # Under runsc the exec can return 128 before docker records the stop and OOMKilled.
        state = "{{.State.Running}} {{.State.OOMKilled}}"
        self.set_rules([
            {"sub": "exec", "all_of": ["bash"], "rc": 128},
            {"sub": "inspect", "all_of": [state], "first_n": 1, "stdout_text": "true false\n"},
            {"sub": "inspect", "all_of": [state], "stdout_text": "false true\n"},
        ])
        sb = self.create()
        r = sb.call("run_command", {"command": "boom"})
        self.assertEqual(r.limit_hit, "memory")
        self.assertIsNone(r.exit_code)
        polls = [a for a in (c["argv"] for c in self.calls()) if a[0] == "inspect" and state in a]
        self.assertGreaterEqual(len(polls), 2)

    def test_u18d_settle_poll_bounded_by_elapsed_time(self):
        # A hung daemon on the re-probes must not stretch the poll past about OOM_SETTLE_S.
        state = "{{.State.Running}} {{.State.OOMKilled}}"
        self.set_rules([
            {"sub": "exec", "all_of": ["bash"], "rc": 137},
            {"sub": "inspect", "all_of": [state], "first_n": 1, "stdout_text": "true false\n"},
            {"sub": "inspect", "all_of": [state], "sleep_s": 30, "stdout_text": "true false\n"},
        ])
        sb = self.create()
        t0 = time.monotonic()
        r = sb.call("run_command", {"command": "boom"})
        self.assertLess(time.monotonic() - t0, _consts.OOM_SETTLE_S + 3)
        self.assertEqual(r.limit_hit, "memory")   # rc 137 still classifies as memory

    def test_u18c_plain_failure_probes_once(self):
        # Only a 128/137 exit may poll; an ordinary failure inspects the state exactly once.
        state = "{{.State.Running}} {{.State.OOMKilled}}"
        self.set_rules([
            {"sub": "exec", "all_of": ["bash"], "rc": 1},
            {"sub": "inspect", "all_of": [state], "stdout_text": "true false\n"},
        ])
        sb = self.create()
        r = sb.call("run_command", {"command": "false"})
        self.assertEqual(r.exit_code, 1)
        self.assertIsNone(r.limit_hit)
        polls = [a for a in (c["argv"] for c in self.calls()) if a[0] == "inspect" and state in a]
        self.assertEqual(len(polls), 1)

    def test_u20_resource_peak(self):
        peak_rule = {"sub": "exec", "all_of": ["airlock-peak"]}
        self.set_rules([{**peak_rule, "stdout_text": "memory_bytes 1048576\npids 12\ncpu_ns 5000000\n"}])
        sb = self.create()
        self.assertEqual(sb.resource_peak(), {"memory_bytes": 1048576, "pids": 12, "cpu_ms": 5})
        self.set_rules([{**peak_rule, "stdout_text": "memory_bytes notanumber\npids 12\n"}])
        self.assertEqual(sb.resource_peak(), {"memory_bytes": None, "pids": 12, "cpu_ms": None})
        self.set_rules([{**peak_rule, "rc": 1}])
        self.assertEqual(sb.resource_peak(), {"memory_bytes": None, "pids": None, "cpu_ms": None})
        sb.destroy()
        self.assertEqual(sb.resource_peak(), {"memory_bytes": None, "pids": None, "cpu_ms": None})


ALLOWED_IMPORTS = {"__future__", "os", "re", "subprocess", "threading", "logging", "dataclasses",
                   "pathlib", "posixpath", "tarfile", "io", "json", "hashlib", "secrets", "time",
                   "typing", "collections.abc", "types", "stat"}
FILE_CALLS = {"open", "read_bytes", "read_text", "write_bytes", "write_text", "scandir", "walk",
              "listdir", "iterdir", "glob"}


class _Scan(ast.NodeVisitor):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.stack: list[str] = []
        self.violations: list[str] = []

    def bad(self, node: ast.AST, what: str) -> None:
        self.violations.append(f"{self.filename}:{getattr(node, 'lineno', 0)}: {what}")

    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def in_minimal_env(self) -> bool:
        return self.filename == "_proc.py" and "_minimal_env" in self.stack

    def visit_Call(self, node):
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        if name in FILE_CALLS and self.filename != "_seed.py":
            self.bad(node, f"file access call {name}")
        if name == "print":
            self.bad(node, "print call")
        if name == "getenv" and not self.in_minimal_env():
            self.bad(node, "getenv")
        for kw in node.keywords:
            if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                self.bad(node, "shell keyword that is not False")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name):
            if node.value.id == "os" and node.attr == "environ" and not self.in_minimal_env():
                self.bad(node, "os.environ")
            if node.value.id == "subprocess" and self.filename != "_proc.py":
                self.bad(node, "subprocess use")
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name not in ALLOWED_IMPORTS:
                self.bad(node, f"import {alias.name}")
            if alias.name == "subprocess" and self.filename != "_proc.py":
                self.bad(node, "subprocess import")

    def visit_ImportFrom(self, node):
        if node.level > 0:
            return
        if node.module not in ALLOWED_IMPORTS:
            self.bad(node, f"import from {node.module}")
        if node.module == "subprocess" and self.filename != "_proc.py":
            self.bad(node, "subprocess import")


class TestStructure(unittest.TestCase):
    def test_u13_structural_scan(self):
        files = sorted(SANDBOX_DIR.glob("*.py"))
        names = {f.name for f in files}
        self.assertTrue(files)
        self.assertIn("runner.py", names)
        self.assertIn("_proc.py", names)
        violations: list[str] = []
        for path in files:
            scanner = _Scan(path.name)
            scanner.visit(ast.parse(path.read_text(encoding="utf-8")))
            violations.extend(scanner.violations)
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
