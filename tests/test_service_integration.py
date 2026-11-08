"""Integration tests I1..I3: real Docker with runsc, real M2, loopback fake OpenAI-compatible provider.

Skipped (not failed) when `docker info` does not list a runsc runtime. Build the image first:
    docker build -t airlock-sandbox:dev sandbox-image
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = pathlib.Path(__file__).resolve().parent
for _p in (str(ROOT), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agent_fakes import FakeProvider, Reply, chat_ok, text_block  # noqa: E402
from service_fakes import (API, KEY, LogCapture, api, db_bytes, env_with_key, jget, jpost,  # noqa: E402
                           make_env, open_session, wait_task_done)
from airlock.sandbox._proc import _minimal_env  # noqa: E402
from airlock.service.app import Service  # noqa: E402
from airlock.service.config import load_config  # noqa: E402

IMAGE = "airlock-sandbox:dev"
BUILD_HINT = "build the image first: docker build -t airlock-sandbox:dev sandbox-image"
_IMAGE_OK = False

BUGGY = "def add(a, b):\n    return a - b\n"
FIXED = "def add(a, b):\n    return a + b\n"
TEST_SRC = ("import unittest\nfrom calc import add\n\n\nclass T(unittest.TestCase):\n"
            "    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n\n\n"
            "if __name__ == '__main__':\n    unittest.main()\n")
SAMPLES = [("calc", {"calc.py": BUGGY, "test_calc.py": TEST_SRC},
            [("fix-bug", "Run the tests and fix calc.py."),
             ("try-memory", 'Run this exact command once: python3 -c "b=bytearray(900*1024*1024)"')])]


def _docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], env=_minimal_env(), capture_output=True,
                          timeout=timeout, check=False)


def setUpModule() -> None:
    global _IMAGE_OK
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


def _reply(tool: str, args: dict) -> Reply:
    return Reply(200, chat_ok(content=text_block(tool, args)))


class ServiceIntegration(unittest.TestCase):
    def setUp(self) -> None:
        if not _IMAGE_OK:
            self.fail(BUILD_HINT)
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="airlock-svc-it-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = env_with_key()
        patcher.start()
        self.addCleanup(patcher.stop)
        self.logs = LogCapture()
        self.logs.__enter__()
        self.addCleanup(self.logs.__exit__, None, None, None)

    def start(self, script) -> tuple[int, str, FakeProvider]:
        provider = FakeProvider(script)
        self.addCleanup(provider.close)
        cfg_path, _, _ = make_env(self.tmp, real_docker=True, samples=SAMPLES, base_url=provider.base_url,
                                  patch={"agent": {"wall_clock_s": 240}})
        self.cfg = load_config(cfg_path)
        svc = Service(self.cfg)
        svc.start()
        self.addCleanup(svc.stop)
        port = svc.address[1]
        return port, open_session(port), provider

    def test_I1_fix_flow_end_to_end(self):
        port, cookie, provider = self.start([
            _reply("write_file", {"path": "calc.py", "content": FIXED}),
            _reply("run_command", {"command": "python3 -m unittest -q"}),
            _reply("finish", {"summary": "fixed add"})])
        status, body, _ = jpost(port, "/tasks", {"sample_id": "calc", "preset_id": "fix-bug"}, cookie)
        self.assertEqual(status, 202, body)
        task = wait_task_done(port, cookie, body["task"]["id"], timeout=300)
        self.assertEqual(task["end_reason"], "agent_finished")
        self.assertTrue(task["report"]["contained"])
        self.assertTrue(task["report"]["destroy_proof"]["verified"])
        tid = task["id"]
        self.assertEqual(jget(port, f"/tasks/{tid}/diff", cookie)[0], 200)
        self.assertEqual(jpost(port, f"/tasks/{tid}/review", {"decision": "approve"}, cookie)[0], 200)
        status, _, patch = api(port, "GET", API + f"/tasks/{tid}/patch", cookie=cookie)
        self.assertEqual(status, 200)
        copy = self.tmp / "fresh"
        shutil.copytree(self.tmp / "samples" / "calc", copy)
        patch_file = self.tmp / "out.patch"
        patch_file.write_bytes(patch)
        proc = subprocess.run(["git", "apply", "--check", str(patch_file)], cwd=copy,
                              capture_output=True, timeout=60, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_I2_memory_bomb_is_contained(self):
        port, cookie, _ = self.start([
            _reply("run_command", {"command": 'python3 -c "b=bytearray(900*1024*1024)"'}),
            _reply("list_dir", {"path": "."}),
            _reply("finish", {"summary": "unreachable"})])
        status, body, _ = jpost(port, "/tasks", {"sample_id": "calc", "preset_id": "try-memory"}, cookie)
        self.assertEqual(status, 202, body)
        task = wait_task_done(port, cookie, body["task"]["id"], timeout=300)
        self.assertEqual((task["status"], task["end_reason"]), ("finished", "sandbox_error"))
        report = task["report"]
        self.assertTrue(report["contained"])
        self.assertEqual(report["sandbox"], "destroyed")
        self.assertIn("sandbox_killed", [h["limit"] for h in report["limit_hits"]])
        self.assertEqual(task["review_state"], "none")
        self.assertEqual(api(port, "GET", API + f"/tasks/{task['id']}/diff", cookie=cookie)[0], 404)

    def test_I3_key_canary_through_real_client(self):
        port, cookie, provider = self.start([_reply("finish", {"summary": "ok"})])
        status, body, _ = jpost(port, "/tasks", {"sample_id": "calc", "preset_id": "fix-bug"}, cookie)
        self.assertEqual(status, 202, body)
        wait_task_done(port, cookie, body["task"]["id"], timeout=300)
        self.assertTrue(provider.headers)
        self.assertIn(KEY, provider.headers[0].get("authorization", ""))
        self.assertNotIn(KEY.encode(), db_bytes(self.cfg.data_dir))
        self.assertNotIn(KEY, self.logs.text)


if __name__ == "__main__":
    unittest.main()
