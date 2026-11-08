"""Integration tests: real Docker with the runsc runtime and a scripted fake client (no LLM).

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

from agent_fakes import FakeClient, RecBudget, RecSink, text_reply  # noqa: E402
from airlock.agent import AgentConfig, run_task  # noqa: E402
from airlock.sandbox import Limits, Sandbox  # noqa: E402
from airlock.sandbox._proc import _minimal_env  # noqa: E402

IMAGE = "airlock-sandbox:dev"
BUILD_HINT = "build the image first: docker build -t airlock-sandbox:dev sandbox-image"

_IMAGE_OK = False
_REPO: pathlib.Path | None = None

BUGGY = "def add(a, b):\n    return a - b\n"
FIXED = "def add(a, b):\n    return a + b\n"
TEST_SRC = ("import unittest\nfrom calc import add\n\n\nclass T(unittest.TestCase):\n"
            "    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n\n\n"
            "if __name__ == '__main__':\n    unittest.main()\n")


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
    _REPO = pathlib.Path(tempfile.mkdtemp(prefix="airlock-agent-it-repo-"))
    (_REPO / "calc.py").write_text(BUGGY, encoding="utf-8")
    (_REPO / "test_calc.py").write_text(TEST_SRC, encoding="utf-8")


def tearDownModule() -> None:
    if _REPO is not None:
        shutil.rmtree(_REPO, ignore_errors=True)


class AgentIntegrationCase(unittest.TestCase):
    def setUp(self) -> None:
        if not _IMAGE_OK:
            self.fail(BUILD_HINT)

    def run_script(self, script, *, limits: Limits | None = None):
        assert _REPO is not None
        sink = RecSink()
        cfg = AgentConfig(limits=limits or Limits(), wall_clock_s=240.0)
        outcome = run_task("fix the bug in calc.py", _REPO, client=FakeClient(script),
                           config=cfg, sink=sink, budget=RecBudget(), sandbox_factory=Sandbox.create)
        return outcome, sink.events

    @staticmethod
    def results(events, tool: str) -> list[dict]:
        return [e for e in events if e["type"] == "tool_result" and e["tool"] == tool]


class TestAgentIntegration(AgentIntegrationCase):
    def test_AI1_fix_flow(self):
        script = [text_reply("write_file", {"path": "calc.py", "content": FIXED}),
                  text_reply("run_command", {"command": "python3 -m unittest -q"}),
                  text_reply("finish", {"summary": "fixed add"})]
        outcome, events = self.run_script(script)
        self.assertEqual(outcome.reason, "agent_finished")
        self.assertEqual(self.results(events, "run_command")[0]["exit_code"], 0)
        self.assertEqual(outcome.diff.state, "ok")
        self.assertIn("calc.py", [f["path"] for f in outcome.diff.files])
        self.assertTrue(outcome.destroy_proof.verified)

    def test_AI2_egress_attempt_does_not_end_task(self):
        script = [text_reply("run_command", {"command": "wget -q -T 5 -O- http://1.1.1.1/"}),
                  text_reply("finish", {"summary": "no network"})]
        outcome, events = self.run_script(script)
        exit_code = self.results(events, "run_command")[0]["exit_code"]
        self.assertNotIn(exit_code, (0, None))
        self.assertEqual(outcome.reason, "agent_finished")
        self.assertTrue(outcome.destroy_proof.verified)

    def test_AI3_resource_bomb_reports_limit(self):
        script = [text_reply("run_command", {"command": "while :; do :; done"}),
                  text_reply("finish", {"summary": "gave up"})]
        outcome, events = self.run_script(script, limits=Limits(command_timeout_s=3))
        self.assertEqual(self.results(events, "run_command")[0]["limit_hit"], "timeout")
        self.assertEqual(outcome.reason, "agent_finished")
        self.assertTrue(outcome.destroy_proof.verified)

    def test_AI4_memory_bomb_ends_with_sandbox_error(self):
        # Under runsc the memory cgroup kill stops the whole container, so the next action
        # finds the sandbox gone: the task ends sandbox_error with no diff, and is destroyed.
        script = [text_reply("run_command", {"command": 'python3 -c "b=bytearray(900*1024*1024)"'}),
                  text_reply("list_dir", {"path": "."}),
                  text_reply("finish", {"summary": "unreachable"})]
        outcome, events = self.run_script(script)
        self.assertEqual(self.results(events, "run_command")[0]["limit_hit"], "memory")
        self.assertEqual(outcome.reason, "sandbox_error")
        self.assertIsNone(outcome.diff)
        self.assertTrue(outcome.destroy_proof.verified)

if __name__ == "__main__":
    unittest.main()
