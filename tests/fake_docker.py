"""Fake docker CLI used by the unit tests.

Tests copy this file to ``<tmp>/docker`` with a ``#!<python>`` line in front and run it as the
docker binary. It reads ``script.json`` next to itself (an ordered list of rules) and appends
one JSON line per invocation to ``calls.jsonl`` next to itself.

Rule fields: {"sub": "run|exec|rm|inspect", "all_of": [argv elements that must all be present
verbatim], "rc": int, "stdout_text" | "stdout_b64" | "stdout_repeat": [char, n],
"stderr_text": str, "sleep_s": float, "patch": {"HostConfig.Runtime": "runc"},
"first_n": int (the rule matches only the first n calls that fit its sub and all_of)}.
"patch" (inspect only) starts from the default inspect document and overrides dotted keys.
"""
import base64
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_CID = "ab12" * 16


def _values(argv, flag):
    return [argv[i + 1] for i, token in enumerate(argv[:-1]) if token == flag]


def derive_inspect(run_argv):
    """Build an inspect document that mirrors the flags of a recorded `run` argv."""
    tmpfs = {}
    for spec in _values(run_argv, "--tmpfs"):
        path, _, opts = spec.partition(":")
        tmpfs[path] = opts
    runtime = ""
    for token in run_argv:
        if token.startswith("--runtime="):
            runtime = token.split("=", 1)[1]
    binds = _values(run_argv, "-v") + _values(run_argv, "--volume")
    memory = int(_values(run_argv, "--memory")[0])
    return {
        "Id": FAKE_CID,
        "State": {"Running": True, "OOMKilled": False},
        "Config": {"User": (_values(run_argv, "--user") or [""])[0]},
        "HostConfig": {
            "Runtime": runtime,
            "NetworkMode": (_values(run_argv, "--network") or [""])[0],
            "ReadonlyRootfs": "--read-only" in run_argv,
            "Privileged": "--privileged" in run_argv,
            "CapDrop": _values(run_argv, "--cap-drop"),
            "CapAdd": None,
            "Memory": memory,
            "MemorySwap": int(_values(run_argv, "--memory-swap")[0]),
            "PidsLimit": int(_values(run_argv, "--pids-limit")[0]),
            "NanoCpus": round(float(_values(run_argv, "--cpus")[0]) * 1e9),
            "IpcMode": (_values(run_argv, "--ipc") or [""])[0],
            "Init": "--init" in run_argv,
            "SecurityOpt": _values(run_argv, "--security-opt"),
            "Binds": binds or None,
            "Mounts": None,
            "PortBindings": {},
            "Tmpfs": tmpfs,
        },
        "Mounts": [{"Type": "tmpfs", "Destination": path} for path in tmpfs],
    }


def _apply_patch(doc, patch):
    for dotted, value in patch.items():
        keys = dotted.split(".")
        node = doc
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
    return doc


def _read_calls():
    path = os.path.join(HERE, "calls.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _load_rules():
    path = os.path.join(HERE, "script.json")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _emit(rc, out=b"", err=b""):
    sys.stdout.buffer.write(out)
    sys.stdout.buffer.flush()
    if err:
        sys.stderr.buffer.write(err)
        sys.stderr.buffer.flush()
    return rc


def main(argv):
    sub = argv[0] if argv else ""
    stdin_data = b""
    cmd = []
    if sub == "exec":
        index = argv.index("-w")
        cmd = argv[index + 3:]
        if "-i" in argv[1:index]:
            stdin_data = sys.stdin.buffer.read()
    previous = _read_calls()
    record = {
        "argv": argv,
        "env": dict(os.environ),
        "stdin_len": len(stdin_data),
        "stdin_sha256": hashlib.sha256(stdin_data).hexdigest(),
    }
    with open(os.path.join(HERE, "calls.jsonl"), "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")

    run_calls = [c["argv"] for c in previous if c["argv"] and c["argv"][0] == "run"]
    for rule in _load_rules():
        if rule.get("sub") != sub:
            continue
        if not all(token in argv for token in rule.get("all_of", [])):
            continue
        if "first_n" in rule:
            prior = sum(1 for c in previous if c["argv"] and c["argv"][0] == sub
                        and all(token in c["argv"] for token in rule.get("all_of", [])))
            if prior >= rule["first_n"]:
                continue
        if rule.get("sleep_s"):
            time.sleep(rule["sleep_s"])
        out = b""
        if "patch" in rule:
            doc = _apply_patch(derive_inspect(run_calls[-1]), rule["patch"])
            out = json.dumps(doc).encode()
        elif "stdout_text" in rule:
            out = rule["stdout_text"].encode()
        elif "stdout_b64" in rule:
            out = base64.b64decode(rule["stdout_b64"])
        elif "stdout_repeat" in rule:
            char, count = rule["stdout_repeat"]
            out = char.encode() * count
        return _emit(rule.get("rc", 0), out, rule.get("stderr_text", "").encode())

    if sub == "run":
        return _emit(0, (FAKE_CID + "\n").encode())
    if sub == "rm":
        return _emit(0)
    if sub == "inspect":
        fmt = argv[argv.index("--format") + 1]
        if fmt == "{{json .}}":
            return _emit(0, json.dumps(derive_inspect(run_calls[-1])).encode())
        if fmt == "{{.Id}}":
            removed = any(c["argv"] and c["argv"][0] == "rm" for c in previous)
            if removed:
                return _emit(1, b"", ("Error: No such object: %s\n" % argv[-1]).encode())
            return _emit(0, (FAKE_CID + "\n").encode())
        return _emit(0, b"true false\n")
    if sub == "exec":
        if cmd and cmd[0] == "pgrep":
            return _emit(0, b"7\n")
        if "rev-parse" in cmd:
            return _emit(0, b"0" * 40 + b"\n")
        return _emit(0)
    return _emit(0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
