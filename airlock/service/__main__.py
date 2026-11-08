"""python3 -m airlock.service --config <path>"""
from __future__ import annotations

import argparse
import logging
import pathlib
import signal
import sys
import threading

from airlock.service.app import Service, StartupError
from airlock.service.config import ConfigError, load_config

_log = logging.getLogger("airlock.service")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m airlock.service")
    parser.add_argument("--config", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        _log.error("startup check failed: config (%s)", exc)
        return 2
    service = Service(cfg)
    try:
        service.start()
    except StartupError as exc:
        _log.error("startup check failed: %s", exc)
        return 2
    done = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: done.set())
    host, port = service.address
    _log.info("listening on %s:%d", host, port)
    done.wait()
    service.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
