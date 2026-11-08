"""Service wiring: startup sequence S1..S11 (fail closed) and shutdown."""
from __future__ import annotations

import functools
import logging
import sqlite3
import threading
from collections.abc import Callable

from airlock.agent import TaskOutcome
from airlock.agent import run_task as _run_task
from airlock.sandbox import Sandbox
from airlock.service import docker_ops
from airlock.service.accounting import Accounting
from airlock.service.clock import Clock, SystemClock
from airlock.service.config import ConfigError, ServiceConfig, make_key_provider
from airlock.service.execution import TaskExecutor
from airlock.service.httpapi import ApiServer, AppContext
from airlock.service.manifest import ManifestError, load_manifest
from airlock.service.ratelimit import RateLimiter
from airlock.service.scheduler import Scheduler, WorkerPool, purge_now, recover_interrupted
from airlock.service.store import BUSY_MS_WORKER, Busy, Store, StoreError

_log = logging.getLogger("airlock.service")

STARTUP_CHECKS: tuple[str, ...] = ("config", "manifest", "key", "sqlite_version", "db_open", "wal",
                                   "schema_version", "integrity", "docker_runtime", "docker_image",
                                   "leftover_list", "listen_address")


class StartupError(Exception):
    """str() is a fixed check name from STARTUP_CHECKS."""


class Service:
    def __init__(self, cfg: ServiceConfig, *,
                 run_task_fn: Callable[..., TaskOutcome] = _run_task,
                 clock: Clock | None = None, start_workers: bool = True,
                 sandbox_factory: Callable[..., object] | None = None) -> None:
        self.cfg = cfg
        self._run_task_fn = run_task_fn
        self.clock: Clock = clock or SystemClock()
        self._start_workers = start_workers
        self._sandbox_factory = sandbox_factory or functools.partial(Sandbox.create,
                                                                     docker=cfg.docker_cmd)
        self._stop_event = threading.Event()
        self._api: ApiServer | None = None
        self._pool: WorkerPool | None = None
        self._scheduler: Scheduler | None = None
        self._address: tuple[str, int] | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._address is None:
            raise StartupError("listen_address")
        return self._address

    def start(self) -> None:
        try:
            self._start()
        except BaseException:
            self.stop(1.0)
            raise

    def _start(self) -> None:
        cfg = self.cfg
        try:  # S2
            manifest = load_manifest(cfg.manifest_path)
        except (ManifestError, OSError):
            raise StartupError("manifest") from None
        try:  # S3
            key_provider = make_key_provider(cfg.inference)
        except (ConfigError, OSError):
            raise StartupError("key") from None
        store = Store(cfg.db_path)
        try:  # S4
            store.initialize()
        except StoreError as exc:
            name = str(exc)
            raise StartupError(name if name in STARTUP_CHECKS else "db_open") from None
        except OSError:
            raise StartupError("db_open") from None
        try:  # S5, S6
            docker_ops.check_runtime(cfg.docker_cmd, cfg.agent.runtime)
            docker_ops.check_image(cfg.docker_cmd, cfg.agent.image)
            if cfg.remove_leftover_containers:  # S7
                removed, failed = docker_ops.remove_leftovers(cfg.docker_cmd)
                _log.info("leftover containers removed=%d failed=%d", removed, failed)
        except docker_ops.DockerCheckError as exc:
            name = str(exc)
            raise StartupError(name if name in STARTUP_CHECKS else "docker_runtime") from None
        accounting = Accounting(cfg, self.clock)
        conn = store.connect(busy_timeout_ms=BUSY_MS_WORKER)
        try:
            interrupted = recover_interrupted(store, conn, self.clock)  # S8
            with store.write_tx(conn):  # S9
                accounting.rollover_in_tx(conn)
            counts = purge_now(store, conn, cfg, self.clock)  # S10
            _log.info("startup interrupted=%d purged_tasks=%d purged_sessions=%d",
                      interrupted, counts.tasks, counts.sessions)
        except (Busy, sqlite3.Error):
            raise StartupError("db_open") from None
        finally:
            conn.close()
        executor = TaskExecutor(store, accounting, cfg, manifest, key_provider, self.clock,
                                self._run_task_fn, self._sandbox_factory)
        pool = WorkerPool(store, executor, cfg.quotas.max_running, self.clock, self._stop_event)
        self._pool = pool
        ctx = AppContext(cfg=cfg, store=store, accounting=accounting, manifest=manifest,
                         limiter=RateLimiter(), clock=self.clock, wake=pool.wake)
        api = ApiServer(ctx)
        try:  # S11
            self._address = api.start()
        except OSError:
            raise StartupError("listen_address") from None
        self._api = api
        scheduler = Scheduler(store, accounting, cfg, self.clock, pool, self._stop_event)
        scheduler.daemon = True
        self._scheduler = scheduler
        scheduler.start()
        if self._start_workers:
            pool.start()
        _log.info("service started")

    def stop(self, timeout_s: float = 5.0) -> None:
        self._stop_event.set()
        if self._api is not None:
            self._api.shutdown()
            self._api = None
        if self._pool is not None:
            self._pool.wake()
            self._pool.join(timeout_s)
        if self._scheduler is not None and self._scheduler.is_alive():
            self._scheduler.join(timeout_s)
