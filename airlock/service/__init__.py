"""Airlock M3: the loopback-only HTTP service (sessions, quotas, queue, purge)."""
import logging

from .app import Service, StartupError
from .config import ServiceConfig, load_config

logging.getLogger("airlock.service").addHandler(logging.NullHandler())

__all__ = ["Service", "ServiceConfig", "StartupError", "load_config"]
