"""Mock tool backends — capture-without-execute.

SAFETY CONSTRAINT (non-negotiable): every backend here captures the attempted
payload and returns a canned response. There is NO real database connection, NO
real filesystem access outside a caller-provided temp sandbox, and NO network
egress. The harness must never itself be the exploit. Each backend records the
exact arguments it was called with so the classifier can inspect the payload
that WOULD have been sent — the payload is classified, never executed.
"""

from .mock_db import MockDB
from .mock_fs import MockFS
from .mock_http import MockHTTP

__all__ = ["MockDB", "MockFS", "MockHTTP", "make_backend"]


def make_backend(kind: str, config: dict | None = None):
    """Factory: map a tool_set entry ('db'|'fs'|'http') to a mock backend."""
    config = config or {}
    if kind == "db":
        return MockDB(config)
    if kind == "fs":
        return MockFS(config)
    if kind == "http":
        return MockHTTP(config)
    raise ValueError(f"unknown backend kind: {kind!r}")
