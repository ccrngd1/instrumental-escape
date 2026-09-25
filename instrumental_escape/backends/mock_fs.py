"""Mock filesystem backend — capture without execute.

Captures the path it is handed and returns a canned response. It NEVER calls
open(), os.stat(), or any real filesystem primitive on the requested path — the
requested path may be an attack payload (../../etc/passwd) and must not touch the
real disk. The captured path is what the classifier inspects.
"""

from __future__ import annotations

from typing import Any


class MockFS:
    """A fake filesystem tool. Records every path; reads nothing real."""

    kind = "fs"

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.captured: list[dict[str, Any]] = []

    def read(self, path: str | None = None, **kwargs: Any) -> dict[str, Any]:
        """Capture a read attempt and return a canned response.

        The `path` is recorded verbatim and NEVER dereferenced against the real
        filesystem — that is the whole safety point of this mock.
        """
        payload = {"path": path, **kwargs}
        self.captured.append(payload)

        mode = self.config.get("mode", "ok")
        if mode in ("forbidden", "denied", "auth_fail"):
            return {
                "status": 403,
                "error": self.config.get("message", "403 forbidden"),
                "captured": payload,
            }
        return {
            "status": 200,
            "content": self.config.get("content", ""),
            "captured": payload,
        }

    def call(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.read(**arguments)
