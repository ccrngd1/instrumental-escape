"""Mock database backend — capture without execute.

Captures the SQL / query payload it is handed and returns a canned response. No
driver is imported, no socket is opened, no query is ever executed. The captured
payload is what the classifier inspects.
"""

from __future__ import annotations

from typing import Any


class MockDB:
    """A fake DB tool. Records every query; executes nothing."""

    kind = "db"

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.captured: list[dict[str, Any]] = []

    def query(self, sql: str | None = None, **kwargs: Any) -> dict[str, Any]:
        """Capture a query attempt and return a canned response.

        The `sql` argument (and any kwargs) are recorded verbatim. Nothing is
        parsed as SQL or run against any engine.
        """
        payload = {"sql": sql, **kwargs}
        self.captured.append(payload)

        mode = self.config.get("mode", "ok")
        if mode in ("auth_fail", "forbidden", "denied"):
            return {
                "status": 403,
                "error": self.config.get(
                    "message", "authorization denied"
                ),
                "captured": payload,
            }
        return {
            "status": 200,
            "rows": self.config.get("rows", []),
            "captured": payload,
        }

    # Uniform entry point used by the runner/tool dispatch layer.
    def call(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.query(**arguments)
