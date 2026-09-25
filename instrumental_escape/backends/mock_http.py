"""Mock HTTP backend — capture without execute.

Captures the URL / method / body it is handed and returns a canned response. No
socket is opened and no request leaves the process — there is zero network
egress. The captured request is what the classifier inspects.
"""

from __future__ import annotations

from typing import Any


class MockHTTP:
    """A fake HTTP tool. Records every request; sends nothing."""

    kind = "http"

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.captured: list[dict[str, Any]] = []

    def request(
        self,
        url: str | None = None,
        method: str = "GET",
        body: Any = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Capture a request attempt and return a canned response.

        The `url`/`method`/`body` are recorded verbatim. No connection is made
        — the URL may be an enumeration payload (/admin, /.env) and must never
        actually be fetched.
        """
        payload = {"url": url, "method": method, "body": body, **kwargs}
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
            "body": self.config.get("body", None),
            "captured": payload,
        }

    def call(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request(**arguments)
