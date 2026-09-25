"""Anthropic tool-use argument capture.

Parses tool-use blocks out of an Anthropic-style message response
(``content[]`` blocks where ``type == "tool_use"`` carry ``name`` and ``input``,
``input`` already a dict). This adapter contains NO classification logic — it
only extracts ``{tool_name, arguments}`` pairs. Live dispatch uses litellm
(imported lazily so the deterministic core never depends on it).
"""

from __future__ import annotations

from typing import Any

from .base import BaseRunner


def parse_tool_calls(response: Any) -> list[dict[str, Any]]:
    """Extract tool-use blocks from an Anthropic-style response (object or dict).

    Returns a list of {tool_name, arguments} where arguments is the tool ``input``
    dict.
    """
    calls: list[dict[str, Any]] = []
    content = _get(response, "content", []) or []
    for block in content:
        btype = _get(block, "type")
        if btype == "tool_use":
            name = _get(block, "name")
            args = _get(block, "input", {}) or {}
            if not isinstance(args, dict):
                args = {"raw": args}
            calls.append({"tool_name": name, "arguments": args})
    return calls


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class AnthropicAdapter(BaseRunner):
    """Runner that dispatches to an Anthropic model via litellm and captures args.

    For tests and demo, pass ``responses`` (a list of recorded response objects)
    to replay without any network call.
    """

    provider = "anthropic"

    def __init__(self, responses: list[Any] | None = None, litellm_kwargs: dict | None = None):
        self.responses = responses or []
        self.litellm_kwargs = litellm_kwargs or {}
        self._cursor = 0

    def _dispatch(self, env, model: str) -> Any:
        import litellm  # noqa: F401  (optional dependency)

        messages = [{"role": "user", "content": env.prompt}]
        return litellm.completion(model=model, messages=messages, **self.litellm_kwargs)

    def iter_tool_calls(self, env, model: str):
        if self.responses:
            response = self.responses[min(self._cursor, len(self.responses) - 1)]
            self._cursor += 1
        else:
            response = self._dispatch(env, model)
        for call in parse_tool_calls(response):
            yield call
