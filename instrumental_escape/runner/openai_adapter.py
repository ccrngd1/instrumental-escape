"""OpenAI tool-call argument capture.

Parses tool-call arguments out of an OpenAI-style chat completion response
(``choices[].message.tool_calls[].function.{name, arguments}``, where
``arguments`` is a JSON string). This adapter contains NO classification logic —
it only extracts ``{tool_name, arguments}`` pairs. Live dispatch uses litellm
(imported lazily so the deterministic core never depends on it).
"""

from __future__ import annotations

import json
from typing import Any

from .base import BaseRunner


def parse_tool_calls(response: Any) -> list[dict[str, Any]]:
    """Extract tool calls from an OpenAI-style response (object or dict).

    Returns a list of {tool_name, arguments} where arguments is a parsed dict
    (falling back to {"raw": <string>} if the JSON is malformed).
    """
    calls: list[dict[str, Any]] = []
    choices = _get(response, "choices", []) or []
    for choice in choices:
        message = _get(choice, "message", {}) or {}
        tool_calls = _get(message, "tool_calls", []) or []
        for tc in tool_calls:
            fn = _get(tc, "function", {}) or {}
            name = _get(fn, "name")
            raw_args = _get(fn, "arguments")
            calls.append({"tool_name": name, "arguments": _parse_args(raw_args)})
    return calls


def _parse_args(raw: Any) -> Any:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {"raw": raw}
    return {"raw": raw}


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Access ``key`` on a dict or an attribute-style SDK object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class OpenAIAdapter(BaseRunner):
    """Runner that dispatches to an OpenAI model via litellm and captures args.

    For tests and demo, pass ``responses`` (a list of recorded response objects)
    to replay without any network call.
    """

    provider = "openai"

    def __init__(self, responses: list[Any] | None = None, litellm_kwargs: dict | None = None):
        self.responses = responses or []
        self.litellm_kwargs = litellm_kwargs or {}
        self._cursor = 0

    def _dispatch(self, env, model: str) -> Any:
        """Live dispatch via litellm. Imported lazily; not needed for tests."""
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
