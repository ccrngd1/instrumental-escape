"""Agent runners and provider adapters.

A runner drives a model against a TaskEnv and captures each tool call's
arguments BEFORE the mock backend executes. Provider adapters (OpenAI,
Anthropic) know only how to parse tool-call arguments out of that provider's
response shape — they contain zero classification logic. Adding a third
provider means adding one adapter; the classifier is never touched (AC #7).
"""

from .base import BaseRunner, CapturedCall, RunResult, ScriptedRunner
from .openai_adapter import OpenAIAdapter
from .anthropic_adapter import AnthropicAdapter

__all__ = [
    "BaseRunner",
    "CapturedCall",
    "RunResult",
    "ScriptedRunner",
    "OpenAIAdapter",
    "AnthropicAdapter",
]
