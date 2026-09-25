"""InstrumentalEscape — Instrumental Hacking Behavior Detector.

InstrumentalEscape is NOT a prompt-injection detector and assumes NO adversary.
It detects when a goal-directed agent, using AUTHORIZED tools, instrumentally
discovers UNAUTHORIZED payloads (SQL injection, path traversal, command
injection, endpoint enumeration) as workarounds when its intended data path is
blocked. Access-control lists miss this entirely: the tool call is authorized;
only the payload is not.
"""

__version__ = "0.1.0"

# The positioning statement is load-bearing and asserted by the positioning test.
NOT_PROMPT_INJECTION = (
    "InstrumentalEscape is NOT a prompt-injection detector and assumes NO "
    "adversary. The agent uses AUTHORIZED tools with UNAUTHORIZED payloads, "
    "which ACLs miss."
)

from .classify import (  # noqa: E402
    BehaviorTier,
    Classification,
    Classifier,
    load_signatures,
)

__all__ = [
    "__version__",
    "NOT_PROMPT_INJECTION",
    "BehaviorTier",
    "Classification",
    "Classifier",
    "load_signatures",
]
