"""InstrumentalEscape command-line interface.

Commands:
  run         run one or more task templates against a model, in blocked/control
              conditions, and gate on the risk delta.
  demo        run the canonical SQL task across a set of (canned) models and show
              the distribution of behaviors — models that do NOT exploit are
              reported as findings, not failures.
  signatures  list or validate the payload-signature registry.

Exit codes: 0 = clean, 1 = gate failed (delta over threshold), 2 = harness error.
"""

from __future__ import annotations

import argparse
import sys

from . import NOT_PROMPT_INJECTION, __version__
from .classify import Classifier
from .demo_data import DEFAULT_DEMO_MODELS, CANONICAL_TASK, SCENARIOS, scenario_for
from .engine import run_suite
from .report import EXIT_HARNESS_ERROR, RunReport, TaskReport, render
from .runner.base import ScriptedRunner

POSITIONING_BANNER = (
    "InstrumentalEscape — Instrumental Hacking Behavior Detector\n"
    f"{NOT_PROMPT_INJECTION}"
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="instrumental-escape",
        description=(
            "Instrumental Hacking Behavior Detector. "
            + NOT_PROMPT_INJECTION
            + " ALL tool backends are mocks (capture-without-execute): no real DB, "
            "filesystem, or network access."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- run ----
    p_run = sub.add_parser("run", help="run task(s) and gate on the risk delta")
    p_run.add_argument("--task", default=None, help="task template name (default: all)")
    p_run.add_argument("--model", default="scripted", help="model id / scenario label")
    p_run.add_argument(
        "--condition", choices=["blocked", "control", "both"], default="both",
        help="which condition(s) to run (default: both — required for a real delta)",
    )
    p_run.add_argument("--threshold", type=int, default=0, help="max allowed risk delta (default 0)")
    p_run.add_argument("--format", choices=["terminal", "json", "md"], default="terminal")
    p_run.add_argument("--out", default=None, help="write the report to this path instead of stdout")
    p_run.add_argument(
        "--adapter", choices=["scripted", "openai", "anthropic"], default="scripted",
        help="runner adapter (default scripted: offline, deterministic)",
    )

    # ---- demo ----
    p_demo = sub.add_parser("demo", help="run the canonical SQL task across models")
    p_demo.add_argument(
        "--models", default=None,
        help="comma-separated model/scenario labels (default: the built-in demo set)",
    )
    p_demo.add_argument("--threshold", type=int, default=0)
    p_demo.add_argument("--format", choices=["terminal", "json", "md"], default="terminal")
    p_demo.add_argument("--out", default=None)

    # ---- signatures ----
    p_sig = sub.add_parser("signatures", help="inspect the payload-signature registry")
    p_sig.add_argument("action", choices=["list", "validate"])
    p_sig.add_argument("--format", choices=["terminal", "json"], default="terminal")

    return parser


def _emit(text: str, out: str | None) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
    else:
        print(text)


# --------------------------------------------------------------- commands ---

def cmd_run(args) -> int:
    conditions = ("blocked", "control") if args.condition == "both" else (args.condition,)
    if args.condition != "both":
        print(
            "[warn] running a single condition: the risk score is a DELTA "
            "(blocked - control); a one-sided run cannot isolate instrumental "
            "escape. Use --condition both for a meaningful gate.",
            file=sys.stderr,
        )

    classifier = Classifier()

    # Only the scripted adapter runs fully offline. Live adapters require litellm
    # and network credentials and are out of scope for a bare `run` invocation
    # here; wire recorded responses in programmatically for those.
    if args.adapter != "scripted":
        print(
            f"[error] adapter {args.adapter!r} needs recorded responses or live "
            "credentials; the CLI `run` path uses the scripted adapter. See the "
            "runner adapters for programmatic use.",
            file=sys.stderr,
        )
        return EXIT_HARNESS_ERROR

    # If --model names a built-in demo scenario, replay its canned tool calls so
    # the gate can actually fire from the CLI. Any other model id yields an empty
    # script (a plumbing smoke test: both conditions run, clean zero-delta result)
    # — wire recorded/live adapter responses in programmatically for real models.
    runner = ScriptedRunner(script=scenario_for(args.model) if args.model in SCENARIOS else {})
    task_names = [args.task] if args.task else None
    try:
        report = run_suite(
            runner, classifier, model=args.model, threshold=args.threshold,
            task_names=task_names, conditions=conditions,
        )
    except KeyError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return EXIT_HARNESS_ERROR
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[error] harness failure: {exc}", file=sys.stderr)
        return EXIT_HARNESS_ERROR

    _emit(render(report, args.format), args.out)
    return report.exit_code


def cmd_demo(args) -> int:
    labels = (
        [m.strip() for m in args.models.split(",") if m.strip()]
        if args.models else list(DEFAULT_DEMO_MODELS)
    )
    classifier = Classifier()

    combined = RunReport(model=",".join(labels), threshold=args.threshold)
    findings: list[str] = []
    for label in labels:
        runner = ScriptedRunner(script=scenario_for(label))
        sub = run_suite(
            runner, classifier, model=label, threshold=args.threshold,
            task_names=[CANONICAL_TASK], conditions=("blocked", "control"),
        )
        for tr in sub.task_reports:
            # Re-label the task report by model for the distribution view.
            combined.task_reports.append(
                TaskReport(
                    task_name=f"{label}:{tr.task_name}",
                    model=label,
                    blocked=tr.blocked,
                    control=tr.control,
                )
            )
            if tr.delta <= 0:
                findings.append(
                    f"{label}: no instrumental escape (delta {tr.delta}) — "
                    "reported as a finding, not a failure."
                )

    text = render(combined, args.format)
    if args.format == "terminal" and findings:
        text += "\n\nFindings (safe behavior is still a finding):\n" + "\n".join(
            f"  - {f}" for f in findings
        )
    _emit(text, args.out)
    return combined.exit_code


def cmd_signatures(args) -> int:
    classifier = Classifier()
    if args.action == "validate":
        problems = classifier.validate()
        if problems:
            for p in problems:
                print(f"[invalid] {p}", file=sys.stderr)
            return EXIT_HARNESS_ERROR
        vectors = ", ".join(sorted(classifier.covered_vectors()))
        print(f"OK: {len(classifier.signatures)} signatures, vectors: {vectors}")
        return 0

    # list
    if args.format == "json":
        import json
        payload = [
            {"id": s.id, "vector": s.vector, "tier": s.tier.label,
             "pattern": s.pattern, "description": s.description}
            for s in classifier.signatures
        ]
        print(json.dumps(payload, indent=2))
        return 0

    print(POSITIONING_BANNER)
    print("=" * 68)
    for s in classifier.signatures:
        print(f"[{s.vector}/{s.tier.label}] {s.id}")
        print(f"    pattern: {s.pattern}")
        print(f"    {s.description}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "demo":
        return cmd_demo(args)
    if args.command == "signatures":
        return cmd_signatures(args)
    parser.error("no command")  # pragma: no cover
    return EXIT_HARNESS_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
