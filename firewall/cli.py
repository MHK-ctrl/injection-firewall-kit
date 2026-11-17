"""Command line interface: ``ifk scan``, ``ifk sanitize``, ``ifk bench``.

Exit codes for ``scan``: 0 when the action is below ``--fail-on``, 2 when it is at or
above it, 3 when the file could not be read. That makes the command usable directly in
a pre-commit hook or a pipeline that screens inbound documents.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .policy import PRESETS, PolicyError, decide, load_policy
from .sanitizers import PROFILES, apply_sanitizers
from .scanner import Scanner
from .types import action_rank

__version__ = "0.1.0"


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _cmd_scan(args: argparse.Namespace) -> int:
    text = _read(args.file)
    policy = load_policy(args.policy)
    scanner = Scanner()
    result = scanner.scan(text, args.carrier or "unknown", policy=policy)
    decision = decide(result, policy)

    if args.json:
        payload = {"file": args.file, "scan": result.as_dict(), "decision": decision.as_dict()}
        print(json.dumps(payload, indent=2))
    else:
        print(f"file:    {args.file}")
        print(f"carrier: {result.carrier}")
        if args.verbose:
            print(result.explain(limit=args.limit))
        else:
            print(f"score:   {result.risk_score}/100")
            for finding in result.top_findings(args.limit):
                span = f" [{finding.span[0]}:{finding.span[1]}]" if finding.span else ""
                print(f"  {finding.severity:<8} {finding.category:<28}{span} {finding.reason}")
        print(f"policy:  {decision.policy_name}")
        for reason in decision.reasons:
            print(f"  - {reason}")
        print(f"action:  {decision.action.upper()}")
        if decision.action == "sanitize":
            print(f"next:    ifk sanitize {args.file} --profile {args.profile}")

    return 2 if action_rank(decision.action) >= action_rank(args.fail_on) else 0


def _cmd_sanitize(args: argparse.Namespace) -> int:
    text = _read(args.file)
    report = apply_sanitizers(text, args.profile)
    if args.out:
        Path(args.out).write_text(report.sanitized, encoding="utf-8")

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
        return 0

    print(f"profile: {report.profile}")
    print(f"changes: {report.describe()}")
    for change in report.changes:
        print(f"  - {change.kind}: {change.reason}")
    if args.show:
        print("\n--- sanitized ---")
        print(report.sanitized)
    if args.diff:
        print("\n--- diff ---")
        print(report.diff(Path(args.file).name))
    if args.out:
        print(f"\nwrote {args.out}")
    return 0


def _cmd_bench(args: argparse.Namespace) -> int:
    from harness.run_benchmark import run_benchmark  # imported late: keeps CLI startup fast

    results = run_benchmark(threshold=args.threshold, policy=args.policy)
    overall = results["overall"]
    print(f"samples:    {results['totals']['samples']}")
    print(f"attacks:    {results['totals']['attacks']}")
    print(f"benign:     {results['totals']['benign']}")
    print(f"threshold:  {results['threshold']}")
    print(
        "precision:  {:.3f}  recall: {:.3f}  f1: {:.3f}  false-positive rate: {:.3f}".format(
            overall["precision"], overall["recall"], overall["f1"], overall["false_positive_rate"]
        )
    )
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"json:       {args.json}")
    if args.markdown:
        from harness.report import render_markdown

        Path(args.markdown).write_text(render_markdown(results), encoding="utf-8")
        print(f"markdown:   {args.markdown}")
    return 0


def _cmd_policy(args: argparse.Namespace) -> int:
    policy = load_policy(args.name)
    print(json.dumps(policy, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ifk",
        description="Scan, sanitize and benchmark against prompt injection.",
    )
    parser.add_argument("--version", action="version", version=f"ifk {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file for injection attempts")
    scan.add_argument("file")
    scan.add_argument("--carrier", default="", help="carrier label, e.g. email_body")
    scan.add_argument("--policy", default="balanced", help="preset name or path to a YAML policy")
    scan.add_argument("--profile", default="standard", choices=sorted(PROFILES))
    scan.add_argument("--limit", type=int, default=5)
    scan.add_argument("--verbose", action="store_true", help="show the full explanation")
    scan.add_argument("--json", action="store_true")
    scan.add_argument(
        "--fail-on",
        default="quarantine",
        choices=["allow", "warn", "sanitize", "quarantine", "block"],
        help="exit with status 2 at or above this action (default: quarantine)",
    )
    scan.set_defaults(func=_cmd_scan)

    sanitize = sub.add_parser("sanitize", help="remove or neutralize risky constructs")
    sanitize.add_argument("file")
    sanitize.add_argument("--profile", default="standard", choices=sorted(PROFILES))
    sanitize.add_argument("--diff", action="store_true", help="show a unified diff")
    sanitize.add_argument("--show", action="store_true", help="print the sanitized text")
    sanitize.add_argument("--out", default="", help="write the sanitized text to this path")
    sanitize.add_argument("--json", action="store_true")
    sanitize.set_defaults(func=_cmd_sanitize)

    bench = sub.add_parser("bench", help="run the benchmark over the bundled corpus")
    bench.add_argument("--json", default="", help="write raw results to this path")
    bench.add_argument("--markdown", default="", help="write a Markdown report to this path")
    bench.add_argument("--threshold", type=int, default=20)
    bench.add_argument("--policy", default="balanced", help="preset name or path")
    bench.set_defaults(func=_cmd_bench)

    policy = sub.add_parser("policy", help="print a policy preset")
    policy.add_argument("name", nargs="?", default="balanced", choices=sorted(PRESETS))
    policy.set_defaults(func=_cmd_policy)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args))
    except (PolicyError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
