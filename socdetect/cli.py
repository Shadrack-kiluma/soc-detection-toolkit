"""CLI for the SOC Detection Toolkit."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .rules import analyze


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"line {line_number}: invalid JSON ({exc.msg})") from exc
                if not isinstance(event, dict):
                    raise ValueError(f"line {line_number}: expected a JSON object")
                events.append(event)
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    return events


def render_text(report: dict[str, Any]) -> str:
    lines = [f"SOC Detection Toolkit — {report['events_analyzed']} events, {report['findings_count']} finding(s)", ""]
    if not report["findings"]:
        lines.append("No configured rule matched. This does not prove the logs are free of suspicious activity.")
    for finding in report["findings"]:
        lines.append(f"[{finding['severity'].upper()}] {finding['rule_id']} · {finding['title']}")
        lines.append(f"  Time: {finding['timestamp']} UTC")
        lines.append(f"  User: {finding['username']} | Source: {finding['source_ip']} | Events: {finding['event_count']}")
        for evidence in finding["evidence"]:
            lines.append(f"  Evidence: {evidence}")
        lines.append("  Triage:")
        lines.extend(f"    - {action}" for action in finding["recommended_triage"])
        lines.append("")
    lines.append(report["disclaimer"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="socdetect",
        description="Run explainable defensive detections against normalized authentication JSONL.",
    )
    parser.add_argument("input", type=Path, help="JSON Lines file; one normalized auth event per line")
    parser.add_argument("--failure-threshold", type=int, default=5,
                        help="failures that trigger burst detections (default: 5)")
    parser.add_argument("--window-minutes", type=int, default=10,
                        help="sliding detection window in minutes (default: 10)")
    parser.add_argument("--spray-accounts", type=int, default=8,
                        help="distinct accounts required for spray detection (default: 8)")
    parser.add_argument("--spray-max-per-account", type=int, default=2,
                        help="maximum failures per account for spray detection (default: 2)")
    parser.add_argument("--format", choices=("text", "json"), default="text",
                        help="report format (default: text)")
    parser.add_argument("--output", type=Path, help="write report to a file instead of stdout")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    try:
        report = analyze(
            load_events(args.input),
            failure_threshold=args.failure_threshold,
            window_minutes=args.window_minutes,
            spray_account_threshold=args.spray_accounts,
            spray_max_attempts_per_account=args.spray_max_per_account,
        )
    except ValueError as exc:
        print(f"socdetect: error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2) if args.format == "json" else render_text(report)
    if args.output:
        try:
            if args.input.resolve() == args.output.resolve():
                print("socdetect: error: output path must not overwrite the input log", file=sys.stderr)
                return 2
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"socdetect: error: cannot write report: {exc}", file=sys.stderr)
            return 2
        print(f"Wrote {report['findings_count']} finding(s) to {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
