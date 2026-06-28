from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from agent import MiniAgent, guard_from_name
from tools import ToolBox


ROOT = Path(__file__).resolve().parent


def load_scenario(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def run_once(scenario_path: Path, guard_name: str):
    scenario = load_scenario(scenario_path)
    toolbox = ToolBox(
        documents={scenario["doc_id"]: scenario["document"]},
        secret=scenario["secret"],
    )
    agent = MiniAgent(toolbox, guard_from_name(guard_name))
    report = agent.run_task(scenario["name"], scenario["doc_id"])
    report.guard = guard_name
    return report


def print_report(report) -> None:
    print(f"\nScenario: {report.scenario}")
    print(f"Guard: {report.guard}")
    print(f"Task success: {report.task_success}")
    print(f"Attack success: {report.attack_success}")
    print(f"Blocked calls: {report.blocked_calls}")
    print(f"False positive: {report.false_positive}")
    print("\nEvents:")
    for event in report.events:
        status = "OK" if event.ok else "BLOCKED"
        print(f"  {event.step}. [{status}] {event.action} - {event.detail}")
    print("\nSent emails:")
    if not report.sent_emails:
        print("  none")
    for email in report.sent_emails:
        print(f"  to={email['to']} body={email['body']}")
    print("\nSaved notes:")
    for note in report.notes:
        print(f"  {note}")


def print_table(reports) -> None:
    headers = ["Guard", "Task", "Attack", "Blocked", "False Positive"]
    rows = [
        [
            report.guard,
            str(report.task_success),
            str(report.attack_success),
            str(report.blocked_calls),
            str(report.false_positive),
        ]
        for report in reports
    ]
    widths = [
        max(len(str(row[i])) for row in [headers] + rows)
        for i in range(len(headers))
    ]
    print(" | ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(" | ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def main() -> None:
    parser = argparse.ArgumentParser(description="ToolTrace: LLM Agent tool-call hijack mini benchmark")
    parser.add_argument(
        "--scenario",
        default=str(ROOT / "scenarios" / "indirect_injection.json"),
        help="Path to a scenario JSON file",
    )
    parser.add_argument(
        "--guard",
        choices=["none", "confirm", "taint", "both"],
        default="none",
        help="Defense mode",
    )
    parser.add_argument("--all", action="store_true", help="Compare all defense modes")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()

    if args.all:
        reports = [
            run_once(Path(args.scenario), guard_name)
            for guard_name in ["none", "confirm", "taint", "both"]
        ]
        if args.json:
            print(json.dumps([asdict(report) for report in reports], ensure_ascii=False, indent=2))
        else:
            print_table(reports)
        return

    report = run_once(Path(args.scenario), args.guard)
    if args.json:
        print(json.dumps(asdict(report), ensure_ascii=False, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
