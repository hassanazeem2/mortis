import json
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt

from core.session import get_case_id

def export_menu(config: dict, console: Console):
    console.print("[red]━━━ EXPORT REPORT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()
    console.print("[red]  [1][/red] [red]Export as JSON[/red]")
    console.print("[red]  [2][/red] [red]Export as Markdown[/red]")
    console.print("[red]  [0][/red] [dim red]Back[/dim red]")
    console.print()

    choice = Prompt.ask("[red]mortis/export[/red]", default="0")
    console.print()

    if choice == "1":
        export_json([], console)
    elif choice == "2":
        export_markdown([], console)

def export_json(findings: list, console: Console):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path.home() / f"mortis_report_{timestamp}.json"

    report = {
        "case_id": get_case_id(),
        "generated": datetime.now().isoformat(),
        "tool": "MORTIS — AWS Credential Forensics Engine",
        "total_findings": len(findings),
        "findings": findings,
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    console.print(f"[red]  ✓ Report exported:[/red] [bold red]{path}[/bold red]")
    console.print()

def export_markdown(findings: list, console: Console):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path.home() / f"mortis_report_{timestamp}.md"

    lines = [
        "# MORTIS — Forensic Report",
        f"Case ID: {get_case_id()}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"## Summary",
        f"- **Total Findings:** {len(findings)}",
        f"- **Critical:** {sum(1 for f in findings if f.get('severity') == 'CRITICAL')}",
        f"- **High:** {sum(1 for f in findings if f.get('severity') == 'HIGH')}",
        "",
        "## Findings",
        "",
    ]

    for i, finding in enumerate(findings, 1):
        lines.append(f"### {i}. {finding.get('type', 'Unknown')} — {finding.get('severity', 'UNKNOWN')}")
        for k, v in finding.items():
            if k not in ("type", "severity"):
                lines.append(f"- **{k}:** {v}")
        lines.append("")

    with open(path, "w") as f:
        f.write("\n".join(lines))

    console.print(f"[red]  ✓ Markdown report exported:[/red] [bold red]{path}[/bold red]")
    console.print()
