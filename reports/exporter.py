import json
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt

from core.case_store import get_findings, load_case, list_cases
from core.session import get_case_id


def export_menu(config: dict, console: Console):
    findings = get_findings()
    console.print("[red]━━━ EXPORT REPORT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()
    console.print(f"[dim red]  Case: {get_case_id()} · {len(findings)} finding(s) on record[/dim red]")
    console.print()
    console.print("[red]  [1][/red] [red]Export as JSON[/red]")
    console.print("[red]  [2][/red] [red]Export as Markdown[/red]")
    console.print("[red]  [3][/red] [red]Export as HTML[/red]")
    console.print("[red]  [4][/red] [red]Export as SARIF (GitHub Security)[/red]")
    console.print("[red]  [0][/red] [dim red]Back[/dim red]")
    console.print()

    choice = Prompt.ask("[red]mortis/export[/red]", default="0")
    console.print()

    if choice == "1":
        export_json(findings, console)
    elif choice == "2":
        export_markdown(findings, console)
    elif choice == "3":
        export_html(findings, console)
    elif choice == "4":
        export_sarif(findings, console)


def _export_path(ext: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path.home() / f"mortis_report_{get_case_id()}_{timestamp}.{ext}"


def _build_report(findings: list) -> dict:
    case = load_case()
    return {
        "case_id": get_case_id(),
        "generated": datetime.now().isoformat(),
        "tool": "MORTIS — AWS Credential Forensics Engine",
        "author": "hassanazeem2",
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
        "key_health": case.get("key_health", {}),
        "autopsies": case.get("autopsies", []),
        "past_cases": list_cases()[:10],
        "findings": findings,
    }


def export_json(findings: list | None, console: Console):
    findings = findings if findings is not None else get_findings()
    path = _export_path("json")
    report = _build_report(findings)

    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    console.print(f"[red]  ✓ JSON exported:[/red] [bold red]{path}[/bold red]")
    console.print()


def export_markdown(findings: list | None, console: Console):
    findings = findings if findings is not None else get_findings()
    path = _export_path("md")
    report = _build_report(findings)

    lines = [
        "# MORTIS — Forensic Report",
        f"**Case ID:** {report['case_id']}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Author:** hassanazeem2",
        "",
        "## Summary",
        f"- **Total Findings:** {report['total_findings']}",
        f"- **Critical:** {report['critical']}",
        f"- **High:** {report['high']}",
        "",
    ]

    if report["key_health"]:
        lines.append("## Key Health")
        lines.append("")
        for key_id, health in report["key_health"].items():
            lines.append(f"- `{key_id}` — {health.get('status', 'unknown')}")
        lines.append("")

    lines.append("## Findings")
    lines.append("")

    for i, finding in enumerate(findings, 1):
        sev = finding.get("severity", "UNKNOWN")
        lines.append(f"### {i}. {finding.get('type', 'Unknown')} — {sev}")
        for k, v in finding.items():
            if k not in ("type", "severity"):
                lines.append(f"- **{k}:** {v}")
        lines.append("")

    with open(path, "w") as f:
        f.write("\n".join(lines))

    console.print(f"[red]  ✓ Markdown exported:[/red] [bold red]{path}[/bold red]")
    console.print()


def export_html(findings: list | None, console: Console):
    findings = findings if findings is not None else get_findings()
    path = _export_path("html")
    report = _build_report(findings)

    rows = ""
    for f in findings:
        rows += f"""
        <tr>
          <td>{f.get('type', '')}</td>
          <td class="sev-{f.get('severity', 'LOW').lower()}">{f.get('severity', '')}</td>
          <td>{f.get('repo', f.get('bucket', ''))}</td>
          <td>{f.get('file', f.get('key', ''))}</td>
          <td>{f.get('exposure_days', '—')}</td>
          <td>{f.get('risk_score', '—')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>MORTIS Report — {report['case_id']}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0d0d0d; color: #e8e8e8; margin: 2rem; }}
    h1 {{ color: #ff4444; }}
    .meta {{ color: #888; margin-bottom: 2rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border: 1px solid #333; padding: 0.6rem; text-align: left; }}
    th {{ background: #1a0000; color: #ff6666; }}
  tr:nth-child(even) {{ background: #111; }}
    .sev-critical {{ color: #ff4444; font-weight: bold; }}
    .sev-high {{ color: #ff8844; }}
    .stats {{ display: flex; gap: 2rem; margin: 1.5rem 0; }}
    .stat {{ background: #1a1a1a; padding: 1rem 1.5rem; border-left: 3px solid #8b0000; }}
  </style>
</head>
<body>
  <h1>MORTIS Forensic Report</h1>
  <p class="meta">Case {report['case_id']} · {report['generated'][:19]} UTC · hassanazeem2</p>
  <div class="stats">
    <div class="stat"><strong>{report['total_findings']}</strong><br>Findings</div>
    <div class="stat"><strong>{report['critical']}</strong><br>Critical</div>
    <div class="stat"><strong>{report['high']}</strong><br>High</div>
  </div>
  <table>
    <thead><tr><th>Type</th><th>Severity</th><th>Source</th><th>Location</th><th>Exposed (days)</th><th>Risk</th></tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="6">No findings recorded</td></tr>'}</tbody>
  </table>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)

    console.print(f"[red]  ✓ HTML exported:[/red] [bold red]{path}[/bold red]")
    console.print()


def export_sarif(findings: list | None, console: Console):
    findings = findings if findings is not None else get_findings()
    path = _export_path("sarif.json")

    results = []
    for i, f in enumerate(findings):
        level = "error" if f.get("severity") == "CRITICAL" else "warning"
        location = f.get("file") or f.get("key") or "unknown"
        results.append({
            "ruleId": f.get("type", "secret").replace(" ", "_").upper(),
            "level": level,
            "message": {"text": f"{f.get('type')} detected in {location}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": location},
                    "region": {"startLine": f.get("line", 1)},
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MORTIS",
                    "version": "1.1.0",
                    "informationUri": "https://github.com/hassanazeem2/mortis1",
                }
            },
            "results": results,
        }],
    }

    with open(path, "w") as f:
        json.dump(sarif, f, indent=2)

    console.print(f"[red]  ✓ SARIF exported:[/red] [bold red]{path}[/bold red]")
    console.print()
