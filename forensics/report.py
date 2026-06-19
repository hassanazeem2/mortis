from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from core.session import get_case_id


def full_report(config: dict, console: Console):
    console.print(Panel(
        f"[bold red]FULL FORENSIC SWEEP[/bold red]\n[dim red]Case: {get_case_id()}[/dim red]",
        border_style="red",
        padding=(1, 2),
    ))
    console.print()
    console.print("[dim red]  This will run:[/dim red]")
    console.print("[red]  ▸ Exhumation: GitHub + S3 scan[/red]")
    console.print("[red]  ▸ Autopsy: CloudTrail analysis + key trace[/red]")
    console.print("[red]  ▸ Burial: export case file[/red]")
    console.print()

    from rich.prompt import Confirm
    if not Confirm.ask("[red]  Proceed?[/red]", default=True):
        return

    console.print()
    all_findings = []

    console.print("[bold red]  ▸ EXHUMATION — GitHub Repository Scan[/bold red]")
    console.print()
    try:
        from github import Github
        g = Github(config["github"]["token"])
        user = g.get_user()
        repos = list(user.get_repos())[:10]

        from scanners.github_scanner import scan_repository
        for repo in repos:
            findings = scan_repository(repo.full_name, config, console, silent=True)
            all_findings.extend(findings)

        console.print(f"[red]  ✓ GitHub: {len(all_findings)} finding(s)[/red]")
    except Exception as e:
        console.print(f"[red]  ✗ GitHub scan failed: {str(e)[:60]}[/red]")

    console.print()

    console.print("[bold red]  ▸ AUTOPSY — CloudTrail Analysis[/bold red]")
    console.print()
    try:
        from datetime import datetime, timedelta
        from scanners.cloudtrail_scanner import analyze_cloudtrail
        analyze_cloudtrail(config, console, datetime.utcnow() - timedelta(days=30), datetime.utcnow())
    except Exception as e:
        console.print(f"[red]  ✗ CloudTrail scan failed: {str(e)[:60]}[/red]")

    console.print()

    if all_findings:
        from forensics.tracer import analyze_findings
        console.print("[bold red]  ▸ AUTOPSY — Chained key investigation[/bold red]")
        console.print()
        analyze_findings(all_findings, config, console)

    console.print("[red]━━━ REPORT SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()
    console.print(f"  [red]Case ID:[/red] [bold red]{get_case_id()}[/bold red]")
    console.print(f"  [red]Total secrets found:[/red] [bold red]{len(all_findings)}[/bold red]")

    critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in all_findings if f.get("severity") == "HIGH")

    console.print(f"  [red]Critical:[/red] [bold red]{critical}[/bold red]")
    console.print(f"  [red]High:[/red] [red]{high}[/red]")
    console.print()

    if all_findings:
        from reports.exporter import export_json
        export_json(all_findings, console)
