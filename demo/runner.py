import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.session import get_case_id
from demo.sample_data import (
    DEMO_KEY,
    DEMO_FINDINGS,
    DEMO_EXPOSURE_CONTEXT,
    build_demo_cloudtrail_events,
)
from forensics.tracer import build_forensic_report
from scanners.github_scanner import SEVERITY_COLOR


def run_demo(console: Console):
    console.print(Panel(
        "[bold red]DEMO MODE[/bold red]\n\n"
        "[dim red]Running a simulated investigation with fake data.[/dim red]\n"
        "[dim red]No AWS or GitHub credentials required.[/dim red]\n\n"
        f"[red]Case: {get_case_id()}[/red]",
        border_style="red",
        padding=(1, 2),
    ))
    console.print()

    _run_exhumation(console)
    time.sleep(0.4)
    _run_autopsy(console)

    console.print(Panel(
        "[bold red]Demo complete.[/bold red]\n\n"
        "[red]Ready for a real scan?[/red]\n"
        "[dim red]  python mortis.py --setup[/dim red]\n"
        "[dim red]  python mortis.py[/dim red]",
        border_style="red",
        padding=(1, 2),
    ))
    console.print()


def _run_exhumation(console: Console):
    console.print("[bold red]  ▸ EXHUMATION — Scanning demo repository...[/bold red]")
    console.print()

    steps = [
        "Connecting to github.com/acme-corp/backend-api...",
        "Scanning 847 commits...",
        "Checking config/.env.production...",
        "Pattern match: AWS Access Key",
        "Pattern match: AWS Secret Key",
    ]
    for step in steps:
        console.print(f"[red]  ▸[/red] [dim red]{step}[/dim red]")
        time.sleep(0.2)

    console.print()
    console.print("[red]  ✓ Scanned 142 files across 847 commits[/red]")
    console.print()
    console.print(f"[bold red]  ⚠ {len(DEMO_FINDINGS)} secret(s) detected[/bold red]")
    console.print()

    table = Table(box=box.SIMPLE_HEAVY, border_style="red", header_style="bold red")
    table.add_column("TYPE", style="red", min_width=20)
    table.add_column("SEVERITY", min_width=10)
    table.add_column("EXPOSED", style="red", width=8)
    table.add_column("RISK", style="bold red", width=12)
    table.add_column("FILE", style="dim red", min_width=30)
    table.add_column("LINE", style="red", width=6)

    for f in DEMO_FINDINGS:
        sev_color = SEVERITY_COLOR.get(f["severity"], "red")
        table.add_row(
            f["type"],
            f"[{sev_color}]{f['severity']}[/{sev_color}]",
            f"{f['exposure_days']}d",
            f"[{sev_color}]{f['risk_score']}/100 {f['risk_label']}[/{sev_color}]",
            f["file"],
            str(f["line"]),
        )

    console.print(table)
    console.print()
    console.print("[red]  ▸ Chaining to autopsy on AWS key found...[/red]")
    console.print()


def _run_autopsy(console: Console):
    console.print("[bold red]  ▸ AUTOPSY — Querying CloudTrail (simulated)...[/bold red]")
    console.print()

    steps = [
        f"Looking up AccessKeyId: {DEMO_KEY}...",
        "Pulling last 30 days of events...",
        f"Retrieved {len(build_demo_cloudtrail_events())} events",
        "Building blast radius map...",
    ]
    for step in steps:
        console.print(f"[red]  ▸[/red] [dim red]{step}[/dim red]")
        time.sleep(0.2)

    console.print()

    events = build_demo_cloudtrail_events()
    build_forensic_report(
        DEMO_KEY,
        events,
        console,
        days=30,
        exposure_context=DEMO_EXPOSURE_CONTEXT,
    )
