#!/usr/bin/env python3

import typer
import time
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from rich import box
import pyfiglet

from core.config import load_config, setup_wizard
from core.menu import main_menu
from core.session import get_case_id

console = Console()
app = typer.Typer(add_completion=False)

BANNER = pyfiglet.figlet_format("MORTIS", font="banner3-D")

def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print("[red]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print("[red]  AWS Credential Forensics Engine  |  Hassan Azeem[/red]")
    console.print(f"[dim red]  Case ID: {get_case_id()}[/dim red]")
    console.print("[red]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()

def boot_sequence(demo: bool = False):
    if demo:
        steps = [
            "Loading demo case file...",
            "Injecting sample credentials...",
            "Simulating CloudTrail events...",
            "MORTIS demo ready.",
        ]
    else:
        steps = [
            "Opening case file...",
            "Loading exhumation patterns...",
            "Connecting to AWS services...",
            "Establishing GitHub API link...",
            "Calibrating autopsy signatures...",
            "MORTIS ready.",
        ]
    for step in steps:
        console.print(f"[red]  ▸[/red] [dim red]{step}[/dim red]")
        time.sleep(0.15)
    console.print()

@app.command()
def main(
    setup: bool = typer.Option(False, "--setup", help="Run setup wizard"),
    demo: bool = typer.Option(False, "--demo", help="Run simulated investigation (no credentials needed)"),
    scan_repo: str = typer.Option(None, "--scan-repo", help="Directly scan a GitHub repo URL"),
    inspect: str = typer.Option(None, "--inspect", help="Inspect a specific key ID"),
):
    print_banner()
    boot_sequence(demo=demo)

    if demo:
        from demo.runner import run_demo
        run_demo(console)
        return

    if setup:
        setup_wizard(console)
        return

    config = load_config()
    if not config:
        console.print("[red]  ✗ No config found. Run [bold]mortis --setup[/bold] first.[/red]")
        console.print()
        setup_wizard(console)
        return

    if scan_repo:
        from scanners.github_scanner import scan_repository
        scan_repository(scan_repo, config, console)
        return

    if inspect:
        from forensics.tracer import inspect_key
        inspect_key(inspect, config, console)
        return

    main_menu(config, console)

if __name__ == "__main__":
    app()
