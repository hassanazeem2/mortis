#!/usr/bin/env python3

import typer
import time
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
import pyfiglet

from core.config import load_config, setup_wizard
from core.menu import main_menu
from core.session import get_case_id
from core.version import __version__

console = Console()
app = typer.Typer(add_completion=False)

BANNER = pyfiglet.figlet_format("MORTIS", font="banner3-D")


def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print("[red]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print("[red]  AWS Credential Forensics Engine  |  Hassan Azeem[/red]")
    console.print(f"[dim red]  Case ID: {get_case_id()} · v{__version__}[/dim red]")
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


def prompt_no_config(console: Console) -> bool:
    """Returns True if user chose demo and we should exit after."""
    console.print(Panel(
        "[bold red]No configuration found[/bold red]\n\n"
        "[red][1][/red] Run demo investigation [dim red](no credentials needed)[/dim red]\n"
        "[red][2][/red] Run setup wizard [dim red](connect AWS + GitHub)[/dim red]",
        border_style="red",
        padding=(1, 2),
    ))
    console.print()
    choice = Prompt.ask("[red]mortis[/red]", default="1")
    console.print()

    if choice == "1":
        from demo.runner import run_demo
        run_demo(console)
        return True
    setup_wizard(console)
    return False


@app.command()
def main(
    setup: bool = typer.Option(False, "--setup", help="Run setup wizard"),
    demo: bool = typer.Option(False, "--demo", help="Run simulated investigation (no credentials needed)"),
    version: bool = typer.Option(False, "--version", help="Show version"),
    scan_repo: str = typer.Option(None, "--scan-repo", help="Directly scan a GitHub repo URL"),
    inspect: str = typer.Option(None, "--inspect", help="Inspect a specific key ID"),
):
    if version:
        console.print(f"MORTIS v{__version__} — hassanazeem2")
        raise typer.Exit()

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
        if prompt_no_config(console):
            return
        config = load_config()
        if not config:
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
