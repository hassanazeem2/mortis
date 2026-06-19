import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.prompt import Prompt

def main_menu(config: dict, console: Console):
    while True:
        console.print("[red]━━━ MAIN MENU ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
        console.print()
        console.print("[bold red]  EXHUMATION[/bold red] [dim red]— find exposed secrets[/dim red]")
        console.print("[bold red]  [1][/bold red] [red]Scan GitHub Repository[/red]")
        console.print("[bold red]  [2][/bold red] [red]Scan S3 Buckets[/red]")
        console.print()
        console.print("[bold red]  AUTOPSY[/bold red] [dim red]— trace what keys accessed[/dim red]")
        console.print("[bold red]  [3][/bold red] [red]Analyze CloudTrail Logs[/red]")
        console.print("[bold red]  [4][/bold red] [red]Inspect Compromised Key[/red]")
        console.print("[bold red]  [5][/bold red] [red]Full Forensic Report[/red]")
        console.print()
        console.print("[bold red]  BURIAL[/bold red] [dim red]— remediate & export[/dim red]")
        console.print("[bold red]  [6][/bold red] [red]Export Report[/red]")
        console.print()
        console.print("[bold red]  DEMO[/bold red] [dim red]— try without credentials[/dim red]")
        console.print("[bold red]  [7][/bold red] [red]Run Demo Investigation[/red]")
        console.print("[bold red]  [0][/bold red] [dim red]Exit[/dim red]")
        console.print()

        choice = Prompt.ask("[red]mortis[/red]", default="0")
        console.print()

        if choice == "1":
            from scanners.github_scanner import scan_menu
            scan_menu(config, console)

        elif choice == "2":
            from scanners.s3_scanner import scan_menu
            scan_menu(config, console)

        elif choice == "3":
            from scanners.cloudtrail_scanner import scan_menu
            scan_menu(config, console)

        elif choice == "4":
            from forensics.tracer import inspect_menu
            inspect_menu(config, console)

        elif choice == "5":
            from forensics.report import full_report
            full_report(config, console)

        elif choice == "6":
            from reports.exporter import export_menu
            export_menu(config, console)

        elif choice == "7":
            from demo.runner import run_demo
            run_demo(console)

        elif choice == "0":
            console.print("[dim red]  Shutting down MORTIS...[/dim red]")
            console.print("[red]  ██ Session terminated.[/red]")
            console.print()
            break

        else:
            console.print("[red]  ✗ Invalid option.[/red]")
            console.print()
