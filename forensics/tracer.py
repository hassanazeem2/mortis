import json
import re
import boto3
from datetime import datetime, timedelta
from collections import defaultdict
from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from core.session import get_case_id
from forensics.autopsy import print_autopsy_report
from forensics.blast_radius import render_blast_radius_tree
from forensics.remediation import print_remediation_playbook

SUSPICIOUS_ACTIONS = {
    "GetSecretValue":      "CRITICAL - Secrets accessed",
    "ListUsers":           "HIGH - IAM enumeration",
    "ListRoles":           "HIGH - IAM enumeration",
    "CreateUser":          "CRITICAL - Privilege escalation attempt",
    "CreateAccessKey":     "CRITICAL - New key creation",
    "AttachUserPolicy":    "CRITICAL - Privilege escalation",
    "PutBucketPolicy":     "HIGH - Bucket policy modification",
    "GetObject":           "MEDIUM - Data access",
    "PutObject":           "MEDIUM - Data write",
    "DeleteObject":        "HIGH - Data destruction",
    "DescribeInstances":   "MEDIUM - Infrastructure enumeration",
    "GetCallerIdentity":   "LOW - Identity check (common recon step)",
    "AssumeRole":          "HIGH - Role assumption",
    "GetSessionToken":     "MEDIUM - Token generation",
    "ListBuckets":         "MEDIUM - S3 enumeration",
    "DescribeDBInstances": "HIGH - RDS enumeration",
    "GetPasswordData":     "CRITICAL - EC2 password retrieval",
    "ListSecrets":         "CRITICAL - Secrets Manager enumeration",
}

def inspect_menu(config: dict, console: Console):
    console.print("[red]━━━ AUTOPSY — CREDENTIAL FORENSICS ━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()

    key_id = Prompt.ask("[red]  Enter AWS Access Key ID to investigate[/red]")
    console.print()

    days = Prompt.ask("[red]  Lookback window (days)[/red]", default="30")
    console.print()

    inspect_key(key_id.strip(), config, console, int(days))

def inspect_key(key_id: str, config: dict, console: Console, days: int = 30, exposure_context: dict | None = None):
    console.print(Panel(
        f"[bold red]AUTOPSY IN PROGRESS[/bold red]\n"
        f"[dim red]Case: {get_case_id()}[/dim red]\n"
        f"[dim red]Target: {key_id}[/dim red]\n"
        f"[dim red]Window: Last {days} days[/dim red]",
        border_style="red",
        padding=(1, 2)
    ))
    console.print()

    from scanners.cloudtrail_scanner import analyze_for_key
    events = analyze_for_key(key_id, config, console, days)

    if config:
        from forensics.key_health import check_key_health
        check_key_health(key_id, config, console)

    if not events:
        console.print("[red]  No CloudTrail events found for this key in the specified window.[/red]")
        console.print("[dim red]  This may mean: key was never used, CloudTrail not enabled, or key is older than the window.[/dim red]")
        if exposure_context:
            print_autopsy_report(
                key_id, [], console,
                exposure_context=exposure_context,
                days=days,
            )
            print_remediation_playbook(
                key_id, console,
                repo=exposure_context.get("repo"),
                file_path=exposure_context.get("file"),
            )
        console.print()
        return

    build_forensic_report(key_id, events, console, days, exposure_context)

def analyze_findings(findings: list, config, console: Console):
    """Called after scanning — auto-investigate any AWS keys found."""
    aws_keys = [f for f in findings if f.get("type") == "AWS Access Key"]

    if not aws_keys:
        console.print("[dim red]  No AWS Access Keys to investigate forensically.[/dim red]")
        return

    console.print(f"[red]  ▸ Found {len(aws_keys)} AWS key(s) — chaining to autopsy...[/red]")
    console.print()

    for finding in aws_keys[:3]:
        match = finding.get("match", "")
        key_match = re.search(r"(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}", match)
        if key_match and config:
            ctx = {
                "repo": finding.get("repo"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "first_commit_sha": finding.get("first_commit_sha"),
                "first_commit_author": finding.get("first_commit_author"),
                "first_seen_date": finding.get("first_seen_date"),
                "exposure_days": finding.get("exposure_days", 0),
                "is_public": finding.get("is_public", False),
                "still_in_head": finding.get("still_in_head", True),
            }
            inspect_key(key_match.group(), config, console, exposure_context=ctx)

def build_forensic_report(key_id: str, events: list, console: Console, days: int, exposure_context: dict | None = None):
    by_day = defaultdict(list)
    by_action = defaultdict(int)
    by_resource = defaultdict(int)
    suspicious_events = []
    source_ips = set()

    first_seen = None
    last_seen = None

    for event in events:
        event_time = event.get("EventTime")
        if event_time:
            if not first_seen or event_time < first_seen:
                first_seen = event_time
            if not last_seen or event_time > last_seen:
                last_seen = event_time

            day_key = event_time.strftime("%Y-%m-%d")
            by_day[day_key].append(event)

        action = event.get("EventName", "Unknown")
        by_action[action] += 1

        if action in SUSPICIOUS_ACTIONS:
            suspicious_events.append(event)

        resources = event.get("Resources", [])
        for r in resources:
            rname = r.get("ResourceName", "")
            if rname:
                by_resource[rname] += 1

        raw = event.get("CloudTrailEvent", "{}")
        try:
            ct = json.loads(raw)
            ip = ct.get("sourceIPAddress", "")
            if ip:
                source_ips.add(ip)
        except json.JSONDecodeError:
            pass

    exposure_days = (last_seen - first_seen).days if first_seen and last_seen else 0

    console.print("[red]━━━ ACTIVITY TIMELINE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()

    max_count = max((len(v) for v in by_day.values()), default=1)

    for day in sorted(by_day.keys()):
        count = len(by_day[day])
        bar_len = int((count / max_count) * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        sus_count = sum(1 for e in by_day[day] if e.get("EventName") in SUSPICIOUS_ACTIONS)
        flag = " [bold red]⚠[/bold red]" if sus_count > 0 else ""
        console.print(f"  [dim red]{day}[/dim red]  [red]{bar}[/red]  [red]{count:3d} events[/red]{flag}")

    console.print()

    console.print("[red]━━━ EXPOSURE SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()
    console.print(f"  [red]Case ID        :[/red] [bold red]{get_case_id()}[/bold red]")
    console.print(f"  [red]Key ID         :[/red] [bold red]{key_id}[/bold red]")
    console.print(f"  [red]First Seen     :[/red] [red]{first_seen.strftime('%Y-%m-%d %H:%M UTC') if first_seen else 'Unknown'}[/red]")
    console.print(f"  [red]Last Seen      :[/red] [red]{last_seen.strftime('%Y-%m-%d %H:%M UTC') if last_seen else 'Unknown'}[/red]")
    console.print(f"  [red]Active Window  :[/red] [bold red]{exposure_days} days[/bold red]")
    console.print(f"  [red]Total Events   :[/red] [red]{len(events)}[/red]")
    console.print(f"  [red]Suspicious     :[/red] [bold red]{len(suspicious_events)}[/bold red]")
    console.print(f"  [red]Source IPs     :[/red] [red]{len(source_ips)} unique[/red]")
    console.print()

    if source_ips:
        console.print("[red]━━━ SOURCE IP ADDRESSES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
        console.print()
        for ip in list(source_ips)[:10]:
            console.print(f"  [red]▸[/red] [dim red]{ip}[/dim red]")
        console.print()

    tree = render_blast_radius_tree(key_id, dict(by_action))
    if tree:
        console.print("[red]━━━ BLAST RADIUS MAP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
        console.print()
        console.print(f"[dim red]{tree}[/dim red]")
        console.print()

    console.print("[red]━━━ API CALL BREAKDOWN ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()

    table = Table(box=box.SIMPLE_HEAVY, border_style="red", header_style="bold red")
    table.add_column("API CALL", style="red", min_width=30)
    table.add_column("COUNT", style="red", width=8)
    table.add_column("RISK NOTE", style="dim red")

    for action, count in sorted(by_action.items(), key=lambda x: x[1], reverse=True)[:20]:
        note = SUSPICIOUS_ACTIONS.get(action, "—")
        note_color = "bold red" if "CRITICAL" in note else "red" if "HIGH" in note else "dark_orange" if "MEDIUM" in note else "dim red"
        table.add_row(action, str(count), f"[{note_color}]{note}[/{note_color}]")

    console.print(table)
    console.print()

    if by_resource:
        console.print("[red]━━━ TOUCHED RESOURCES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
        console.print()

        table2 = Table(box=box.SIMPLE, border_style="red", header_style="bold red")
        table2.add_column("RESOURCE", style="red", min_width=40)
        table2.add_column("ACCESSES", style="red", width=10)

        for resource, count in sorted(by_resource.items(), key=lambda x: x[1], reverse=True)[:15]:
            table2.add_row(resource[:60], str(count))

        console.print(table2)
        console.print()

    print_autopsy_report(
        key_id, events, console,
        first_seen=first_seen,
        last_seen=last_seen,
        suspicious_count=len(suspicious_events),
        source_ips=source_ips,
        exposure_context=exposure_context,
        days=days,
    )

    has_critical = any(
        "CRITICAL" in SUSPICIOUS_ACTIONS.get(e.get("EventName", ""), "")
        for e in suspicious_events
    )
    ctx = exposure_context or {}
    print_remediation_playbook(
        key_id, console,
        repo=ctx.get("repo"),
        file_path=ctx.get("file"),
        has_critical_actions=has_critical,
    )

    from core.case_store import add_autopsy_summary
    add_autopsy_summary({
        "key_id": key_id,
        "total_events": len(events),
        "suspicious_events": len(suspicious_events),
        "source_ips": list(source_ips)[:10],
    })
