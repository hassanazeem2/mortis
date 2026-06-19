from rich.console import Console
from rich.panel import Panel

from core.session import get_case_id
from forensics.risk import compute_exposure_risk


def print_autopsy_report(
    key_id: str,
    events: list,
    console: Console,
    *,
    first_seen=None,
    last_seen=None,
    suspicious_count: int = 0,
    source_ips: set | None = None,
    exposure_context: dict | None = None,
    days: int = 30,
):
    source_ips = source_ips or set()
    ctx = exposure_context or {}

    exposure_days = ctx.get("exposure_days", 0)
    if first_seen and last_seen:
        activity_days = (last_seen - first_seen).days
    else:
        activity_days = 0

    risk_score, risk_label = compute_exposure_risk(
        severity="CRITICAL",
        exposure_days=exposure_days or activity_days,
        is_public=ctx.get("is_public", False),
        suspicious_events=suspicious_count,
    )

    cause = _build_cause_of_exposure(ctx)
    activity = _build_activity_summary(first_seen, last_seen, len(events), suspicious_count, source_ips)
    verdict = _build_verdict(suspicious_count, risk_label)

    body = (
        f"[bold red]CASE FILE: {get_case_id()}[/bold red]\n"
        f"[dim red]Subject: {key_id}[/dim red]\n\n"
        f"[bold red]CAUSE OF EXPOSURE[/bold red]\n"
        f"[red]{cause}[/red]\n\n"
        f"[bold red]EXPOSURE CLOCK[/bold red]\n"
        f"[red]{_exposure_clock(ctx, exposure_days, activity_days)}[/red]\n\n"
        f"[bold red]ATTACKER ACTIVITY[/bold red]\n"
        f"[red]{activity}[/red]\n\n"
        f"[bold red]RISK SCORE[/bold red]\n"
        f"[bold red]{risk_score}/100 — {risk_label}[/bold red]\n\n"
        f"[bold red]VERDICT[/bold red]\n"
        f"[red]{verdict}[/red]"
    )

    console.print(Panel(body, title="[bold red]CREDENTIAL AUTOPSY[/bold red]", border_style="red", padding=(1, 2)))
    console.print()


def _build_cause_of_exposure(ctx: dict) -> str:
    if not ctx:
        return "  Origin unknown — key was submitted for direct CloudTrail analysis."

    repo = ctx.get("repo", "unknown repo")
    file_path = ctx.get("file", "unknown file")
    line = ctx.get("line", "?")
    commit = ctx.get("first_commit_sha", "unknown")[:7]
    author = ctx.get("first_commit_author", "unknown")
    date = ctx.get("first_seen_date", "unknown date")
    visibility = "PUBLIC" if ctx.get("is_public") else "PRIVATE"

    return (
        f"  Leaked via commit {commit} in [bold]{repo}[/bold] ({visibility})\n"
        f"  File: {file_path}:{line} · Author: {author}\n"
        f"  First appeared: {date}"
    )


def _exposure_clock(ctx: dict, exposure_days: int, activity_days: int) -> str:
    lines = []
    if exposure_days:
        lines.append(f"  Time in the wild: {exposure_days} day(s) since first commit")
    if ctx.get("still_in_head", True):
        lines.append("  Status: STILL PRESENT in repository HEAD")
    else:
        lines.append("  Status: Removed from HEAD (may remain in git history)")
    if activity_days:
        lines.append(f"  AWS activity window: {activity_days} day(s) of CloudTrail events")
    if not lines:
        lines.append("  Exposure duration could not be determined from git history")
    return "\n".join(lines)


def _build_activity_summary(first_seen, last_seen, total_events, suspicious_count, source_ips) -> str:
    first = first_seen.strftime("%Y-%m-%d %H:%M UTC") if first_seen else "Unknown"
    last = last_seen.strftime("%Y-%m-%d %H:%M UTC") if last_seen else "Unknown"
    ips = ", ".join(list(source_ips)[:3]) if source_ips else "None recorded"

    return (
        f"  First API call: {first}\n"
        f"  Last API call:  {last}\n"
        f"  Total events: {total_events} · Suspicious: {suspicious_count}\n"
        f"  Source IPs: {ips}"
    )


def _build_verdict(suspicious_count: int, risk_label: str) -> str:
    if suspicious_count > 0 and risk_label in ("CRITICAL", "HIGH"):
        return "  ACTIVE BREACH LIKELY — revoke key immediately and audit blast radius."
    if suspicious_count > 0:
        return "  Suspicious activity detected — rotate credentials and review IAM scope."
    if risk_label in ("CRITICAL", "HIGH"):
        return "  Key is exposed but no suspicious CloudTrail activity in window — rotate proactively."
    return "  Low immediate risk — still rotate and remove secret from git history."
