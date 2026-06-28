import re
import time
import base64
from datetime import datetime, timezone
from forensics.risk import compute_exposure_risk
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from github import Github, GithubException

# AWS credential patterns
PATTERNS = {
    "AWS Access Key":     r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
    "AWS Secret Key":     r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "AWS Session Token":  r"(?i)(aws_session_token|aws_security_token).{0,20}['\"][A-Za-z0-9/+=]{100,}['\"]",
    "GitHub PAT":         r"ghp_[A-Za-z0-9]{36}",
    "GitHub OAuth":       r"gho_[A-Za-z0-9]{36}",
    "Generic API Key":    r"(?i)(api_key|apikey|api-key).{0,10}['\"][A-Za-z0-9_\-]{20,50}['\"]",
    "Private Key":        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Hardcoded Password": r"(?i)(password|passwd|pwd).{0,5}=.{0,5}['\"][^'\"]{8,}['\"]",
}

SEVERITY = {
    "AWS Access Key": "CRITICAL",
    "AWS Secret Key": "CRITICAL",
    "AWS Session Token": "HIGH",
    "GitHub PAT": "HIGH",
    "GitHub OAuth": "HIGH",
    "Generic API Key": "MEDIUM",
    "Private Key": "CRITICAL",
    "Hardcoded Password": "MEDIUM",
}

def enrich_finding_exposure(repo, finding: dict):
    """Estimate how long a secret has been exposed via git history."""
    finding["is_public"] = not repo.private
    finding["still_in_head"] = True

    try:
        commits = list(repo.get_commits(path=finding["file"]))
        if commits:
            oldest = commits[-1]
            finding["first_commit_sha"] = oldest.sha
            author = oldest.commit.author
            finding["first_commit_author"] = author.name if author else "unknown"
            if author and author.date:
                finding["first_seen_date"] = author.date.strftime("%Y-%m-%d %H:%M UTC")
                now = datetime.now(timezone.utc)
                commit_date = author.date if author.date.tzinfo else author.date.replace(tzinfo=timezone.utc)
                finding["exposure_days"] = max(0, (now - commit_date).days)
            else:
                finding["first_seen_date"] = "unknown"
                finding["exposure_days"] = 0
        else:
            finding["exposure_days"] = 0
    except Exception:
        finding["exposure_days"] = 0

    score, label = compute_exposure_risk(
        finding["severity"],
        exposure_days=finding.get("exposure_days", 0),
        is_public=finding["is_public"],
    )
    finding["risk_score"] = score
    finding["risk_label"] = label

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "dark_orange",
    "LOW": "yellow",
}

def scan_menu(config: dict, console: Console):
    console.print("[red]━━━ GITHUB REPOSITORY SCANNER ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()
    console.print("[dim red]  Options:[/dim red]")
    console.print("[red]  [1][/red] [red]Scan your own repos[/red]")
    console.print("[red]  [2][/red] [red]Scan specific repo URL[/red]")
    console.print("[red]  [0][/red] [dim red]Back[/dim red]")
    console.print()

    choice = Prompt.ask("[red]mortis/github[/red]", default="0")
    console.print()

    if choice == "1":
        scan_own_repos(config, console)
    elif choice == "2":
        repo_url = Prompt.ask("[red]  Repository URL[/red]")
        console.print()
        repo_name = repo_url.replace("https://github.com/", "").strip("/")
        scan_repository(repo_name, config, console)

def scan_own_repos(config: dict, console: Console):
    try:
        g = Github(config["github"]["token"])
        user = g.get_user()
        repos = list(user.get_repos())

        console.print(f"[red]  ✓ Found {len(repos)} repositories for {user.login}[/red]")
        console.print()

        table = Table(box=box.SIMPLE, border_style="red", header_style="bold red")
        table.add_column("#", style="dim red", width=4)
        table.add_column("Repository", style="red")
        table.add_column("Visibility", style="red")
        table.add_column("Last Updated", style="dim red")

        for i, repo in enumerate(repos[:20], 1):
            vis = "PRIVATE" if repo.private else "PUBLIC"
            updated = repo.updated_at.strftime("%Y-%m-%d") if repo.updated_at else "N/A"
            table.add_row(str(i), repo.full_name, vis, updated)

        console.print(table)
        console.print()

        choice = Prompt.ask("[red]  Select repo number (or 'all' to scan all)[/red]")
        console.print()

        if choice.lower() == "all":
            all_findings = []
            for repo in repos:
                findings = scan_repository(repo.full_name, config, console, silent=True)
                all_findings.extend(findings)
            display_findings_summary(all_findings, console, config)
        elif choice.isdigit() and 1 <= int(choice) <= len(repos):
            repo = repos[int(choice) - 1]
            scan_repository(repo.full_name, config, console)
        else:
            console.print("[red]  ✗ Invalid selection.[/red]")

    except GithubException as e:
        console.print(f"[red]  ✗ GitHub API error: {e.data.get('message', str(e))}[/red]")
    except Exception as e:
        console.print(f"[red]  ✗ Error: {str(e)}[/red]")

def scan_repository(repo_name: str, config: dict, console: Console, silent: bool = False):
    findings = []

    try:
        g = Github(config["github"]["token"])
        repo = g.get_repo(repo_name)

        if not silent:
            console.print(f"[red]  ▸ Scanning:[/red] [bold red]{repo.full_name}[/bold red]")
            console.print()

        # Get all commits
        commits = list(repo.get_commits())
        commit_count = len(commits)

        if not silent:
            console.print(f"[dim red]  Analyzing {commit_count} commits across all branches...[/dim red]")
            console.print()

        # Scan files in default branch
        try:
            contents = repo.get_contents("")
            files_scanned = 0

            with Progress(
                SpinnerColumn(style="red"),
                TextColumn("[red]{task.description}[/red]"),
                BarColumn(style="red", complete_style="bold red"),
                TextColumn("[dim red]{task.completed}/{task.total}[/dim red]"),
                console=console,
                transient=True
            ) as progress:
                stack = list(contents)
                task = progress.add_task("Scanning files...", total=None)

                while stack:
                    file_content = stack.pop(0)
                    progress.update(task, description=f"[red]Scanning {file_content.path[:50]}[/red]")

                    if file_content.type == "dir":
                        try:
                            stack.extend(repo.get_contents(file_content.path))
                        except:
                            pass
                        continue

                    # Skip binary files
                    if any(file_content.path.endswith(ext) for ext in [
                        ".png", ".jpg", ".gif", ".zip", ".tar", ".gz",
                        ".exe", ".bin", ".pdf", ".ico", ".woff", ".ttf"
                    ]):
                        continue

                    try:
                        if file_content.encoding == "base64" and file_content.content:
                            raw = base64.b64decode(file_content.content).decode("utf-8", errors="ignore")
                        else:
                            continue

                        files_scanned += 1

                        for secret_type, pattern in PATTERNS.items():
                            matches = re.finditer(pattern, raw)
                            for match in matches:
                                line_num = raw[:match.start()].count("\n") + 1
                                finding = {
                                    "type": secret_type,
                                    "severity": SEVERITY.get(secret_type, "MEDIUM"),
                                    "repo": repo.full_name,
                                    "file": file_content.path,
                                    "line": line_num,
                                    "match": match.group()[:60] + "..." if len(match.group()) > 60 else match.group(),
                                    "commit_count": commit_count,
                                    "repo_url": repo.html_url,
                                    "discovered": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                }
                                enrich_finding_exposure(repo, finding)
                                findings.append(finding)
                    except Exception:
                        pass

        except Exception as e:
            if not silent:
                console.print(f"[dim red]  ⚠ Could not scan some files: {str(e)[:60]}[/dim red]")

        if not silent:
            display_findings(findings, files_scanned, commit_count, console, config)

        if findings:
            from core.case_store import add_findings
            add_findings(findings, source="github")

        return findings

    except GithubException as e:
        if not silent:
            console.print(f"[red]  ✗ GitHub error: {e.data.get('message', str(e))}[/red]")
        return []
    except Exception as e:
        if not silent:
            console.print(f"[red]  ✗ Error: {str(e)}[/red]")
        return []

def display_findings(findings: list, files_scanned: int, commit_count: int, console: Console, config: dict | None = None):
    console.print()
    console.print(f"[red]  ✓ Scanned {files_scanned} files across {commit_count} commits[/red]")
    console.print()

    if not findings:
        console.print("[red]  ✓ No secrets detected.[/red]")
        console.print()
        return

    console.print(f"[bold red]  ⚠ {len(findings)} secret(s) detected[/bold red]")
    console.print()

    table = Table(box=box.SIMPLE_HEAVY, border_style="red", header_style="bold red")
    table.add_column("TYPE", style="red", min_width=20)
    table.add_column("SEVERITY", min_width=10)
    table.add_column("EXPOSED", style="red", width=8)
    table.add_column("RISK", style="bold red", width=12)
    table.add_column("FILE", style="dim red", min_width=30)
    table.add_column("LINE", style="red", width=6)
    table.add_column("MATCH", style="dim red")

    for f in findings:
        sev_color = SEVERITY_COLOR.get(f["severity"], "red")
        exposed = f"{f.get('exposure_days', '?')}d" if f.get("exposure_days") is not None else "—"
        risk = f"{f.get('risk_score', '—')}/100"
        table.add_row(
            f["type"],
            f"[{sev_color}]{f['severity']}[/{sev_color}]",
            exposed,
            f"[{sev_color}]{risk} {f.get('risk_label', '')}[/{sev_color}]",
            f["file"][-40:] if len(f["file"]) > 40 else f["file"],
            str(f["line"]),
            f["match"][:40] + "..." if len(f["match"]) > 40 else f["match"],
        )

    console.print(table)
    console.print()

    from rich.prompt import Confirm
    if config and Confirm.ask("[red]  Chain to autopsy on AWS keys found?[/red]", default=True):
        from forensics.tracer import analyze_findings
        analyze_findings(findings, config, console)

def display_findings_summary(findings: list, console: Console, config: dict | None = None):
    if not findings:
        console.print("[red]  ✓ No secrets found across all repositories.[/red]")
        return

    console.print(f"[bold red]  ⚠ TOTAL FINDINGS: {len(findings)}[/bold red]")
    display_findings(findings, 0, 0, console, config)
