from rich.console import Console


def print_remediation_playbook(
    key_id: str,
    console: Console,
    *,
    repo: str | None = None,
    file_path: str | None = None,
    has_critical_actions: bool = False,
):
    console.print("[red]━━━ BURIAL — REMEDIATION PLAYBOOK ━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()
    console.print("[dim red]  Copy-paste commands for incident response:[/dim red]")
    console.print()

    console.print(f"  [bold red][1][/bold red] [red]Revoke the compromised key immediately[/red]")
    console.print(f"      [dim red]aws iam update-access-key --access-key-id {key_id} --status Inactive[/dim red]")
    console.print(f"      [dim red]aws iam delete-access-key --access-key-id {key_id}[/dim red]")
    console.print()

    console.print(f"  [bold red][2][/bold red] [red]Audit what the key accessed (CloudTrail)[/red]")
    console.print(
        f"      [dim red]aws cloudtrail lookup-events --lookup-attributes "
        f"AttributeKey=Username,AttributeValue={key_id}[/dim red]"
    )
    console.print()

    console.print(f"  [bold red][3][/bold red] [red]Rotate secrets in blast radius (S3, Secrets Manager, RDS)[/red]")
    console.print(f"  [bold red][4][/bold red] [red]Apply least-privilege IAM — remove unused permissions[/red]")
    console.print(f"  [bold red][5][/bold red] [red]Enable MFA on root and privileged IAM users[/red]")
    console.print()

    if repo and file_path:
        console.print(f"  [bold red][6][/bold red] [red]Remove secret from git history[/red]")
        console.print(f"      [dim red]pip install git-filter-repo[/dim red]")
        console.print(f"      [dim red]git filter-repo --path {file_path} --invert-paths[/dim red]")
        console.print(f"      [dim red]# Or use BFG: bfg --replace-text passwords.txt {repo}[/dim red]")
        console.print()
        console.print(f"  [bold red][7][/bold red] [red]Enable GitHub secret scanning & push protection[/red]")
        console.print(f"      [dim red]https://github.com/{repo}/settings/security_analysis[/dim red]")
        console.print()

    console.print(f"  [bold red][8][/bold red] [red]Set CloudWatch alarm for future key misuse[/red]")
    console.print(f"      [dim red]Monitor: CreateAccessKey, AttachUserPolicy, GetSecretValue[/dim red]")
    console.print()

    if has_critical_actions:
        console.print("[bold red]  ⚠ CRITICAL ACTIONS DETECTED — treat as active breach. Escalate now.[/bold red]")
        console.print()
