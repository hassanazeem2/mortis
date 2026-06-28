import boto3
from botocore.exceptions import ClientError
from rich.console import Console


def check_key_health(key_id: str, config: dict, console: Console) -> dict:
    """Check if a leaked access key still exists and when it was last used."""
    console.print("[red]━━━ KEY HEALTH CHECK ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()

    result = {"key_id": key_id, "status": "unknown", "active": None, "last_used": None}

    try:
        iam = boto3.client(
            "iam",
            aws_access_key_id=config["aws"]["access_key_id"],
            aws_secret_access_key=config["aws"]["secret_access_key"],
            region_name=config["aws"]["region"],
        )
        response = iam.get_access_key_last_used(AccessKeyId=key_id)
        last_used = response.get("AccessKeyLastUsed", {})
        service = last_used.get("ServiceName", "Never")
        last_date = last_used.get("LastUsedDate")

        result["active"] = True
        result["status"] = "ACTIVE"
        result["last_used"] = last_date.isoformat() if last_date else None
        result["last_service"] = service

        console.print(f"  [red]Key status     :[/red] [bold red]ACTIVE — still enabled in IAM[/bold red]")
        console.print(f"  [red]Last used      :[/red] [red]{last_date.strftime('%Y-%m-%d %H:%M UTC') if last_date else 'Never'}[/red]")
        console.print(f"  [red]Last service   :[/red] [red]{service}[/red]")
        console.print()
        console.print("[bold red]  ⚠ Revoke this key immediately.[/bold red]")
        console.print()

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchEntity", "InvalidClientTokenId"):
            result["active"] = False
            result["status"] = "NOT_FOUND"
            console.print(f"  [red]Key status     :[/red] [red]Not found or already revoked[/red]")
        elif code == "AccessDenied":
            result["status"] = "ACCESS_DENIED"
            console.print("[dim red]  Could not check key — add iam:GetAccessKeyLastUsed to your IAM policy[/dim red]")
        else:
            result["status"] = "ERROR"
            console.print(f"[dim red]  Key health check failed: {e.response['Error']['Message']}[/dim red]")
        console.print()

    from core.case_store import set_key_health
    set_key_health(key_id, result)
    return result
