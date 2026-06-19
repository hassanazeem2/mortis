import re
import boto3
import json
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

PATTERNS = {
    "AWS Access Key":  r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
    "AWS Secret Key":  r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Private Key":     r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Generic API Key": r"(?i)(api_key|apikey|api-key).{0,10}['\"][A-Za-z0-9_\-]{20,50}['\"]",
}

def get_client(config: dict):
    return boto3.client(
        "s3",
        aws_access_key_id=config["aws"]["access_key_id"],
        aws_secret_access_key=config["aws"]["secret_access_key"],
        region_name=config["aws"]["region"],
    )

def scan_menu(config: dict, console: Console):
    console.print("[red]━━━ S3 BUCKET SCANNER ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()

    try:
        s3 = get_client(config)
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])

        if not buckets:
            console.print("[red]  ✗ No S3 buckets found in this account.[/red]")
            console.print()
            return

        console.print(f"[red]  ✓ Found {len(buckets)} bucket(s)[/red]")
        console.print()

        table = Table(box=box.SIMPLE, border_style="red", header_style="bold red")
        table.add_column("#", style="dim red", width=4)
        table.add_column("Bucket Name", style="red")
        table.add_column("Created", style="dim red")

        for i, bucket in enumerate(buckets, 1):
            created = bucket["CreationDate"].strftime("%Y-%m-%d") if bucket.get("CreationDate") else "N/A"
            table.add_row(str(i), bucket["Name"], created)

        console.print(table)
        console.print()

        choice = Prompt.ask("[red]  Select bucket number (or 'all')[/red]")
        console.print()

        if choice.lower() == "all":
            all_findings = []
            for bucket in buckets:
                findings = scan_bucket(bucket["Name"], config, console, silent=True)
                all_findings.extend(findings)
            display_summary(all_findings, console)
        elif choice.isdigit() and 1 <= int(choice) <= len(buckets):
            bucket_name = buckets[int(choice) - 1]["Name"]
            scan_bucket(bucket_name, config, console)

    except NoCredentialsError:
        console.print("[red]  ✗ Invalid AWS credentials. Run mortis --setup[/red]")
    except ClientError as e:
        console.print(f"[red]  ✗ AWS error: {e.response['Error']['Message']}[/red]")
    except Exception as e:
        console.print(f"[red]  ✗ Error: {str(e)}[/red]")

def scan_bucket(bucket_name: str, config: dict, console: Console, silent: bool = False):
    findings = []

    try:
        s3 = get_client(config)

        if not silent:
            console.print(f"[red]  ▸ Scanning bucket:[/red] [bold red]{bucket_name}[/bold red]")
            console.print()

        # Check public access
        public_risk = check_public_access(s3, bucket_name, console, silent)

        # List objects
        paginator = s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket_name)

        scannable = [".env", ".json", ".yaml", ".yml", ".txt", ".conf", ".config", ".ini", ".sh", ".py", ".js", ".ts"]
        files_scanned = 0

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[red]{task.description}[/red]"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Scanning objects...", total=None)

            for page in pages:
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    progress.update(task, description=f"[red]Scanning {key[:60]}[/red]")

                    if not any(key.endswith(ext) for ext in scannable):
                        continue

                    try:
                        response = s3.get_object(Bucket=bucket_name, Key=key)
                        content = response["Body"].read().decode("utf-8", errors="ignore")
                        files_scanned += 1

                        for secret_type, pattern in PATTERNS.items():
                            for match in re.finditer(pattern, content):
                                line_num = content[:match.start()].count("\n") + 1
                                findings.append({
                                    "type": secret_type,
                                    "bucket": bucket_name,
                                    "key": key,
                                    "line": line_num,
                                    "match": match.group()[:60],
                                    "public_risk": public_risk,
                                    "discovered": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "size": obj.get("Size", 0),
                                    "last_modified": obj.get("LastModified", "").strftime("%Y-%m-%d") if obj.get("LastModified") else "N/A",
                                })
                    except Exception:
                        pass

        if not silent:
            display_findings(findings, files_scanned, bucket_name, console)

        return findings

    except ClientError as e:
        if not silent:
            console.print(f"[red]  ✗ Error scanning {bucket_name}: {e.response['Error']['Message']}[/red]")
        return []

def check_public_access(s3, bucket_name: str, console: Console, silent: bool) -> str:
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                if not silent:
                    console.print(f"[bold red]  ⚠ BUCKET IS PUBLICLY ACCESSIBLE — HIGH RISK[/bold red]")
                return "PUBLIC"
        return "PRIVATE"
    except:
        return "UNKNOWN"

def display_findings(findings: list, files_scanned: int, bucket_name: str, console: Console):
    console.print()
    console.print(f"[red]  ✓ Scanned {files_scanned} files in {bucket_name}[/red]")
    console.print()

    if not findings:
        console.print("[red]  ✓ No secrets detected.[/red]")
        console.print()
        return

    console.print(f"[bold red]  ⚠ {len(findings)} secret(s) found[/bold red]")
    console.print()

    table = Table(box=box.SIMPLE_HEAVY, border_style="red", header_style="bold red")
    table.add_column("TYPE", style="red", min_width=18)
    table.add_column("FILE", style="dim red", min_width=30)
    table.add_column("LINE", style="red", width=6)
    table.add_column("PUBLIC?", style="red", width=10)
    table.add_column("MATCH", style="dim red")

    for f in findings:
        pub_color = "bold red" if f["public_risk"] == "PUBLIC" else "red"
        table.add_row(
            f["type"],
            f["key"][-40:],
            str(f["line"]),
            f"[{pub_color}]{f['public_risk']}[/{pub_color}]",
            f["match"][:40],
        )

    console.print(table)
    console.print()

def display_summary(findings: list, console: Console):
    console.print(f"[bold red]  ⚠ TOTAL: {len(findings)} secret(s) across all buckets[/bold red]")
    console.print()
    display_findings(findings, 0, "all buckets", console)
