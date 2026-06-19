import boto3
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, NoCredentialsError
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from collections import defaultdict

def get_client(config: dict):
    return boto3.client(
        "cloudtrail",
        aws_access_key_id=config["aws"]["access_key_id"],
        aws_secret_access_key=config["aws"]["secret_access_key"],
        region_name=config["aws"]["region"],
    )

def scan_menu(config: dict, console: Console):
    console.print("[red]━━━ CLOUDTRAIL ANALYZER ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()
    console.print("[dim red]  Lookback window:[/dim red]")
    console.print("[red]  [1][/red] [red]Last 24 hours[/red]")
    console.print("[red]  [2][/red] [red]Last 7 days[/red]")
    console.print("[red]  [3][/red] [red]Last 30 days[/red]")
    console.print("[red]  [4][/red] [red]Custom date range[/red]")
    console.print("[red]  [0][/red] [dim red]Back[/dim red]")
    console.print()

    choice = Prompt.ask("[red]mortis/cloudtrail[/red]", default="0")
    console.print()

    now = datetime.utcnow()
    if choice == "1":
        start = now - timedelta(hours=24)
    elif choice == "2":
        start = now - timedelta(days=7)
    elif choice == "3":
        start = now - timedelta(days=30)
    elif choice == "4":
        days = Prompt.ask("[red]  Days back[/red]", default="14")
        start = now - timedelta(days=int(days))
    elif choice == "0":
        return
    else:
        return

    analyze_cloudtrail(config, console, start, now)

def analyze_cloudtrail(config: dict, console: Console, start: datetime, end: datetime):
    try:
        client = get_client(config)

        console.print(f"[red]  ▸ Querying CloudTrail:[/red] [dim red]{start.strftime('%Y-%m-%d')} → {end.strftime('%Y-%m-%d')}[/dim red]")
        console.print()

        events = []
        kwargs = {
            "StartTime": start,
            "EndTime": end,
            "MaxResults": 50,
        }

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[red]{task.description}[/red]"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Pulling CloudTrail events...", total=None)

            while True:
                response = client.lookup_events(**kwargs)
                events.extend(response.get("Events", []))
                progress.update(task, description=f"[red]Fetched {len(events)} events...[/red]")

                next_token = response.get("NextToken")
                if not next_token or len(events) >= 500:
                    break
                kwargs["NextToken"] = next_token

        display_cloudtrail_analysis(events, console)

    except NoCredentialsError:
        console.print("[red]  ✗ Invalid AWS credentials.[/red]")
    except ClientError as e:
        console.print(f"[red]  ✗ AWS error: {e.response['Error']['Message']}[/red]")
    except Exception as e:
        console.print(f"[red]  ✗ Error: {str(e)}[/red]")

def analyze_for_key(key_id: str, config: dict, console: Console, days: int = 30):
    """Analyze CloudTrail for a specific access key - used by forensics tracer"""
    try:
        client = get_client(config)

        end = datetime.utcnow()
        start = end - timedelta(days=days)

        events = []
        kwargs = {
            "StartTime": start,
            "EndTime": end,
            "LookupAttributes": [
                {"AttributeKey": "AccessKeyId", "AttributeValue": key_id}
            ],
            "MaxResults": 50,
        }

        while True:
            response = client.lookup_events(**kwargs)
            events.extend(response.get("Events", []))
            next_token = response.get("NextToken")
            if not next_token or len(events) >= 500:
                break
            kwargs["NextToken"] = next_token

        return events

    except Exception as e:
        console.print(f"[red]  ✗ CloudTrail query failed: {str(e)}[/red]")
        return []

def display_cloudtrail_analysis(events: list, console: Console):
    console.print(f"[red]  ✓ Retrieved {len(events)} events[/red]")
    console.print()

    if not events:
        console.print("[red]  No CloudTrail events found in this window.[/red]")
        return

    # Group by user/key
    by_user = defaultdict(list)
    by_action = defaultdict(int)
    suspicious = []

    SUSPICIOUS_ACTIONS = [
        "GetSecretValue", "ListUsers", "ListRoles", "ListBuckets",
        "GetObject", "PutObject", "DescribeInstances", "CreateUser",
        "AttachUserPolicy", "CreateAccessKey", "GetCallerIdentity",
        "AssumeRole", "GetSessionToken"
    ]

    for event in events:
        user = event.get("Username", "Unknown")
        action = event.get("EventName", "Unknown")
        by_user[user].append(event)
        by_action[action] += 1

        if action in SUSPICIOUS_ACTIONS:
            suspicious.append(event)

    # Display by user activity
    console.print("[red]━━━ ACTIVITY BY IDENTITY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()

    table = Table(box=box.SIMPLE_HEAVY, border_style="red", header_style="bold red")
    table.add_column("IDENTITY", style="red", min_width=30)
    table.add_column("EVENTS", style="red", width=8)
    table.add_column("RISK", style="red", width=12)

    for user, user_events in sorted(by_user.items(), key=lambda x: len(x[1]), reverse=True)[:15]:
        suspicious_count = sum(1 for e in user_events if e.get("EventName") in SUSPICIOUS_ACTIONS)
        risk = "CRITICAL" if suspicious_count > 10 else "HIGH" if suspicious_count > 5 else "MEDIUM" if suspicious_count > 0 else "LOW"
        risk_color = "bold red" if risk == "CRITICAL" else "red" if risk == "HIGH" else "dark_orange" if risk == "MEDIUM" else "dim red"
        table.add_row(user[:45], str(len(user_events)), f"[{risk_color}]{risk}[/{risk_color}]")

    console.print(table)
    console.print()

    # Top actions
    console.print("[red]━━━ TOP API CALLS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print()

    table2 = Table(box=box.SIMPLE, border_style="red", header_style="bold red")
    table2.add_column("ACTION", style="red", min_width=35)
    table2.add_column("COUNT", style="red", width=8)
    table2.add_column("SUSPICIOUS?", style="red", width=12)

    for action, count in sorted(by_action.items(), key=lambda x: x[1], reverse=True)[:15]:
        is_sus = "⚠ YES" if action in SUSPICIOUS_ACTIONS else "no"
        sus_color = "bold red" if action in SUSPICIOUS_ACTIONS else "dim red"
        table2.add_row(action, str(count), f"[{sus_color}]{is_sus}[/{sus_color}]")

    console.print(table2)
    console.print()

    if suspicious:
        console.print(f"[bold red]  ⚠ {len(suspicious)} suspicious API calls detected[/bold red]")
        console.print()
