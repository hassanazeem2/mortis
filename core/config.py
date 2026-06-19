import os
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

CONFIG_PATH = Path.home() / ".mortis" / "config.json"

def load_config():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return None

def save_config(config: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

def setup_wizard(console: Console):
    console.print(Panel(
        "[bold red]MORTIS SETUP WIZARD[/bold red]\n[dim red]Configure your AWS and GitHub credentials[/dim red]",
        border_style="red",
        padding=(1, 2)
    ))
    console.print()

    console.print("[red]━━━ AWS CONFIGURATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print("[dim red]  Create a read-only IAM user with CloudTrail + S3 read permissions[/dim red]")
    console.print()

    aws_key = Prompt.ask("[red]  AWS Access Key ID[/red]")
    aws_secret = Prompt.ask("[red]  AWS Secret Access Key[/red]", password=True)
    aws_region = Prompt.ask("[red]  AWS Region[/red]", default="us-east-1")

    console.print()
    console.print("[red]━━━ GITHUB CONFIGURATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/red]")
    console.print("[dim red]  Create a GitHub PAT with repo:read scope at github.com/settings/tokens[/dim red]")
    console.print()

    github_token = Prompt.ask("[red]  GitHub Personal Access Token[/red]", password=True)
    github_user = Prompt.ask("[red]  GitHub Username[/red]")

    config = {
        "aws": {
            "access_key_id": aws_key,
            "secret_access_key": aws_secret,
            "region": aws_region
        },
        "github": {
            "token": github_token,
            "username": github_user
        }
    }

    save_config(config)
    console.print()
    console.print("[red]  ✓ Configuration saved to ~/.mortis/config.json[/red]")
    console.print("[red]  ✓ MORTIS is ready.[/red]")
    console.print()
