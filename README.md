# MORTIS
### AWS Credential Forensics Engine

> Hassan Azeem

MORTIS is an interactive CLI tool that scans GitHub repositories and S3 buckets for exposed AWS credentials, then forensically traces what those credentials accessed via CloudTrail — building a full blast radius report with remediation steps.

---

## Setup

### 1. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. AWS IAM Setup

Create a read-only IAM user with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "s3:ListAllMyBuckets",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:GetBucketAcl",
        "iam:ListUsers",
        "iam:ListRoles"
      ],
      "Resource": "*"
    }
  ]
}
```

### 3. GitHub PAT

Create a token at: https://github.com/settings/tokens
- Scope: `repo` (read access)

### 4. Run setup wizard

```bash
python mortis.py --setup
```

---

## Usage

```bash
# Interactive menu
python mortis.py

# Direct repo scan
python mortis.py --scan-repo hassanazeem2/aevix-backend

# Inspect specific key
python mortis.py --inspect AKIA0000000000000000
```

---

## Features

- **Exhumation** — GitHub & S3 scanning for 8 secret types (AWS keys, GitHub PATs, private keys, hardcoded passwords)
- **Exposure Clock** — Estimates days a secret has been in git history with composite risk score
- **Autopsy** — CloudTrail trace reconstructs attack timeline, blast radius map, and credential autopsy report
- **Burial** — Copy-paste remediation playbook (revoke, rotate, git history cleanup, GitHub secret scanning)
- **Case Files** — Every session gets a unique case ID (`CASE-2026-06-19-A3F2`) included in exports

---

## V2 Roadmap

- `--demo` mode with sanitized sample data (no AWS/GitHub creds needed)
- SARIF export for GitHub Advanced Security
- Live CloudTrail watch mode
- Org-wide hygiene dashboard across repos

---

## Stack

- Python 3.11+
- `typer` — CLI framework
- `rich` — Terminal UI (red theme)
- `boto3` — AWS SDK
- `PyGithub` — GitHub API
- `pyfiglet` — ASCII banners

---

## Author

Hassan Azeem — [hazeem.org](https://hazeem.org) | [github.com/hassanazeem2](https://github.com/hassanazeem2)
