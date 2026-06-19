"""Sanitized sample data for --demo mode. No real credentials."""

from datetime import datetime, timedelta

DEMO_KEY = "AKIA0000000000000000"

DEMO_FINDINGS = [
    {
        "type": "AWS Access Key",
        "severity": "CRITICAL",
        "repo": "acme-corp/backend-api",
        "file": "config/.env.production",
        "line": 14,
        "match": "AKIA0000000000000000",
        "commit_count": 847,
        "repo_url": "https://github.com/acme-corp/backend-api",
        "discovered": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "exposure_days": 47,
        "is_public": True,
        "still_in_head": True,
        "first_commit_sha": "a1b2c3d4e5f6789012345678abcdef0123456789",
        "first_commit_author": "dev-bot",
        "first_seen_date": "2026-04-03 09:14 UTC",
        "risk_score": 91,
        "risk_label": "CRITICAL",
    },
    {
        "type": "AWS Secret Key",
        "severity": "CRITICAL",
        "repo": "acme-corp/backend-api",
        "file": "config/.env.production",
        "line": 15,
        "match": "aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCY...'",
        "commit_count": 847,
        "repo_url": "https://github.com/acme-corp/backend-api",
        "discovered": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "exposure_days": 47,
        "is_public": True,
        "still_in_head": True,
        "first_commit_sha": "a1b2c3d4e5f6789012345678abcdef0123456789",
        "first_commit_author": "dev-bot",
        "first_seen_date": "2026-04-03 09:14 UTC",
        "risk_score": 88,
        "risk_label": "CRITICAL",
    },
]

DEMO_EXPOSURE_CONTEXT = {
    "repo": "acme-corp/backend-api",
    "file": "config/.env.production",
    "line": 14,
    "first_commit_sha": "a1b2c3d4e5f6789012345678abcdef0123456789",
    "first_commit_author": "dev-bot",
    "first_seen_date": "2026-04-03 09:14 UTC",
    "exposure_days": 47,
    "is_public": True,
    "still_in_head": True,
}


def build_demo_cloudtrail_events() -> list:
    """Build fake CloudTrail events matching the real lookup_events response shape."""
    now = datetime.utcnow()
    actions = [
        ("GetCallerIdentity", "recon", 1),
        ("ListBuckets", "s3-prod-backups", 3),
        ("ListBuckets", "s3-customer-data", 3),
        ("GetObject", "s3-customer-data/exports/users.csv", 8),
        ("GetObject", "s3-customer-data/exports/orders.csv", 4),
        ("ListUsers", "iam", 2),
        ("ListRoles", "iam", 2),
        ("ListSecrets", "secrets-manager", 1),
        ("GetSecretValue", "prod/database/credentials", 2),
        ("DescribeInstances", "ec2", 3),
    ]

    ips = ["185.220.101.45", "198.98.51.237", "45.142.214.89"]
    events = []

    for i, (action, resource, count) in enumerate(actions):
        for j in range(count):
            event_time = now - timedelta(days=12 - (i % 8), hours=j * 2, minutes=17)
            ip = ips[j % len(ips)]
            events.append({
                "EventTime": event_time,
                "EventName": action,
                "Username": DEMO_KEY,
                "Resources": [{"ResourceName": resource}],
                "CloudTrailEvent": (
                    f'{{"sourceIPAddress": "{ip}", "userAgent": "aws-cli/2.15.0", '
                    f'"eventName": "{action}"}}'
                ),
            })

    events.sort(key=lambda e: e["EventTime"])
    return events
