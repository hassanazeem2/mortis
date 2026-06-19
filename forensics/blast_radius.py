from collections import defaultdict

SERVICE_MAP = {
    "GetObject": "S3",
    "PutObject": "S3",
    "DeleteObject": "S3",
    "ListBuckets": "S3",
    "PutBucketPolicy": "S3",
    "GetBucketPolicy": "S3",
    "ListUsers": "IAM",
    "ListRoles": "IAM",
    "CreateUser": "IAM",
    "CreateAccessKey": "IAM",
    "AttachUserPolicy": "IAM",
    "AssumeRole": "IAM",
    "GetCallerIdentity": "IAM",
    "GetSecretValue": "Secrets Manager",
    "ListSecrets": "Secrets Manager",
    "DescribeInstances": "EC2",
    "GetPasswordData": "EC2",
    "DescribeDBInstances": "RDS",
    "GetSessionToken": "STS",
}


def categorize_actions(by_action: dict) -> dict[str, dict[str, int]]:
    tree: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for action, count in by_action.items():
        service = SERVICE_MAP.get(action, "Other")
        tree[service][action] = count

    return dict(tree)


def render_blast_radius_tree(key_id: str, by_action: dict) -> str:
    tree = categorize_actions(by_action)
    if not tree:
        return ""

    lines = [f"Leaked Key ({key_id[:8]}…{key_id[-4:]})"]
    services = sorted(tree.keys(), key=lambda s: sum(tree[s].values()), reverse=True)

    for i, service in enumerate(services):
        is_last_service = i == len(services) - 1
        branch = "└──" if is_last_service else "├──"
        actions = tree[service]
        total = sum(actions.values())
        lines.append(f"    {branch} {service} ({total} calls)")

        action_items = sorted(actions.items(), key=lambda x: x[1], reverse=True)
        prefix = "        " if is_last_service else "    │   "
        for j, (action, count) in enumerate(action_items[:5]):
            is_last_action = j == len(action_items[:5]) - 1
            sub_branch = "└──" if is_last_action else "├──"
            lines.append(f"{prefix}{sub_branch} {action}: {count}")

    return "\n".join(lines)
