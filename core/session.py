import uuid
from datetime import datetime

_case_id: str | None = None


def get_case_id() -> str:
    global _case_id
    if _case_id is None:
        date = datetime.now().strftime("%Y-%m-%d")
        suffix = uuid.uuid4().hex[:4].upper()
        _case_id = f"CASE-{date}-{suffix}"
    return _case_id
