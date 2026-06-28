import json
from datetime import datetime
from pathlib import Path

from core.session import get_case_id

CASES_DIR = Path.home() / ".mortis" / "cases"


def _case_path(case_id: str | None = None) -> Path:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    return CASES_DIR / f"{case_id or get_case_id()}.json"


def _empty_case() -> dict:
    return {
        "case_id": get_case_id(),
        "created": datetime.now().isoformat(),
        "updated": datetime.now().isoformat(),
        "findings": [],
        "key_health": {},
        "autopsies": [],
        "notes": [],
    }


def load_case(case_id: str | None = None) -> dict:
    path = _case_path(case_id)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return _empty_case()


def save_case(case: dict) -> Path:
    case["case_id"] = case.get("case_id") or get_case_id()
    case["updated"] = datetime.now().isoformat()
    path = _case_path(case["case_id"])
    with open(path, "w") as f:
        json.dump(case, f, indent=2, default=str)
    return path


def get_findings() -> list:
    return load_case().get("findings", [])


def add_findings(findings: list, source: str = "scan"):
    if not findings:
        return
    case = load_case()
    for f in findings:
        entry = dict(f)
        entry["source"] = source
        entry["recorded_at"] = datetime.now().isoformat()
        case["findings"].append(entry)
    save_case(case)


def set_key_health(key_id: str, status: dict):
    case = load_case()
    case["key_health"][key_id] = status
    save_case(case)


def add_autopsy_summary(summary: dict):
    case = load_case()
    case["autopsies"].append({**summary, "recorded_at": datetime.now().isoformat()})
    save_case(case)


def list_cases() -> list[str]:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    return sorted((p.stem for p in CASES_DIR.glob("CASE-*.json")), reverse=True)
