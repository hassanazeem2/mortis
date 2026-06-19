SEVERITY_BASE = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 5}

RISK_LABELS = [
    (85, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (0, "LOW"),
]


def compute_exposure_risk(
    severity: str,
    exposure_days: int = 0,
    is_public: bool = False,
    suspicious_events: int = 0,
) -> tuple[int, str]:
    score = SEVERITY_BASE.get(severity, 10)
    score += min(exposure_days, 90) * 0.5
    if is_public:
        score += 20
    score += min(suspicious_events, 20) * 2

    score = min(int(score), 100)

    label = "LOW"
    for threshold, name in RISK_LABELS:
        if score >= threshold:
            label = name
            break

    return score, label
