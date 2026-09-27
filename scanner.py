import re
from dataclasses import dataclass
from typing import Literal

import httpx

Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]


@dataclass(frozen=True, slots=True)
class HeaderRule:
    header: str
    severity: Severity
    description: str
    recommendation: str
    guide_url: str | None = None
    must_match: str | None = None


RULES: list[HeaderRule] = [
    HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        description="Forces HTTPS and prevents downgrade attacks.",
        recommendation="Add a Strict-Transport-Security header with a positive max-age.",
        guide_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        must_match=r"max-age\s*=\s*[1-9]",
    ),
    HeaderRule(
        header="Content-Security-Policy",
        severity="high",
        description="Limits executable sources to reduce XSS and injection risk.",
        recommendation="Define a restrictive Content-Security-Policy for scripts, styles, and resources.",
        guide_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    ),
    HeaderRule(
        header="Permissions-Policy",
        severity="medium",
        description="Controls access to browser features such as camera, microphone, and geolocation.",
        recommendation="Set Permissions-Policy to restrict unnecessary browser capabilities.",
        guide_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    ),
    HeaderRule(
        header="Cross-Origin-Opener-Policy",
        severity="low",
        description="Helps isolate top-level browsing contexts to reduce cross-origin issues.",
        recommendation="Set Cross-Origin-Opener-Policy to same-origin or same-origin-allow-popups where appropriate.",
        guide_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
        must_match=r"same-origin",
    ),
]


SEVERITY_POINTS: dict[Severity, int] = {
    "high": 30,
    "medium": 15,
    "low": 5,
}


@dataclass(frozen=True, slots=True)
class HeaderFinding:
    rule: HeaderRule
    status: Status
    actual_value: str | None
    note: str


def evaluate_header(rule: HeaderRule, response_headers: dict[str, str]) -> HeaderFinding:
    target = rule.header.lower()
    actual_value = next((value for name, value in response_headers.items() if name.lower() == target), None)

    if actual_value is None:
        return HeaderFinding(
            rule=rule,
            status="missing",
            actual_value=None,
            note=f"Header {rule.header} is not set.",
        )

    if rule.must_match is None:
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note="Header is present.",
        )

    if re.search(rule.must_match, actual_value, re.IGNORECASE):
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note=f"Header is present and matches the recommended pattern.",
        )

    return HeaderFinding(
        rule=rule,
        status="weak",
        actual_value=actual_value,
        note=f"Header is present but does not meet the recommended configuration.",
    )


def normalize_url(url: str) -> str:
    value = url.strip()
    if not value:
        raise ValueError("A URL is required.")
    if "://" not in value:
        value = "https://" + value
    return value


DEFAULT_USER_AGENT = "http-headers-scanner/1.0 (+https://example.com)"


def scan_url(url: str, timeout: float = 10.0) -> dict:
    normalized_url = normalize_url(url)

    response = httpx.get(
        normalized_url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": DEFAULT_USER_AGENT},
    )

    response_headers = {name.lower(): value for name, value in response.headers.items()}
    findings = [evaluate_header(rule, response_headers) for rule in RULES]

    total_points = sum(SEVERITY_POINTS[rule.severity] for rule in RULES)
    earned_points = 0
    for finding in findings:
        if finding.status == "ok":
            earned_points += SEVERITY_POINTS[finding.rule.severity]
        elif finding.status == "weak":
            earned_points += SEVERITY_POINTS[finding.rule.severity] / 2

    score = int((earned_points / total_points) * 100) if total_points else 0
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    passed = []
    weak = []
    missing = []
    recommendations = []

    for finding in findings:
        item = {
            "header": finding.rule.header,
            "severity": finding.rule.severity,
            "status": finding.status,
            "actual_value": finding.actual_value,
            "description": finding.rule.description,
            "recommendation": finding.rule.recommendation,
            "guide_url": finding.rule.guide_url,
            "note": finding.note,
        }

        if finding.status == "ok":
            passed.append(item)
        elif finding.status == "weak":
            weak.append(item)
        else:
            missing.append(item)

        if finding.status != "ok":
            recommendations.append({
                "header": finding.rule.header,
                "recommendation": finding.rule.recommendation,
                "severity": finding.rule.severity,
            })

    return {
        "url": normalized_url,
        "final_url": str(response.url),
        "status_code": response.status_code,
        "score": score,
        "grade": grade,
        "passed": passed,
        "weak": weak,
        "missing": missing,
        "recommendations": recommendations,
        "checks": [
            {
                "header": finding.rule.header,
                "severity": finding.rule.severity,
                "status": finding.status,
                "actual_value": finding.actual_value,
                "description": finding.rule.description,
                "recommendation": finding.rule.recommendation,
                "guide_url": finding.rule.guide_url,
                "note": finding.note,
            }
            for finding in findings
        ],
    }


if __name__ == "__main__":
    import json

    example_url = "https://example.com"
    print(json.dumps(scan_url(example_url), indent=2))
