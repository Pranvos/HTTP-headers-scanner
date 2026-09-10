"""
http_headers_scanner.py

This scans a HTTP url and gives a score of its HTTP security headers that ranges A-F
"""

import argparse  # Parses command-line arguments passed to the script
import re  # Provides regular expression matching for evaluating header values
import sys  # Handles system-specific functions and exit codes
from dataclasses import dataclass  # Decorator used to generate clean, structured data classes
from typing import Literal  # Defines fixed string options for type hinting (e.g., Severity and Status)

import httpx  # Makes HTTP requests to fetch web pages and response headers
from rich import box  # Provides table border styles (e.g., rounded borders)
from rich.console import Console  # Handles formatted printing to the terminal
from rich.panel import Panel  # Renders bordered display cards for summaries
from rich.table import Table  # Constructs colored Unicode tables for report findings

Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]


@dataclass(frozen=True, slots=True)
class HeaderRule:
    header: str
    severity: Severity
    description: str
    recommendation: str
    must_match: str | None = None


RULES: list[HeaderRule] = [
    HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        description="Enforces HTTPS connections",
        recommendation="Add STS with a positive max-age",
        must_match=r"max-age\s*=\s*[1-9]",
    ),
    HeaderRule(
        header="Content-Security-Policy",
        severity="high",
        description="Restricts sources of executable content",
        recommendation="Define a strict Content-Security-Policy",
    ),
    HeaderRule(
        header="Permissions Policy",
        severity="high",
        description="Restricts access to browser permissions(e.g. camera, microphone, and geolocation permissions)",
        recommendation="Define a Permissions-Policy header to restrict browser features (e.g., camera=(), microphone=(), geolocation=())"
    ),
# work on this
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


@dataclass(frozen=True, slots=True)
class ScanReport: 
    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding]

    @property
    def score(self) -> int:
        total = sum(SEVERITY_POINTS[r.severity] for r in RULES)
        if total == 0:
            return 0
        earned = 0.0
        for finding in self.findings:
            full = SEVERITY_POINTS[finding.rule.severity]
            if finding.status == "ok":
                earned += full
            elif finding.status == "weak":
                earned += full / 2
        return int((earned / total) * 100 + 0.5)

    @property
    def grade(self) -> str:
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 50:
            return "D"
        return "F"


def evaluate_header(
    rule: HeaderRule,
    response_headers: dict[str, str],
) -> HeaderFinding:
    target = rule.header.lower()

    actual_value: str | None = None
    for name, value in response_headers.items():
        if name.lower() == target:
            actual_value = value
            break

    if actual_value is None:
        return HeaderFinding(
            rule=rule,
            status="missing",
            actual_value=None,
            note=f"Header `{rule.header}` is not set",
        )

    if rule.must_match is None:
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note="Present",
        )

    if re.search(rule.must_match, actual_value, re.IGNORECASE):
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note=f"Present and matches `{rule.must_match}`",
        )

    return HeaderFinding(
        rule=rule,
        status="weak",
        actual_value=actual_value,
        note=(
            f"Present but does not match `{rule.must_match}` "
            f"(got `{actual_value}`)"
        ),
    )


# Parentheses string formatting replaces set curly braces
DEFAULT_USER_AGENT: str = (
    "http-headers-scanner/1.0 "
    "(+https://github.com/Pranvos/HTTP-headers-scanner)"
)


def scan(
    url: str, 
    *,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT
) -> ScanReport:
    response = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={
            "User-Agent": user_agent
        }, 
    )

    response_headers = dict(response.headers)
    findings = [evaluate_header(rule, response_headers) for rule in RULES]

    return ScanReport(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=findings
    )


GRADE_COLORS: dict[str, str] = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bright_red",
}


def render_report(report: ScanReport, console: Console) -> None:
    table = Table(title="HTTP-Headers Scanner", box=box.ROUNDED)
    table.add_column("Header", style="bold black")
    table.add_column("Severity", style="")
    table.add_column("Status", style="bold")
    table.add_column("Finding Note", style="dim underline")
    table.add_column("Recommendation", style="dim", min_width=50)

    for finding in report.findings:
        # Maps status to display colors
        if finding.status == "ok":
            status_color = "green"
        elif finding.status == "weak":
            status_color = "yellow"
        else:
            status_color = "red"

        # Determines severity colors
        if finding.status == "ok":
            severity_color = "green"
        elif finding.rule.severity == "high":
            severity_color = "bright_red"
        elif finding.rule.severity == "medium":
            severity_color = "yellow"
        else:
            severity_color = "bright_black"

        # Adds populated row to table
        table.add_row(
            finding.rule.header,
            f"[{severity_color}]{finding.rule.severity.upper()}[/{severity_color}]",
            f"[{status_color}]{finding.status.upper()}[/{status_color}]",
            finding.note,
            finding.rule.recommendation if finding.status != "ok" else "-",
        )

    #Print completed table outside the findings loop
    console.print(table)

    #Print HTTP warning outside loop
    if report.final_url.startswith("http://"):
        console.print(
            "[yellow]Note: this response was served over plain HTTP. "
            "Browsers IGNORE Strict-Transport-Security over HTTP.[/yellow]"
        )

    #Print report panel
    grade_color = GRADE_COLORS[report.grade]
    panel = Panel(
        f"[bold]Grade:[/bold] [{grade_color}]{report.grade}[/{grade_color}]\n"
        f"[bold]Score:[/bold] {report.score}/100\n"
        f"[bold]Target URL:[/bold] {report.url}\n"
        f"[bold]Final URL:[/bold] {report.final_url}\n"
        f"[bold]Status Code:[/bold] {report.status_code}",
        title="[bold]Scan Report[/bold]",
        border_style=grade_color,
    )
    console.print(panel)

    #Print actionable recommendations list
    actionable = [x for x in report.findings if x.status != "ok"]
    if actionable:
        console.print("\n[bold]Recommendations:[/bold]")
        for finding in actionable:
            console.print(
                f"[bold]{finding.rule.header}:[/bold] {finding.rule.recommendation}"
            )

def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headers",
        description="Scan a URL for HTTP security headers and grade the result A–F."
    )

    parser.add_argument(
        "url", 
        help="Full URL to scan (must include either http:// or https://)"
    )
    
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Seconds to wait before giving up on the request (default: 10).",
    )

    return parser


def main() -> int:
    #initializes the argument parser and processes commands
    parser = build_argument_parser()
    args = parser.parse_args()
    #attepts network request to scan target url for security headers
    try:
        report = scan(args.url, timeout=args.timeout)
    except httpx.RequestError as exc:
        print(f"Request failed: {type(exc).__name__}: {exc}")
        return 2 # 2 means failure
    else:
        console = Console()
        render_report(report, console)

        if report.grade in ("A", "B"):
            return 0 # 0 means success or high compliance
        if report.grade in ("C", "D"):
            return 1 # 1 means moderate warning or sub optimal compliance and configuration
        return 2

#ensures main() executes only when script is run directly from the terminal
if __name__ == "__main__":
    sys.exit(main())


    