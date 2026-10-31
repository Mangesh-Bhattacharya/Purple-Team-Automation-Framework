"""CI-friendly report formats.

JUnit XML is understood by Jenkins, GitLab, GitHub Actions summaries, Azure DevOps and most
other CI systems, so a detection regression can fail a pipeline like any other test.

Exit codes used by ``ptaf selftest`` (stable, documented in docs/enterprise.md):
    0  every runnable canary detected, no drift
    1  a detection gap or drift was found
    2  usage error (bad option, unknown canary id)
    3  sensor problem: a canary produced no telemetry or could not run (not a rule gap)
    4  another monitor already holds the state-directory lock
"""

from __future__ import annotations

from xml.etree import ElementTree as ET  # nosec B405 - only generates XML, never parses it

from .validation import SelfTestReport

EXIT_OK, EXIT_GAP, EXIT_USAGE, EXIT_SENSOR, EXIT_LOCKED = 0, 1, 2, 3, 4


def exit_code_for(report: SelfTestReport, drift: list[dict]) -> int:
    statuses = {r.status for r in report.results}
    if not report.results:
        return EXIT_SENSOR  # nothing was verified: that must never look like success
    if "missed" in statuses or drift:
        return EXIT_GAP
    if statuses & {"no_telemetry", "error"}:
        return EXIT_SENSOR
    return EXIT_OK


def to_junit(report: SelfTestReport) -> str:
    suite = ET.Element(
        "testsuite",
        name=f"ptaf-sentinel.{report.host.get('hostname', 'host')}",
        tests=str(len(report.results)),
        failures=str(sum(r.status == "missed" for r in report.results)),
        errors=str(sum(r.status in {"no_telemetry", "error"} for r in report.results)),
        timestamp=report.started,
    )
    for r in report.results:
        case = ET.SubElement(
            suite,
            "testcase",
            classname=f"ptaf.{r.technique_id}",
            name=r.name,
            time=str(r.duration_s),
        )
        if r.status == "missed":
            ET.SubElement(
                case, "failure", message="no detection fired", type="DetectionGap"
            ).text = r.detail
        elif r.status in {"no_telemetry", "error"}:
            ET.SubElement(case, "error", message=r.status, type="SensorProblem").text = r.detail
    return ET.tostring(ET.ElementTree(suite).getroot(), encoding="unicode", xml_declaration=False)
