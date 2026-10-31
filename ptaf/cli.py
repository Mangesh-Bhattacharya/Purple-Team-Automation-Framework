"""``python -m ptaf`` / ``ptaf`` command line."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import click

from . import state
from . import dashboard as dash
from .exports import badge, navigator_layer
from .fleet import load_fleet
from .monitor import Monitor
from .platform_info import collect_host_info
from .service import render
from .canaries import CANARIES, CANARY_TAG, canaries_for, unknown_ids
from .sensor import MODES, SensorUnavailable, default_mode
from .doctor import exit_code as doctor_exit
from .doctor import run_checks
from .reports import EXIT_LOCKED, EXIT_SENSOR, exit_code_for, to_junit
from .sigma_lite import check_rule
from .validation import load_rules, run_selftest

_rules_opt = click.option(
    "--rules",
    "rules_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Directory of Sigma rules (default: bundled rules).",
)


@click.group()
@click.version_option("0.2.0", prog_name="ptaf")
def main() -> None:
    """PTAF Sentinel: continuously prove your detections still fire."""


@main.command()
def info() -> None:
    """Show OS, architecture, VM and container context for this host."""
    click.echo(json.dumps(collect_host_info().to_dict(), indent=2))


_only_opt = click.option("--only", multiple=True, help="Run only this canary id (repeatable).")
_skip_opt = click.option("--skip", multiple=True, help="Skip this canary id (repeatable).")


def _validate_ids(only: tuple[str, ...], skip: tuple[str, ...]) -> None:
    bad = unknown_ids(only) + unknown_ids(skip)
    if bad:
        raise click.UsageError(f"unknown canary id(s): {', '.join(bad)} (see `ptaf canaries`)")


_collector_opt = click.option(
    "--collector",
    type=click.Choice(list(MODES)),
    default=None,
    help="Sensor: auto (default; event-driven on Linux as root), poll, or procconn. "
    "Env: PTAF_COLLECTOR.",
)


@main.command()
@_rules_opt
@_only_opt
@_skip_opt
@_collector_opt
@click.option("--json-out", "as_json", is_flag=True, help="Emit the full JSON report.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "junit"]),
    default=None,
    help="Output format (junit is for CI systems).",
)
def selftest(rules_dir, only, skip, collector, as_json, fmt) -> None:
    """Run benign canaries once and report which detections fired.

    Exit codes: 0 all detected; 1 gap or drift; 2 usage error; 3 sensor problem
    (no telemetry / could not run); 4 another monitor is running.
    """
    fmt = fmt or ("json" if as_json else "text")
    host = collect_host_info()
    _validate_ids(only, skip)
    rules, errors = load_rules(rules_dir)
    previous = state.load_previous()
    try:
        report = run_selftest(
            rules, errors, host, only=only, skip=skip, collector_mode=collector or default_mode()
        )
    except SensorUnavailable as exc:
        click.echo(f"ptaf: {exc}", err=True)
        raise SystemExit(EXIT_SENSOR)
    drift = state.compute_drift(previous, report)
    if not only and not skip:  # a filtered run must not overwrite the full baseline
        state.save(report)
    for d in drift:
        state.append_jsonl("alerts.jsonl", {**d, "host": host.hostname, "time": report.started})
    if fmt == "json":
        click.echo(json.dumps({**report.to_dict(), "drift": drift}, indent=2))
    elif fmt == "junit":
        click.echo(to_junit(report))
    else:
        vm = host.virtualization if host.virtualization != "none" else "bare metal"
        distro = f" {host.distro}" if host.distro else ""
        click.echo(f"PTAF Sentinel on {host.os}{distro} ({host.arch}, {vm})")
        if report.sensor:
            click.echo(f"Sensor: {report.sensor['name']}: {report.sensor['note']}")
        for r in report.results:
            click.echo(f"  [{r.status.upper():12}] {r.technique_id:10} {r.name}")
            if r.detail:
                click.echo(f"                 {r.detail}")
        for sk in report.skipped:
            click.echo(f"  [SKIPPED     ] {sk['id']}: {sk['reason']}")
        cov = report.coverage
        click.echo(f"Verified detection coverage: {'n/a' if cov is None else f'{cov:g}%'}")
        if not report.results:
            click.echo("  Nothing was verified (no canary could run with this sensor).", err=True)
        for d in drift:
            click.echo(f"  DRIFT: {d['technique_id']} {d['from']} -> {d['to']}", err=True)
        for e in errors:
            click.echo(f"  rule error: {e}", err=True)
    raise SystemExit(exit_code_for(report, drift))


@main.command()
@_rules_opt
@_only_opt
@_skip_opt
@_collector_opt
@click.option("--interval", default=3600, show_default=True, help="Seconds between self-tests.")
@click.option("--once", is_flag=True, help="Run a single cycle and exit.")
@click.option("--quiet", is_flag=True, help="Write alerts to disk only, not stdout.")
def monitor(rules_dir, only, skip, collector, interval: int, once: bool, quiet: bool) -> None:
    """Run as an agent: live rule matching + scheduled drift-detecting self-tests."""
    if interval < 30:
        raise click.UsageError("--interval must be at least 30 seconds")
    host = collect_host_info()
    _validate_ids(only, skip)
    rules, errors = load_rules(rules_dir)
    try:
        mon = Monitor(
            rules, errors, host, interval_s=interval, emit_stdout=not quiet,
            only=only, skip=skip, collector_mode=collector or default_mode(),
        )  # fmt: skip
    except SensorUnavailable as exc:
        click.echo(f"ptaf: {exc}", err=True)
        raise SystemExit(EXIT_SENSOR)
    try:
        mon.run(run_once=once)
    except state.AlreadyRunning as exc:
        click.echo(f"ptaf: {exc}", err=True)
        raise SystemExit(EXIT_LOCKED)


@main.command()
@click.option("--json-out", "as_json", is_flag=True, help="Machine-readable output.")
@_rules_opt
@_collector_opt
def doctor(rules_dir, collector, as_json: bool) -> None:
    """Preflight: can this machine run the agent, and how much can the sensor see?"""
    checks = run_checks(rules_dir, collector or default_mode())
    try:  # best effort: lets the dashboard show the last health check
        (state.state_dir() / "doctor.json").write_text(
            json.dumps(
                {
                    "time": datetime.now(timezone.utc).isoformat(),
                    "checks": [c.to_dict() for c in checks],
                }
            ),
            encoding="utf-8",
        )
    except OSError:
        pass
    if as_json:
        click.echo(json.dumps([c.to_dict() for c in checks], indent=2))
    else:
        icon = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}
        for c in checks:
            click.echo(f"[{icon[c.status]}] {c.name}: {c.detail}")
            if c.fix and c.status != "ok":
                click.echo(f"        fix: {c.fix}")
    raise SystemExit(doctor_exit(checks))


@main.command()
@click.option("--json-out", "as_json", is_flag=True)
@click.option(
    "--all-platforms", is_flag=True, help="List canaries for every OS, not just this one."
)
def canaries(as_json: bool, all_platforms: bool) -> None:
    """List exactly what a self-test will execute (for change-approval and SOC allowlisting).

    Nothing is run. Every canary is a local no-op; those that can carry it include the
    tag 'ptaf-canary' in their command line so test activity is recognisable.
    """
    host = collect_host_info()
    chosen = CANARIES if all_platforms else canaries_for(host.os)
    rows = [
        {
            "id": c.id, "technique": c.technique_id, "name": c.name,
            "platforms": list(c.platforms), "description": c.description,
            "command": " ".join(c.build_argv("<marker>")),
            "tagged": CANARY_TAG in " ".join(c.build_argv("<marker>")),
        }
        for c in chosen
    ]  # fmt: skip
    if as_json:
        click.echo(json.dumps({"tag": CANARY_TAG, "canaries": rows}, indent=2))
        return
    click.echo(f"Canary tag for SOC filters: {CANARY_TAG}\n")
    for r in rows:
        click.echo(f"{r['id']}  [{r['technique']}]  {','.join(r['platforms'])}")
        click.echo(f"    {r['description']}")
        click.echo(f"    runs: {r['command']}\n")


@main.group()
def rules() -> None:
    """Inspect Sigma rules."""


@rules.command("check")
@click.argument("directory", required=False,
                type=click.Path(exists=True, file_okay=False, path_type=Path))  # fmt: skip
@click.option("--json-out", "as_json", is_flag=True)
@click.option("--strict", is_flag=True, help="Exit 1 if any rule cannot run.")
def rules_check(directory: Path | None, as_json: bool, strict: bool) -> None:
    """Report which of your Sigma rules PTAF can actually run, and why not.

    Point it at any rule directory (e.g. a SigmaHQ checkout). Three verdicts:
    runnable, partial (uses fields PTAF does not collect), unsupported.
    """
    loaded, errors = load_rules(directory)
    verdicts = [check_rule(r) for r in loaded]
    counts = {
        v: sum(x.verdict == v for x in verdicts) for v in ("runnable", "partial", "unsupported")
    }
    if as_json:
        click.echo(json.dumps({"counts": counts, "load_errors": errors,
                               "rules": [vars(v) for v in verdicts]}, indent=2))  # fmt: skip
    else:
        for v in verdicts:
            if v.verdict != "runnable":
                click.echo(f"[{v.verdict.upper():11}] {Path(v.path).name}: {'; '.join(v.reasons)}")
        for e in errors:
            click.echo(f"[LOAD ERROR ] {e}")
        click.echo(f"\n{counts['runnable']} runnable, {counts['partial']} partial, "
                   f"{counts['unsupported']} unsupported, {len(errors)} failed to load "
                   f"(of {len(loaded) + len(errors)})")  # fmt: skip
    if strict and (counts["partial"] or counts["unsupported"] or errors):
        raise SystemExit(1)


@main.group()
def export() -> None:
    """Export the latest results."""


def _latest_report(rules_dir: Path | None):
    host = collect_host_info()
    rules, errors = load_rules(rules_dir)
    return rules, run_selftest(rules, errors, host)


@export.command("badge")
@_rules_opt
def export_badge(rules_dir: Path | None) -> None:
    """Print a shields.io endpoint JSON for a coverage badge."""
    _, report = _latest_report(rules_dir)
    click.echo(json.dumps(badge(report), indent=2))


@export.command("navigator")
@_rules_opt
def export_navigator(rules_dir: Path | None) -> None:
    """Print a MITRE ATT&CK Navigator layer (green/yellow/red)."""
    rules, report = _latest_report(rules_dir)
    click.echo(json.dumps(navigator_layer(report, rules), indent=2))


@export.command("summary")
def export_summary() -> None:
    """Print this host's dashboard summary as JSON (collect these for the organization view)."""
    click.echo(json.dumps(dash.build_summary(), indent=2))


@main.command()
@click.option(
    "--os",
    "os_name",
    type=click.Choice(["windows", "linux", "macos"]),
    default=None,
    help="Target OS (default: this host).",
)
@click.option("--interval", default=3600, show_default=True)
def service(os_name: str | None, interval: int) -> None:
    """Print a systemd unit / launchd plist / schtasks command for review."""
    click.echo(render(os_name or collect_host_info().os, interval_s=interval))


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address.")
@click.option("--port", default=8787, show_default=True)
@click.option("--demo", is_flag=True, help="Use clearly-labelled sample data (includes a fleet).")
@click.option(
    "--fleet",
    "fleet_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Directory of exported host summaries (`ptaf export summary`) for the organization view.",
)
@click.option(
    "--token",
    default=None,
    help="Access token (or env PTAF_DASHBOARD_TOKEN). REQUIRED when binding beyond localhost. "
    "Open the page as http://host:port/#token=VALUE (the fragment is never sent to servers).",
)
@click.option(
    "--export",
    "export_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write a self-contained HTML snapshot (for clients) and exit.",
)
def dashboard(host, port, demo, fleet_dir, token, export_path) -> None:
    """Plain-English dashboard: is the tool running, what's covered, what needs doing.

    Live on localhost, token-protected on a LAN, or exported as one HTML file to share.
    """
    token = token or os.environ.get("PTAF_DASHBOARD_TOKEN") or None
    if export_path:
        summary = dash.demo_summary() if demo else dash.build_summary()
        fleet = dash.demo_fleet() if demo else (load_fleet(fleet_dir) if fleet_dir else None)
        export_path.write_text(dash.render_html(summary, fleet), encoding="utf-8")
        click.echo(f"Wrote {export_path}")
        return
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise click.UsageError(
            "refusing to serve beyond localhost without an access token. "
            "Pass --token (or set PTAF_DASHBOARD_TOKEN)."
        )
    if token and len(token) < 12:
        raise click.UsageError("the access token must be at least 12 characters")
    dash.serve(host, port, demo, fleet_dir, token)
