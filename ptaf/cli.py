"""``python -m ptaf`` / ``ptaf`` command line."""

from __future__ import annotations

import json
from pathlib import Path

import click

from . import state
from . import dashboard as dash
from .exports import badge, navigator_layer
from .monitor import Monitor
from .platform_info import collect_host_info
from .service import render
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


@main.command()
@_rules_opt
@click.option("--json-out", "as_json", is_flag=True, help="Emit the full JSON report.")
def selftest(rules_dir: Path | None, as_json: bool) -> None:
    """Run benign canaries once and report which detections fired."""
    host = collect_host_info()
    rules, errors = load_rules(rules_dir)
    previous = state.load_previous()
    report = run_selftest(rules, errors, host)
    drift = state.compute_drift(previous, report)
    state.save(report)
    for d in drift:
        state.append_jsonl("alerts.jsonl", {**d, "host": host.hostname, "time": report.started})
    if as_json:
        click.echo(json.dumps({**report.to_dict(), "drift": drift}, indent=2))
    else:
        vm = host.virtualization if host.virtualization != "none" else "bare metal"
        click.echo(f"PTAF Sentinel on {host.os} ({host.arch}, {vm})")
        for r in report.results:
            click.echo(f"  [{r.status.upper():12}] {r.technique_id:10} {r.name}")
            if r.detail:
                click.echo(f"                 {r.detail}")
        cov = report.coverage
        click.echo(f"Verified detection coverage: {'n/a' if cov is None else f'{cov:g}%'}")
        for d in drift:
            click.echo(f"  DRIFT: {d['technique_id']} {d['from']} -> {d['to']}", err=True)
        for e in errors:
            click.echo(f"  rule error: {e}", err=True)
    if drift or any(r.status == "missed" for r in report.results):
        raise SystemExit(1)


@main.command()
@_rules_opt
@click.option("--interval", default=3600, show_default=True, help="Seconds between self-tests.")
@click.option("--once", is_flag=True, help="Run a single cycle and exit.")
@click.option("--quiet", is_flag=True, help="Write alerts to disk only, not stdout.")
def monitor(rules_dir: Path | None, interval: int, once: bool, quiet: bool) -> None:
    """Run as an agent: live rule matching + scheduled drift-detecting self-tests."""
    host = collect_host_info()
    rules, errors = load_rules(rules_dir)
    Monitor(rules, errors, host, interval_s=interval, emit_stdout=not quiet).run(run_once=once)


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
@click.option("--demo", is_flag=True, help="Use clearly-labelled sample data.")
@click.option(
    "--export",
    "export_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write a self-contained HTML snapshot (for clients) and exit.",
)
def dashboard(host: str, port: int, demo: bool, export_path: Path | None) -> None:
    """Plain-English dashboard: live on localhost, or an HTML snapshot to share."""
    if export_path:
        summary = dash.demo_summary() if demo else dash.build_summary()
        export_path.write_text(dash.render_html(summary), encoding="utf-8")
        click.echo(f"Wrote {export_path}")
        return
    if host not in ("127.0.0.1", "localhost", "::1"):
        click.echo("WARNING: dashboard has no authentication; binding beyond localhost.", err=True)
    dash.serve(host, port, demo)
