"""SIPTestWin command-line interface (Typer).

Commands:
    version           Print version information.
    validate-config   Load and strictly validate a configuration file.
    validate-scenario Parse and validate a scenario XML file.
    run               Execute a scenario (simulate by default; --execute to send).
    report            Summarize previously written JSON reports.
    testserver        Run the local loopback test SIP server.
    doctor            Diagnose the local environment (ports, imports, firewall).

Safety: ``run`` operates in SIMULATE mode unless ``--execute`` is given. An
active run requires the target to be on security.authorized_targets and prompts
for confirmation unless ``--yes`` is passed.
"""

from __future__ import annotations

import signal
import socket
import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from . import config as config_mod
from . import reporting, scenario_parser
from .capture import SipTracer
from .engine import Engine
from .netutils import list_local_ipv4
from .safety import (
    AuditLog,
    AuthorizationError,
    RunLimits,
    confirmation_prompt,
    ensure_authorized,
    redact_config,
)

app = typer.Typer(
    add_completion=False,
    help="SIPTestWin - authorized SIP interoperability / security testing for Windows.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_config_or_exit(path: Path, overrides: dict) -> config_mod.Config:
    try:
        cfg = config_mod.load(path)
    except config_mod.ConfigError as exc:
        err_console.print(f"[red]config error:[/red] {exc}")
        raise typer.Exit(2)
    _apply_overrides(cfg, overrides)
    errors = cfg.validate()
    if errors:
        err_console.print("[red]invalid configuration:[/red]")
        for e in errors:
            err_console.print(f"  - {e}")
        raise typer.Exit(2)
    return cfg


def _apply_overrides(cfg: config_mod.Config, overrides: dict) -> None:
    if overrides.get("host"):
        cfg.target.host = overrides["host"]
    if overrides.get("port"):
        cfg.target.port = overrides["port"]
    if overrides.get("transport"):
        cfg.target.transport = overrides["transport"]
    if overrides.get("scenario"):
        cfg.execution.scenario = overrides["scenario"]
    if overrides.get("calls"):
        cfg.execution.calls = overrides["calls"]
    if overrides.get("concurrency"):
        cfg.execution.concurrency = overrides["concurrency"]
    if overrides.get("call_rate"):
        cfg.execution.call_rate = overrides["call_rate"]
    if overrides.get("output_dir"):
        cfg.reporting.output_dir = overrides["output_dir"]
    if overrides.get("local_host"):
        cfg.execution.local_host = overrides["local_host"]
    if overrides.get("authorize"):
        for host in overrides["authorize"]:
            if host not in cfg.security.authorized_targets:
                cfg.security.authorized_targets.append(host)


def _build_tracer(cfg, capture, pcap, trace_console, trace_full, trace_file):
    """Construct a SipTracer from config + CLI flags, or None if tracing off."""
    cap = cfg.capture
    cli_requested = capture or pcap or trace_console
    if not (cap.enabled or cli_requested):
        return None

    console_on = trace_console or (cap.enabled and cap.console)
    console_full = trace_full or (cap.enabled and cap.console_full)
    text_on = capture or (cap.enabled and cap.text)
    pcap_on = pcap or (cap.enabled and cap.pcap)
    # If tracing is on but no sink resolved (e.g. bare config enabled), default to text.
    if not (console_on or text_on or pcap_on):
        text_on = True

    base = trace_file or cap.file or \
        str(Path(cfg.reporting.output_dir) / f"trace-{time.strftime('%Y%m%d-%H%M%S')}")
    text_path = f"{base}.trace.log" if text_on else None
    pcap_path = f"{base}.pcap" if pcap_on else None
    return SipTracer(
        to_console=console_on,
        text_path=text_path,
        pcap_path=pcap_path,
        console_full=console_full,
        console_print=lambda m: console.print(m, highlight=False, soft_wrap=True),
    )


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Print version information."""
    console.print(f"SIPTestWin {__version__}  (python {sys.version.split()[0]})")


@app.command("validate-config")
def validate_config(
    config: Path = typer.Option(..., "--config", "-c", exists=True, help="YAML/JSON config file."),
) -> None:
    """Load and strictly validate a configuration file."""
    cfg = _load_config_or_exit(config, {})
    console.print("[green]OK[/green] configuration is valid.")
    console.print_json(data=redact_config(cfg))


@app.command("validate-scenario")
def validate_scenario(
    file: Path = typer.Option(..., "--file", "-f", exists=True, help="Scenario XML file."),
) -> None:
    """Parse and validate a scenario XML file."""
    try:
        scenario = scenario_parser.parse_file(file)
    except scenario_parser.ScenarioError as exc:
        err_console.print(f"[red]scenario error:[/red] {exc}")
        raise typer.Exit(2)
    console.print(f"[green]OK[/green] scenario '{scenario.name}' is valid.")
    console.print(f"  flow: {scenario.summary()}")


@app.command()
def run(
    config: Path = typer.Option(..., "--config", "-c", exists=True, help="YAML/JSON config file."),
    execute: bool = typer.Option(False, "--execute", help="Send real packets (default is simulate)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the active-run confirmation prompt."),
    host: str = typer.Option(None, "--host", help="Override target host."),
    port: int = typer.Option(None, "--port", help="Override target port."),
    transport: str = typer.Option(None, "--transport", help="Override transport (udp/tcp/tls)."),
    scenario: str = typer.Option(None, "--scenario", help="Override scenario file path."),
    calls: int = typer.Option(None, "--calls", help="Override number of calls."),
    concurrency: int = typer.Option(None, "--concurrency", help="Override concurrency."),
    call_rate: float = typer.Option(None, "--call-rate", help="Override call rate (calls/s)."),
    local_host: str = typer.Option(None, "--local-host",
                                   help="Source IP for Via/Contact/bind (see 'interfaces')."),
    authorize: list[str] = typer.Option(None, "--authorize",
                                        help="Add a host/CIDR to the authorized-targets allow-list."),
    output_dir: str = typer.Option(None, "--output-dir", help="Override report output directory."),
    capture: bool = typer.Option(False, "--capture", help="Trace SIP messages to a .trace.log file."),
    pcap: bool = typer.Option(False, "--pcap", help="Also write a Wireshark-openable .pcap."),
    trace_console: bool = typer.Option(False, "--trace-console", help="Print each SIP message line to the console."),
    trace_full: bool = typer.Option(False, "--trace-full", help="With --trace-console, print full messages."),
    trace_file: str = typer.Option(None, "--trace-file", help="Base path for trace/pcap output."),
) -> None:
    """Execute a scenario. SIMULATE by default; use --execute to transmit."""
    overrides = {
        "host": host, "port": port, "transport": transport, "scenario": scenario,
        "calls": calls, "concurrency": concurrency, "call_rate": call_rate,
        "output_dir": output_dir, "authorize": authorize, "local_host": local_host,
    }
    cfg = _load_config_or_exit(config, overrides)

    try:
        parsed = scenario_parser.parse_file(cfg.execution.scenario)
    except scenario_parser.ScenarioError as exc:
        err_console.print(f"[red]scenario error:[/red] {exc}")
        raise typer.Exit(2)

    simulate = not execute
    limits = RunLimits.from_config(cfg)

    if not simulate:
        try:
            ensure_authorized(cfg)
        except AuthorizationError as exc:
            err_console.print(f"[red]authorization error:[/red] {exc}")
            raise typer.Exit(3)
        console.print(confirmation_prompt(cfg, limits))
        if not yes:
            if not typer.confirm("Proceed with this ACTIVE test?", default=False):
                console.print("aborted.")
                raise typer.Exit(1)

    tracer = _build_tracer(cfg, capture, pcap, trace_console, trace_full, trace_file)
    engine = Engine(cfg, parsed, simulate=simulate, tracer=tracer,
                    on_log=lambda m: console.print(f"[dim]{m}[/dim]"))

    # Ctrl+C -> graceful stop.
    def _sigint(_signum, _frame):
        err_console.print("\n[yellow]stopping (Ctrl+C)...[/yellow]")
        engine.stop()
    signal.signal(signal.SIGINT, _sigint)

    audit = AuditLog(cfg.reporting.output_dir)
    if not simulate:
        audit.record("run_start", cfg, {"limits": vars(limits)})

    mode = "SIMULATE (no packets)" if simulate else "ACTIVE"
    console.rule(f"SIPTestWin run - {mode}")
    result = engine.run()
    if tracer is not None:
        tracer.close()
    result.config_summary = redact_config(cfg)

    reporting.print_summary(result, console)
    written = reporting.write_reports(result, cfg.reporting.output_dir, cfg.reporting.formats)
    for p in written:
        console.print(f"[green]report:[/green] {p}")
    if tracer is not None:
        for p in tracer.paths():
            console.print(f"[green]trace:[/green] {p}")
    if not simulate:
        audit.record("run_end", cfg, {
            "passed": result.passed, "failed": result.failed,
            "duration_s": result.duration_s,
        })

    raise typer.Exit(0 if result.failed == 0 else 4)


@app.command()
def report(
    input: Path = typer.Option(..., "--input", "-i", exists=True, help="Directory of JSON reports."),
) -> None:
    """Summarize previously written JSON reports."""
    reports = reporting.load_reports(input)
    if not reports:
        err_console.print("[yellow]no report-*.json files found[/yellow]")
        raise typer.Exit(1)
    for r in reports:
        s = r.get("summary", {})
        console.print(f"[bold]{r.get('scenario')}[/bold] vs {r.get('target')} "
                      f"({r.get('mode')}) -> passed={s.get('passed')} failed={s.get('failed')} "
                      f"[{r.get('started_at')}]")


@app.command()
def testserver(
    host: str = typer.Option("127.0.0.1", help="Bind host (loopback by default)."),
    port: int = typer.Option(5060, help="Bind port."),
    transport: str = typer.Option("udp", help="udp or tcp."),
    require_auth: bool = typer.Option(False, "--require-auth", help="Require Digest auth."),
) -> None:
    """Run the local loopback test SIP server (for lab validation)."""
    from .testserver import TestSIPServer
    server = TestSIPServer(host=host, port=port, transport=transport, require_auth=require_auth)
    server.start()
    console.print(f"[green]test server listening[/green] on {host}:{server.port}/{transport} "
                  f"(auth={'on' if require_auth else 'off'}); Ctrl+C to stop")
    try:
        signal.pause() if hasattr(signal, "pause") else _wait_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        console.print("stopped.")


def _wait_forever() -> None:
    import time
    while True:
        time.sleep(1)


@app.command()
def interfaces() -> None:
    """List local IPv4 addresses available to trace / bind as source IP."""
    addrs = list_local_ipv4()
    table = Table(title="Local IPv4 addresses", header_style="bold")
    table.add_column("IP")
    table.add_column("Type")
    for a in addrs:
        table.add_row(a.ip, a.label)
    console.print(table)
    console.print("Pick one with:  run --local-host <IP>   "
                  "(or set execution.local_host in the config).")


@app.command()
def doctor() -> None:
    """Diagnose the local environment for SIP testing on Windows."""
    ok = True
    console.rule("SIPTestWin doctor")

    pyver = sys.version_info
    if pyver >= (3, 12):
        console.print(f"[green]OK[/green] Python {pyver.major}.{pyver.minor}.{pyver.micro}")
    else:
        ok = False
        console.print(f"[red]FAIL[/red] Python >= 3.12 required, found {pyver.major}.{pyver.minor}")

    for mod in ("yaml", "typer", "rich"):
        try:
            __import__(mod)
            console.print(f"[green]OK[/green] import {mod}")
        except ImportError:
            ok = False
            console.print(f"[red]FAIL[/red] cannot import {mod}")

    # Can we bind a UDP socket (needed to receive responses)?
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        bound = s.getsockname()[1]
        s.close()
        console.print(f"[green]OK[/green] UDP bind works (ephemeral port {bound})")
    except OSError as exc:
        ok = False
        console.print(f"[red]FAIL[/red] UDP bind failed: {exc}")

    console.print()
    console.print("[bold]Windows firewall note:[/bold] inbound SIP responses may be blocked by "
                  "Windows Defender Firewall. If responses time out, allow Python/siptestwin.exe "
                  "for the active network profile, or test against the local testserver first.")
    console.print("[bold]Ports:[/bold] SIP commonly uses UDP/TCP 5060 and TLS 5061. Binding low "
                  "ports is not required for a client; the OS assigns an ephemeral source port.")
    raise typer.Exit(0 if ok else 1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
