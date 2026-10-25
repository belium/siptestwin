"""Report generation: JSON, CSV and a human-readable console summary.

Reports never contain credential material (see :func:`siptestwin.safety.redact`).
"""

from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .metrics import Metrics


@dataclass
class CallRecord:
    """Outcome of a single scenario execution (one call/transaction run)."""

    index: int
    outcome: str                 # "passed" | "failed" | "timeout" | "error"
    final_code: int | None = None
    reason: str | None = None
    latency_ms: float | None = None
    steps_completed: int = 0


@dataclass
class RunResult:
    target: str
    scenario: str
    transport: str
    simulate: bool
    started_at: float
    finished_at: float = 0.0
    metrics: Metrics = field(default_factory=Metrics)
    calls: list[CallRecord] = field(default_factory=list)
    config_summary: dict = field(default_factory=dict)

    @property
    def duration_s(self) -> float:
        return round((self.finished_at or time.time()) - self.started_at, 3)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.calls if c.outcome == "passed")

    @property
    def failed(self) -> int:
        return sum(1 for c in self.calls if c.outcome != "passed")

    def to_dict(self) -> dict:
        return {
            "tool": "SIPTestWin",
            "target": self.target,
            "scenario": self.scenario,
            "transport": self.transport,
            "mode": "simulate" if self.simulate else "active",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.started_at)),
            "duration_seconds": self.duration_s,
            "summary": {
                "calls_total": len(self.calls),
                "passed": self.passed,
                "failed": self.failed,
            },
            "metrics": self.metrics.to_dict(),
            "calls": [vars(c) for c in self.calls],
            "config": self.config_summary,
        }


def write_reports(result: RunResult, output_dir: str | Path, formats: list[str]) -> list[Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(result.started_at))
    written: list[Path] = []

    if "json" in [f.lower() for f in formats]:
        p = out / f"report-{stamp}.json"
        p.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(p)

    if "csv" in [f.lower() for f in formats]:
        p = out / f"calls-{stamp}.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["index", "outcome", "final_code", "reason",
                             "latency_ms", "steps_completed"])
            for c in result.calls:
                writer.writerow([c.index, c.outcome, c.final_code or "",
                                 c.reason or "", c.latency_ms or "", c.steps_completed])
        written.append(p)

        pm = out / f"metrics-{stamp}.csv"
        with pm.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["metric", "value"])
            flat = result.metrics.to_dict()
            for key in ("messages_sent", "messages_received", "retransmissions",
                        "transport_errors", "timeouts", "calls_attempted",
                        "calls_established", "calls_terminated",
                        "transactions_completed", "transactions_failed"):
                writer.writerow([key, flat[key]])
            for cat, n in flat["response_by_category"].items():
                writer.writerow([f"responses_{cat}", n])
            for k, v in flat["latency"].items():
                writer.writerow([f"latency_{k}", v])
        written.append(pm)

    return written


def print_summary(result: RunResult, console: Console | None = None) -> None:
    console = console or Console()
    m = result.metrics.to_dict()

    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold")
    header.add_column()
    header.add_row("Target", result.target)
    header.add_row("Scenario", result.scenario)
    header.add_row("Transport", result.transport.upper())
    header.add_row("Mode", "SIMULATE (no packets sent)" if result.simulate else "ACTIVE")
    header.add_row("Duration", f"{result.duration_s}s")
    console.print(header)

    summary = Table(title="Result", show_header=True, header_style="bold")
    summary.add_column("Metric")
    summary.add_column("Value", justify="right")
    summary.add_row("Calls total", str(len(result.calls)))
    summary.add_row("[green]Passed[/green]", str(result.passed))
    summary.add_row("[red]Failed[/red]", str(result.failed))
    summary.add_row("Messages sent / received",
                    f"{m['messages_sent']} / {m['messages_received']}")
    summary.add_row("Retransmissions", str(m["retransmissions"]))
    summary.add_row("Timeouts", str(m["timeouts"]))
    summary.add_row("Transport errors", str(m["transport_errors"]))
    summary.add_row("Calls established / terminated",
                    f"{m['calls_established']} / {m['calls_terminated']}")
    console.print(summary)

    if m["response_by_category"]:
        rc = Table(title="Responses by category", header_style="bold")
        rc.add_column("Category")
        rc.add_column("Count", justify="right")
        for cat, n in m["response_by_category"].items():
            rc.add_row(cat, str(n))
        console.print(rc)

    lat = m["latency"]
    if lat["count"]:
        lt = Table(title="Latency (ms)", header_style="bold")
        for k in ("min_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms"):
            lt.add_column(k.replace("_ms", ""), justify="right")
        lt.add_row(*[str(lat[k]) for k in ("min_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms")])
        console.print(lt)

    if m["failure_reasons"]:
        fr = Table(title="Failure reasons", header_style="bold")
        fr.add_column("Reason")
        fr.add_column("Count", justify="right")
        for reason, n in m["failure_reasons"].items():
            fr.add_row(reason, str(n))
        console.print(fr)


def load_reports(input_dir: str | Path) -> list[dict]:
    """Load previously written JSON reports from a directory."""
    out = Path(input_dir)
    reports = []
    for p in sorted(out.glob("report-*.json")):
        try:
            reports.append(json.loads(p.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    return reports
