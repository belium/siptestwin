"""Regression comparison against an expected baseline report."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RegressionResult:
    passed: bool
    differences: list[str] = field(default_factory=list)


def compare_to_baseline(
    current: dict,
    baseline_path: str | Path,
    *,
    tolerate_latency: bool = True,
) -> RegressionResult:
    """Compare a current report dict to a stored baseline JSON report.

    Compares response-code categories and pass/fail counts, which are the
    stable, repeatable signals. Latency is informational and ignored unless
    ``tolerate_latency`` is False.
    """
    p = Path(baseline_path)
    if not p.is_file():
        return RegressionResult(False, [f"baseline not found: {p}"])
    baseline = json.loads(p.read_text(encoding="utf-8"))

    diffs: list[str] = []
    cur_cat = current.get("metrics", {}).get("response_by_category", {})
    base_cat = baseline.get("metrics", {}).get("response_by_category", {})
    for key in sorted(set(cur_cat) | set(base_cat)):
        if cur_cat.get(key, 0) != base_cat.get(key, 0):
            diffs.append(f"response {key}: baseline={base_cat.get(key, 0)} current={cur_cat.get(key, 0)}")

    cur_sum = current.get("summary", {})
    base_sum = baseline.get("summary", {})
    for key in ("passed", "failed"):
        if cur_sum.get(key) != base_sum.get(key):
            diffs.append(f"summary.{key}: baseline={base_sum.get(key)} current={cur_sum.get(key)}")

    if not tolerate_latency:
        cur_p95 = current.get("metrics", {}).get("latency", {}).get("p95_ms", 0)
        base_p95 = baseline.get("metrics", {}).get("latency", {}).get("p95_ms", 0)
        if base_p95 and cur_p95 > base_p95 * 1.5:
            diffs.append(f"latency p95 regressed: baseline={base_p95} current={cur_p95}")

    return RegressionResult(passed=not diffs, differences=diffs)
