"""GitHub Actions adapter (slice S17).

Emits a SARIF 2.1.0 file and ``::error file=...,title=...::`` annotations
from a FuzzReport. Framework middleware contract: ``to_annotations(report)
-> list[str]``. Import-safe: no third-party deps beyond stdlib.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pqblocks_tlsfuzz.report import Finding, FuzzReport, Severity


class GHActionAnnotations:
    """GitHub Actions annotation lines derived from a FuzzReport."""

    def __init__(self, report: FuzzReport) -> None:
        self.report = report

    def render(self) -> list[str]:
        """Render all findings as ``::error`` / ``::warning`` annotation lines."""
        lines: list[str] = []
        for finding in self.report.findings:
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                level = "error"
            else:
                level = "warning"
            rule_id = finding.clause.replace(" ", "-").replace(".", "-").replace("§", "").replace(",", "").lower()
            message = (
                f"{finding.mutation_id} | {finding.expected} | "
                f"observed {finding.observed.value} | clause {finding.clause}"
            )
            lines.append(
                f"::{level} file={rule_id},title={finding.mutation_id}::{message}"
            )
        return lines


def to_annotations(report: FuzzReport) -> list[str]:
    """Middleware entry point: convert a FuzzReport to GH Actions annotation strings."""
    return GHActionAnnotations(report).render()


def emit_sarif(report: FuzzReport, path: Path | str) -> Path:
    """Write SARIF 2.1.0 output from a FuzzReport to ``path``. Returns the path written."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    rules: dict[str, dict[str, Any]] = {}
    for finding in report.findings:
        if finding.clause not in rules:
            rules[finding.clause] = {
                "id": finding.clause.replace(" ", "-").replace(".", "-").replace("§", "").replace(",", "").lower(),
                "name": finding.clause,
                "shortDescription": {"text": finding.clause},
                "fullDescription": {"text": finding.detail},
                "defaultConfiguration": {"level": finding.severity.value},
            }

    results: list[dict[str, Any]] = []
    for finding in report.findings:
        rule_id = finding.clause.replace(" ", "-").replace(".", "-").replace("§", "").replace(",", "").lower()
        level = "error" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": finding.detail},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"mutation://{finding.mutation_id}"},
                    "region": {"startLine": 1},
                }
            }],
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pqblocks-tlsfuzz",
                    "version": report.fuzz_tlsfuzz_version,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    out.write_text(json.dumps(sarif, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    return out


def emit_annotations_file(report: FuzzReport, path: Path | str) -> Path:
    """Write ``::error`` / ``::warning`` annotation lines to ``path``."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = to_annotations(report)
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return out