"""GitLab CI adapter (slice S18).

Emits GitLab Codequality JSON from a FuzzReport. Framework middleware contract:
``to_codequality(report) -> list[dict]`` mirroring the S17 annotation contract.
Import-safe: stdlib only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pqblocks_tlsfuzz.report import Finding, FuzzReport, Severity


class GitLabCodequality:
    """GitLab codequality items derived from a FuzzReport."""

    def __init__(self, report: FuzzReport) -> None:
        self.report = report

    def render(self) -> list[dict[str, Any]]:
        """Render all findings as GitLab codequality JSON items."""
        items: list[dict[str, Any]] = []
        for finding in self.report.findings:
            severity_map = {
                Severity.CRITICAL: "critical",
                Severity.HIGH: "high",
                Severity.MEDIUM: "medium",
                Severity.LOW: "low",
                Severity.INFO: "info",
            }
            severity = severity_map.get(finding.severity, "info")
            rule_id = finding.clause.replace(" ", "-").replace(".", "-").replace("§", "").replace(",", "").lower()
            items.append({
                "type": "issue",
                "check_name": f"pqblocks-tlsfuzz/{finding.mutation_class.value}",
                "description": f"{finding.expected}: observed {finding.observed.value} — {finding.detail}",
                "categories": ["TLS", "PQC", "mutation"],
                "location": {
                    "path": f"mutation://{finding.mutation_id}",
                    "lines": {"begin": 1},
                },
                "severity": severity,
                "fingerprint": f"{rule_id}-{finding.mutation_id}",
            })
        return items


def to_codequality(report: FuzzReport) -> list[dict[str, Any]]:
    """Middleware entry point: convert a FuzzReport to GitLab codequality items."""
    return GitLabCodequality(report).render()


def emit_codequality_json(report: FuzzReport, path: Path | str) -> Path:
    """Write GitLab codequality JSON to ``path``. Returns the path written."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    items = to_codequality(report)
    out.write_text(json.dumps(items, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    return out


def write_gitlab_ci_yml(path: Path | str, *, docker_image: str = "python:3.12-slim") -> Path:
    """Write a minimal .gitlab-ci.yml template that runs pqblocks-tlsfuzz and uploads codequality."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    content = f"""stages:
  - test

pq-tls-fuzz:
  stage: test
  image: {docker_image}
  before_script:
    - pip install pqblocks-tlsfuzz
  script:
    - pqblocks-tlsfuzz fuzz --endpoint ${{PQ_TLSFUZZ_ENDPOINT:-localhost:8443}} --iterations 1000 --seed 42 --report /tmp/report.json
    - pqblocks-tlsfuzz report --from /tmp/report.json --format sarif --out /tmp/results.sarif
    - pqblocks-tlsfuzz report --from /tmp/report.json --format junit --out /tmp/results.xml
  artifacts:
    reports:
      codequality: /tmp/codequality.json
    paths:
      - /tmp/results.sarif
      - /tmp/results.xml
"""
    out.write_text(content, encoding="utf-8")
    return out