"""Report types for pqblocks_tlsfuzz (slice S9).

FuzzReport, Finding, Severity with JSON, JUnit, SARIF, JSONL writers.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pqblocks_tlsfuzz.constants import Group
from pqblocks_tlsfuzz.corpus import MutationClass
from pqblocks_tlsfuzz.transport import HandshakeOutcome, OutcomeClass


class Severity(str, Enum):
    """Finding severity levels (spec §1.3)."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """A single finding from the fuzz campaign (spec §1.3)."""
    mutation_id: str
    group: Group
    mutation_class: MutationClass
    severity: Severity
    expected: str
    observed: OutcomeClass
    clause: str
    detail: str


@dataclass(frozen=True)
class FuzzReport:
    """Complete fuzz campaign report (spec §1.3, §6.3)."""
    target: str
    started_utc: str
    fuzz_tlsfuzz_version: str
    outcomes: tuple[HandshakeOutcome, ...]
    findings: tuple[Finding, ...]
    p95_latency_ms: float
    false_positive_rate: float | None
    
    def to_json(self) -> str:
        """Serialize to JSON (schema v1, config_version=1)."""
        import json
        
        def outcome_to_dict(o: HandshakeOutcome) -> dict[str, Any]:
            return {
                "mutation_id": o.mutation_id,
                "group": str(o.mutation_id.split("-")[0]) if "-" in o.mutation_id else "",
                "mutation_class": o.mutation_id.split("-")[1] if "-" in o.mutation_id else "",
                "outcome": o.outcome.value,
                "latency_ms": o.latency_ms,
                "alert_description": o.alert_description,
                "bytes_captured": o.bytes_captured,
                "negotiated_group": o.negotiated_group,
                "detail": o.detail,
            }
        
        def finding_to_dict(f: Finding) -> dict[str, Any]:
            return {
                "mutation_id": f.mutation_id,
                "group": f.group.value,
                "mutation_class": f.mutation_class.value,
                "severity": f.severity.value,
                "expected": f.expected,
                "observed": f.observed.value,
                "clause": f.clause,
                "detail": f.detail,
            }
        
        # Build outcome histogram
        histogram: dict[str, int] = {}
        for o in self.outcomes:
            histogram[o.outcome.value] = histogram.get(o.outcome.value, 0) + 1
        
        report = {
            "target": self.target,
            "started_utc": self.started_utc,
            "pqblocks_tlsfuzz_version": self.fuzz_tlsfuzz_version,
            "config": {
                "config_version": 1,
            },
            "outcomes": [outcome_to_dict(o) for o in self.outcomes],
            "findings": [finding_to_dict(f) for f in self.findings],
            "p95_latency_ms": self.p95_latency_ms,
            "false_positive_rate": self.false_positive_rate,
            "outcome_histogram": histogram,
        }
        return json.dumps(report, separators=(",", ":"), sort_keys=True)
    
    def to_junit(self) -> str:
        """Serialize to JUnit XML (xunit 1.0 schema)."""
        import xml.etree.ElementTree as ET
        
        testsuite = ET.Element("testsuite")
        testsuite.set("name", "pqblocks-tlsfuzz")
        testsuite.set("tests", str(len(self.outcomes)))
        
        failures = sum(1 for f in self.findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
        testsuite.set("failures", str(failures))
        testsuite.set("errors", "0")
        testsuite.set("skipped", "0")
        testsuite.set("time", f"{self.p95_latency_ms / 1000.0:.3f}")
        
        for outcome in self.outcomes:
            testcase = ET.SubElement(testsuite, "testcase")
            testcase.set("name", outcome.mutation_id)
            # classname from mutation_id prefix
            classname = outcome.mutation_id.split("-")[0] if "-" in outcome.mutation_id else "unknown"
            testcase.set("classname", classname)
            testcase.set("time", f"{outcome.latency_ms / 1000.0:.6f}")
            
            # Check if this outcome has a finding
            finding = next((f for f in self.findings if f.mutation_id == outcome.mutation_id), None)
            if finding and finding.severity in (Severity.CRITICAL, Severity.HIGH):
                failure = ET.SubElement(testcase, "failure")
                failure.set("message", finding.detail)
                failure.set("type", finding.severity.value)
                failure.text = (
                    f"Expected: {finding.expected}, Observed: {finding.observed.value}, "
                    f"Clause: {finding.clause}"
                )
        
        # Pretty print
        ET.indent(testsuite, space="  ")
        xml_str = ET.tostring(testsuite, encoding="unicode", xml_declaration=True).strip()
        xml_str = xml_str.replace("<?xml version='1.0' encoding='utf-8'?>", '<?xml version="1.0" encoding="utf-8"?>')
        if xml_str.endswith("/>"):
            xml_str = xml_str[:-2] + "></testsuite>"
        return xml_str
    
    def to_sarif(self) -> str:
        """Serialize to SARIF 2.1.0 (ruleId = oracle clause id)."""
        import json
        
        # Build rules from findings (unique clauses)
        def _rule_id(clause: str) -> str:
            s = clause.strip()
            if s.startswith("§"):
                s = "section-" + s[1:].lstrip()
            return s.replace("§", "").replace(" ", "-").replace(".", "-").replace(",", "").lower()

        rules: dict[str, dict[str, Any]] = {}
        for finding in self.findings:
            if finding.clause not in rules:
                rules[finding.clause] = {
                    "id": _rule_id(finding.clause),
                    "name": finding.clause,
                    "shortDescription": {"text": finding.clause},
                    "fullDescription": {"text": finding.detail},
                    "defaultConfiguration": {"level": finding.severity.value},
                }
        
        results = []
        for outcome in self.outcomes:
            finding = next((f for f in self.findings if f.mutation_id == outcome.mutation_id), None)
            if finding:
                rule_id = _rule_id(finding.clause)
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
                        "version": self.fuzz_tlsfuzz_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }]
        }
        return json.dumps(sarif, separators=(",", ":"), sort_keys=True)
    
    def to_jsonl(self, path: Path) -> None:
        """Write outcomes as JSONL stream (flush every 64)."""
        import json
        
        def outcome_to_jsonl(o: HandshakeOutcome) -> dict[str, Any]:
            return {
                "mutation_id": o.mutation_id,
                "outcome": o.outcome.value,
                "latency_ms": o.latency_ms,
                "alert_description": o.alert_description,
                "bytes_captured": o.bytes_captured,
                "negotiated_group": o.negotiated_group,
                "detail": o.detail,
            }
        
        with open(path, "w") as f:
            for i, outcome in enumerate(self.outcomes):
                f.write(json.dumps(outcome_to_jsonl(outcome), separators=(",", ":")))
                f.write("\n")
                if (i + 1) % 64 == 0:
                    f.flush()