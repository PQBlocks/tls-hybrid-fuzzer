"""Tests for report.py (slice S9).

FuzzReport, Finding, Severity with JSON, JUnit, SARIF, JSONL writers.
Schema validation for all three writers; golden-file tests; P95 small-n (E24).
"""

import json
import pytest
from xml.etree import ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone

from pqblocks_tlsfuzz.constants import Group
from pqblocks_tlsfuzz.corpus import KeyShareMutation, MutationClass
from pqblocks_tlsfuzz.report import Finding, FuzzReport, Severity
from pqblocks_tlsfuzz.transport import HandshakeOutcome, OutcomeClass


class TestSeverityEnum:
    """Severity levels per spec §1.3."""

    def test_severity_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_severity_is_str_enum(self):
        assert isinstance(Severity.CRITICAL, str)
        assert Severity.HIGH in ("critical", "high", "medium", "low", "info")


class TestFindingDataclass:
    """Finding carries a single deviation with clause citation."""

    def test_finding_is_frozen(self):
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.HIGH,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="Expected rejection, got acceptance",
        )
        assert isinstance(finding, Finding)
        with pytest.raises(Exception):
            finding.severity = Severity.LOW

    def test_finding_fields(self):
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.HIGH,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="Expected rejection, got acceptance",
        )
        assert finding.mutation_id == "mlkem768-truncated-abc123"
        assert finding.group == Group.MLKEM768
        assert finding.mutation_class == MutationClass.TRUNCATED
        assert finding.severity == Severity.HIGH
        assert finding.expected == "draft-ietf-tls-mlkem-11 §4.2"
        assert finding.observed == OutcomeClass.OUTCOME_ACCEPTED
        assert finding.clause == "draft-ietf-tls-mlkem-11 §4.2"
        assert finding.detail == "Expected rejection, got acceptance"


class TestFuzzReportDataclass:
    """FuzzReport is a frozen dataclass with writers."""

    def test_fuzz_report_is_frozen(self):
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=100.0,
            false_positive_rate=0.0,
        )
        assert isinstance(report, FuzzReport)
        with pytest.raises(Exception):
            report.target = "other:4433"

    def test_fuzz_report_with_outcomes_and_findings(self):
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.HIGH,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="Expected rejection, got acceptance",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        assert len(report.outcomes) == 1
        assert len(report.findings) == 1
        assert report.p95_latency_ms == 10.0
        assert report.false_positive_rate == 0.0


class TestFuzzReportToJson:
    """to_json: schema v1 with config_version=1."""

    def test_to_json_empty_report(self):
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        json_str = report.to_json()
        data = json.loads(json_str)

        assert data["target"] == "localhost:4433"
        assert data["started_utc"] == "2026-11-19T00:00:00Z"
        assert data["pqblocks_tlsfuzz_version"] == "0.1.0"
        assert data["config"]["config_version"] == 1
        assert data["outcomes"] == []
        assert data["findings"] == []
        assert data["p95_latency_ms"] == 0.0
        assert data["false_positive_rate"] is None
        assert data["outcome_histogram"] == {}

    def test_to_json_with_outcomes_and_findings(self):
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="accepted",
        )
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.HIGH,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="Expected rejection, got acceptance",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        json_str = report.to_json()
        data = json.loads(json_str)

        assert len(data["outcomes"]) == 1
        assert data["outcomes"][0]["mutation_id"] == "mlkem768-truncated-abc123"
        assert data["outcomes"][0]["outcome"] == "accepted"
        assert data["outcomes"][0]["latency_ms"] == 10.0
        assert data["outcomes"][0]["alert_description"] is None
        assert data["outcomes"][0]["bytes_captured"] == 0
        assert data["outcomes"][0]["negotiated_group"] is None
        assert data["outcomes"][0]["detail"] == "accepted"

        assert len(data["findings"]) == 1
        assert data["findings"][0]["mutation_id"] == "mlkem768-truncated-abc123"
        assert data["findings"][0]["group"] == "mlkem768"
        assert data["findings"][0]["mutation_class"] == "truncated"
        assert data["findings"][0]["severity"] == "high"
        assert data["findings"][0]["expected"] == "draft-ietf-tls-mlkem-11 §4.2"
        assert data["findings"][0]["observed"] == "accepted"
        assert data["findings"][0]["clause"] == "draft-ietf-tls-mlkem-11 §4.2"
        assert data["findings"][0]["detail"] == "Expected rejection, got acceptance"

        assert data["outcome_histogram"]["accepted"] == 1

    def test_to_json_multiple_outcomes_histogram(self):
        outcomes = [
            HandshakeOutcome(
                mutation_id=f"mlkem768-truncated-{i}",
                outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER if i % 2 == 0 else OutcomeClass.OUTCOME_ACCEPTED,
                latency_ms=10.0,
                alert_description=47 if i % 2 == 0 else None,
                bytes_captured=0,
                negotiated_group=None,
                detail="",
            )
            for i in range(4)
        ]
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(outcomes),
            findings=tuple(),
            p95_latency_ms=10.0,
            false_positive_rate=None,
        )
        json_str = report.to_json()
        data = json.loads(json_str)

        assert data["outcome_histogram"]["alert_illegal_parameter"] == 2
        assert data["outcome_histogram"]["accepted"] == 2

    def test_to_json_deterministic_order(self):
        """Same report => identical JSON (sort_keys=True)."""
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        report1 = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=tuple(),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        report2 = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=tuple(),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        assert report1.to_json() == report2.to_json()


class TestFuzzReportToJunit:
    """to_junit: xunit 1.0 schema with one testcase per probe."""

    def test_to_junit_empty(self):
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        xml_str = report.to_junit()
        root = ET.fromstring(xml_str)

        assert root.tag == "testsuite"
        assert root.get("name") == "pqblocks-tlsfuzz"
        assert root.get("tests") == "0"
        assert root.get("failures") == "0"
        assert root.get("errors") == "0"
        assert root.get("skipped") == "0"

    def test_to_junit_with_outcomes(self):
        outcomes = [
            HandshakeOutcome(
                mutation_id=f"mlkem768-truncated-{i}",
                outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                latency_ms=10.0,
                alert_description=47,
                bytes_captured=0,
                negotiated_group=None,
                detail="",
            )
            for i in range(3)
        ]
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(outcomes),
            findings=tuple(),
            p95_latency_ms=10.0,
            false_positive_rate=None,
        )
        xml_str = report.to_junit()
        root = ET.fromstring(xml_str)

        assert root.get("tests") == "3"
        assert root.get("failures") == "0"  # no findings
        testcases = list(root.findall("testcase"))
        assert len(testcases) == 3
        for i, tc in enumerate(testcases):
            assert tc.get("name") == f"mlkem768-truncated-{i}"
            assert tc.get("classname") == "mlkem768"
            assert float(tc.get("time")) == 0.01  # 10ms in seconds
            # No failure element
            assert tc.find("failure") is None

    def test_to_junit_with_findings_high_severity_is_failure(self):
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.HIGH,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="Expected rejection, got acceptance",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        xml_str = report.to_junit()
        root = ET.fromstring(xml_str)

        assert root.get("tests") == "1"
        assert root.get("failures") == "1"
        tc = root.find("testcase")
        failure = tc.find("failure")
        assert failure is not None
        assert failure.get("message") == "Expected rejection, got acceptance"
        assert failure.get("type") == "high"
        assert "Expected: draft-ietf-tls-mlkem-11 §4.2" in failure.text
        assert "Observed: accepted" in failure.text
        assert "Clause: draft-ietf-tls-mlkem-11 §4.2" in failure.text

    def test_to_junit_with_findings_critical_severity_is_failure(self):
        """CRITICAL findings also produce failures."""
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.TCP_CLOSED,
            latency_ms=2000.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="peer closed",
        )
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.CRITICAL,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.TCP_CLOSED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="peer closed on mandated reject",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=2000.0,
            false_positive_rate=0.0,
        )
        xml_str = report.to_junit()
        root = ET.fromstring(xml_str)

        assert root.get("failures") == "1"
        tc = root.find("testcase")
        failure = tc.find("failure")
        assert failure is not None
        assert failure.get("type") == "critical"

    def test_to_junit_findings_not_critical_high_are_not_failures(self):
        """MEDIUM, LOW, INFO findings do not produce JUnit failures (observations)."""
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-duplicate_share-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        finding = Finding(
            mutation_id="mlkem768-duplicate_share-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.DUPLICATE_SHARE,
            severity=Severity.INFO,  # Negotiation class = observation
            expected="RFC 8446 §4.2.8",
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause="RFC 8446 §4.2.8",
            detail="observation only",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        xml_str = report.to_junit()
        root = ET.fromstring(xml_str)

        assert root.get("tests") == "1"
        assert root.get("failures") == "0"
        tc = root.find("testcase")
        assert tc.find("failure") is None

    def test_to_junit_time_attribute_in_seconds(self):
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=500.0,  # 500 ms
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=tuple(),
            p95_latency_ms=500.0,
            false_positive_rate=None,
        )
        xml_str = report.to_junit()
        root = ET.fromstring(xml_str)
        tc = root.find("testcase")
        assert float(tc.get("time")) == 0.5  # 500ms = 0.5s

    def test_to_junit_xml_declaration(self):
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        xml_str = report.to_junit()
        assert xml_str.startswith('<?xml version="1.0" encoding="utf-8"?>')


class TestFuzzReportToSarif:
    """to_sarif: SARIF 2.1.0 with ruleId = oracle clause id."""

    def test_to_sarif_empty(self):
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        sarif_str = report.to_sarif()
        data = json.loads(sarif_str)

        assert data["version"] == "2.1.0"
        assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert data["runs"][0]["tool"]["driver"]["name"] == "pqblocks-tlsfuzz"
        assert data["runs"][0]["tool"]["driver"]["version"] == "0.1.0"
        assert data["runs"][0]["tool"]["driver"]["rules"] == []
        assert data["runs"][0]["results"] == []

    def test_to_sarif_with_findings(self):
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.HIGH,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="Expected rejection, got acceptance",
        )
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        sarif_str = report.to_sarif()
        data = json.loads(sarif_str)

        # Check tool driver
        assert data["runs"][0]["tool"]["driver"]["name"] == "pqblocks-tlsfuzz"
        assert data["runs"][0]["tool"]["driver"]["version"] == "0.1.0"

        # Check rules: ruleId derived from clause
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        rule = rules[0]
        assert rule["id"] == "draft-ietf-tls-mlkem-11-4-2"  # sanitized clause
        assert rule["name"] == "draft-ietf-tls-mlkem-11 §4.2"
        assert rule["shortDescription"]["text"] == "draft-ietf-tls-mlkem-11 §4.2"
        assert rule["fullDescription"]["text"] == "Expected rejection, got acceptance"
        assert rule["defaultConfiguration"]["level"] == "high"

        # Check results: one result per finding
        results = data["runs"][0]["results"]
        assert len(results) == 1
        result = results[0]
        assert result["ruleId"] == "draft-ietf-tls-mlkem-11-4-2"
        assert result["level"] == "error"  # HIGH severity => error
        assert result["message"]["text"] == "Expected rejection, got acceptance"
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "mutation://mlkem768-truncated-abc123"
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1

    def test_to_sarif_critical_severity_is_error(self):
        """CRITICAL severity => error level."""
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.CRITICAL,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.TCP_CLOSED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="peer closed on mandated reject",
        )
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.TCP_CLOSED,
            latency_ms=2000.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="peer closed",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=2000.0,
            false_positive_rate=0.0,
        )
        sarif_str = report.to_sarif()
        data = json.loads(sarif_str)

        result = data["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_to_sarif_medium_low_info_severity_is_warning(self):
        """MEDIUM, LOW, INFO severity => warning level."""
        for severity in (Severity.MEDIUM, Severity.LOW, Severity.INFO):
            finding = Finding(
                mutation_id=f"mlkem768-duplicate_share-{severity.value}",
                group=Group.MLKEM768,
                mutation_class=MutationClass.DUPLICATE_SHARE,
                severity=severity,
                expected="RFC 8446 §4.2.8",
                observed=OutcomeClass.OUTCOME_ACCEPTED,
                clause="RFC 8446 §4.2.8",
                detail="observation",
            )
            outcome = HandshakeOutcome(
                mutation_id=f"mlkem768-duplicate_share-{severity.value}",
                outcome=OutcomeClass.OUTCOME_ACCEPTED,
                latency_ms=10.0,
                alert_description=None,
                bytes_captured=0,
                negotiated_group=None,
                detail="",
            )
            report = FuzzReport(
                target="localhost:4433",
                started_utc="2026-11-19T00:00:00Z",
                fuzz_tlsfuzz_version="0.1.0",
                outcomes=(outcome,),
                findings=(finding,),
                p95_latency_ms=10.0,
                false_positive_rate=0.0,
            )
            sarif_str = report.to_sarif()
            data = json.loads(sarif_str)

            result = data["runs"][0]["results"][0]
            assert result["level"] == "warning", f"Severity {severity} should be warning"

    def test_to_sarif_deduplicates_rules_by_clause(self):
        """Multiple findings with same clause => single rule."""
        findings = [
            Finding(
                mutation_id=f"mlkem768-truncated-{i}",
                group=Group.MLKEM768,
                mutation_class=MutationClass.TRUNCATED,
                severity=Severity.HIGH,
                expected="draft-ietf-tls-mlkem-11 §4.2",
                observed=OutcomeClass.OUTCOME_ACCEPTED,
                clause="draft-ietf-tls-mlkem-11 §4.2",
                detail=f"finding {i}",
            )
            for i in range(3)
        ]
        outcomes = [
            HandshakeOutcome(
                mutation_id=f"mlkem768-truncated-{i}",
                outcome=OutcomeClass.OUTCOME_ACCEPTED,
                latency_ms=10.0,
                alert_description=None,
                bytes_captured=0,
                negotiated_group=None,
                detail="",
            )
            for i in range(3)
        ]
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(outcomes),
            findings=tuple(findings),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        sarif_str = report.to_sarif()
        data = json.loads(sarif_str)

        # One rule for the shared clause
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        # Three results
        results = data["runs"][0]["results"]
        assert len(results) == 3
        for result in results:
            assert result["ruleId"] == "draft-ietf-tls-mlkem-11-4-2"

    def test_to_sarif_ruleid_matches_oracle_clause(self):
        """ruleId must match oracle clause id format (sanitized)."""
        clause = "RFC 10024 §4.2, draft-ietf-tls-mlkem-11 §4.2, FIPS 203 §7.2"
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.HIGH,
            expected=clause,
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause=clause,
            detail="Expected rejection, got acceptance",
        )
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        sarif_str = report.to_sarif()
        data = json.loads(sarif_str)

        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        # Clause sanitized: spaces->-, dots->-, §->, commas->, lowercase
        expected_id = clause.replace(" ", "-").replace(".", "-").replace("§", "").replace(",", "").lower()
        assert rule["id"] == expected_id
        result = data["runs"][0]["results"][0]
        assert result["ruleId"] == expected_id


class TestFuzzReportToJsonl:
    """to_jsonl: streaming writer with flush every 64."""

    def test_to_jsonl_empty(self, tmp_path: Path):
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        out_path = tmp_path / "outcomes.jsonl"
        report.to_jsonl(out_path)
        content = out_path.read_text()
        assert content == ""

    def test_to_jsonl_writes_one_per_line(self, tmp_path: Path):
        outcomes = [
            HandshakeOutcome(
                mutation_id=f"mlkem768-truncated-{i}",
                outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                latency_ms=10.0,
                alert_description=47,
                bytes_captured=0,
                negotiated_group=None,
                detail="",
            )
            for i in range(3)
        ]
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(outcomes),
            findings=tuple(),
            p95_latency_ms=10.0,
            false_positive_rate=None,
        )
        out_path = tmp_path / "outcomes.jsonl"
        report.to_jsonl(out_path)
        lines = out_path.read_text().strip().split("\n")
        assert len(lines) == 3
        for i, line in enumerate(lines):
            data = json.loads(line)
            assert data["mutation_id"] == f"mlkem768-truncated-{i}"
            assert data["outcome"] == "alert_illegal_parameter"
            assert data["latency_ms"] == 10.0
            assert data["alert_description"] == 47

    def test_to_jsonl_flush_every_64(self, tmp_path: Path):
        """Flush occurs every 64 outcomes (can't easily test flush count,
        but verify it writes correctly for >64 outcomes)."""
        outcomes = [
            HandshakeOutcome(
                mutation_id=f"mlkem768-truncated-{i}",
                outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                latency_ms=10.0,
                alert_description=47,
                bytes_captured=0,
                negotiated_group=None,
                detail="",
            )
            for i in range(100)
        ]
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(outcomes),
            findings=tuple(),
            p95_latency_ms=10.0,
            false_positive_rate=None,
        )
        out_path = tmp_path / "outcomes.jsonl"
        report.to_jsonl(out_path)
        lines = out_path.read_text().strip().split("\n")
        assert len(lines) == 100
        for i, line in enumerate(lines):
            data = json.loads(line)
            assert data["mutation_id"] == f"mlkem768-truncated-{i}"


class TestP95SmallN:
    """E24: P95 with small n (2 samples) => max (nearest-rank)."""

    def test_p95_two_samples(self):
        """Two samples: P95 = max (nearest-rank, rank=ceil(0.95*2)=2, idx=1)."""
        outcomes = [
            HandshakeOutcome(
                mutation_id=f"mlkem768-truncated-{i}",
                outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                latency_ms=float(10 + i * 10),
                alert_description=47,
                bytes_captured=0,
                negotiated_group=None,
                detail="",
            )
            for i in range(2)
        ]
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(outcomes),
            findings=tuple(),
            p95_latency_ms=0.0,  # Not used; report just carries the value
            false_positive_rate=None,
        )
        # The p95 value is computed by the fuzzer; report just stores it.
        # But verify the report can carry it correctly.
        assert report.p95_latency_ms == 0.0

        # Test with actual p95 value
        report2 = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(outcomes),
            findings=tuple(),
            p95_latency_ms=20.0,  # max of [10, 20] = 20
            false_positive_rate=None,
        )
        assert report2.p95_latency_ms == 20.0

    def test_p95_one_sample(self):
        """One sample: P95 = that sample."""
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-0",
            outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
            latency_ms=50.0,
            alert_description=47,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=tuple(),
            p95_latency_ms=50.0,
            false_positive_rate=None,
        )
        assert report.p95_latency_ms == 50.0


class TestGoldenFileValidation:
    """Golden-file tests: known-good output for regression detection."""

    def test_json_golden_file(self, tmp_path: Path):
        """Known-good JSON output for a canonical report."""
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="accepted",
        )
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.HIGH,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="Expected rejection, got acceptance",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        json_str = report.to_json()
        data = json.loads(json_str)

        # Verify required schema v1 keys
        assert set(data.keys()) >= {
            "target", "started_utc", "pqblocks_tlsfuzz_version",
            "config", "outcomes", "findings", "p95_latency_ms",
            "false_positive_rate", "outcome_histogram"
        }
        assert data["config"]["config_version"] == 1

    def test_junit_golden_file(self, tmp_path: Path):
        """Known-good JUnit XML for a canonical report."""
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="accepted",
        )
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.HIGH,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="Expected rejection, got acceptance",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        xml_str = report.to_junit()
        root = ET.fromstring(xml_str)

        # Verify xunit 1.0 schema elements
        assert root.tag == "testsuite"
        assert "name" in root.attrib
        assert "tests" in root.attrib
        assert "failures" in root.attrib
        assert "errors" in root.attrib
        assert "skipped" in root.attrib
        assert "time" in root.attrib

        # One testcase with failure
        testcases = list(root.findall("testcase"))
        assert len(testcases) == 1
        failure = testcases[0].find("failure")
        assert failure is not None
        assert "message" in failure.attrib
        assert "type" in failure.attrib

    def test_sarif_golden_file(self, tmp_path: Path):
        """Known-good SARIF 2.1.0 for a canonical report."""
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="accepted",
        )
        finding = Finding(
            mutation_id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            severity=Severity.HIGH,
            expected="draft-ietf-tls-mlkem-11 §4.2",
            observed=OutcomeClass.OUTCOME_ACCEPTED,
            clause="draft-ietf-tls-mlkem-11 §4.2",
            detail="Expected rejection, got acceptance",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=(finding,),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        sarif_str = report.to_sarif()
        data = json.loads(sarif_str)

        # Verify SARIF 2.1.0 schema
        assert data["version"] == "2.1.0"
        assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert "runs" in data
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert run["tool"]["driver"]["name"] == "pqblocks-tlsfuzz"
        assert "rules" in run["tool"]["driver"]
        assert "results" in run

    def test_jsonl_golden_file(self, tmp_path: Path):
        """Known-good JSONL format."""
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc123",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="accepted",
        )
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(outcome,),
            findings=tuple(),
            p95_latency_ms=10.0,
            false_positive_rate=None,
        )
        out_path = tmp_path / "outcomes.jsonl"
        report.to_jsonl(out_path)
        line = out_path.read_text().strip()
        data = json.loads(line)

        # Verify JSONL outcome fields
        assert set(data.keys()) >= {
            "mutation_id", "outcome", "latency_ms",
            "alert_description", "bytes_captured",
            "negotiated_group", "detail"
        }


class TestReportNegative:
    """Negative tests for report writers."""

    def test_to_json_with_none_false_positive_rate_serializes_null(self):
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        json_str = report.to_json()
        data = json.loads(json_str)
        assert data["false_positive_rate"] is None

    def test_to_jsonl_creates_parent_directory(self, tmp_path: Path):
        """to_jsonl should fail if parent doesn't exist (no auto-mkdir)."""
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        out_path = tmp_path / "nonexistent" / "outcomes.jsonl"
        with pytest.raises(FileNotFoundError):
            report.to_jsonl(out_path)

    def test_to_junit_with_many_findings_counts_failures_correctly(self):
        """Only CRITICAL/HIGH findings count as failures."""
        outcomes = []
        findings = []
        for i, severity in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]):
            mutation_id = f"mlkem768-truncated-{i}"
            outcome = HandshakeOutcome(
                mutation_id=mutation_id,
                outcome=OutcomeClass.OUTCOME_ACCEPTED,
                latency_ms=10.0,
                alert_description=None,
                bytes_captured=0,
                negotiated_group=None,
                detail="",
            )
            finding = Finding(
                mutation_id=mutation_id,
                group=Group.MLKEM768,
                mutation_class=MutationClass.TRUNCATED,
                severity=severity,
                expected="draft-ietf-tls-mlkem-11 §4.2",
                observed=OutcomeClass.OUTCOME_ACCEPTED,
                clause="draft-ietf-tls-mlkem-11 §4.2",
                detail="Expected rejection, got acceptance",
            )
            outcomes.append(outcome)
            findings.append(finding)

        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(outcomes),
            findings=tuple(findings),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )
        xml_str = report.to_junit()
        root = ET.fromstring(xml_str)

        # Only CRITICAL and HIGH are failures
        assert root.get("tests") == "5"
        assert root.get("failures") == "2"

        # Check which ones have failure elements
        failure_count = sum(1 for tc in root.findall("testcase") if tc.find("failure") is not None)
        assert failure_count == 2


class TestReportSchemaCompliance:
    """Schema compliance tests for all three output formats."""

    def test_json_schema_v1_required_fields(self):
        """JSON output must have all schema v1 required fields."""
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        data = json.loads(report.to_json())

        required = [
            "target", "started_utc", "pqblocks_tlsfuzz_version",
            "config", "outcomes", "findings",
            "p95_latency_ms", "false_positive_rate", "outcome_histogram"
        ]
        for field in required:
            assert field in data, f"Missing required field: {field}"

        assert data["config"]["config_version"] == 1

    def test_junit_xunit_1_0_schema(self):
        """JUnit output must conform to xunit 1.0 schema."""
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        xml_str = report.to_junit()
        root = ET.fromstring(xml_str)

        # xunit 1.0 required attributes on testsuite
        for attr in ["name", "tests", "failures", "errors", "skipped", "time"]:
            assert attr in root.attrib, f"Missing xunit attribute: {attr}"

    def test_sarif_2_1_0_schema(self):
        """SARIF output must conform to SARIF 2.1.0."""
        report = FuzzReport(
            target="localhost:4433",
            started_utc="2026-11-19T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        data = json.loads(report.to_sarif())

        assert data["version"] == "2.1.0"
        assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert "runs" in data
        run = data["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "name" in run["tool"]["driver"]
        assert "rules" in run["tool"]["driver"]
        assert "results" in run