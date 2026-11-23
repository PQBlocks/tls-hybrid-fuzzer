"""Tests for JSONL corpus/report format determinism (slice S16).

Same seed => byte-identical JSONL. SARIF rule IDs match Oracle clauses.
"""

import json
from pathlib import Path

import pytest

from pqblocks_tlsfuzz.corpus import (
    KeyShareMutation,
    MutationClass,
    SeedCorpus,
    iter_corpus,
)
from pqblocks_tlsfuzz.constants import Group
from pqblocks_tlsfuzz.report import FuzzReport, Finding, Severity
from pqblocks_tlsfuzz.transport import HandshakeOutcome, OutcomeClass


class TestJSONLDeterminism:
    def test_same_seed_byte_identical_jsonl(self, tmp_path):
        """Same (groups, classes, iterations, seed) => byte-identical JSONL output."""
        groups = (Group.MLKEM512, Group.MLKEM768)
        classes = (MutationClass.TRUNCATED, MutationClass.OVERSIZED)
        iterations = 50
        seed = 12345

        def dump_jsonl(path: Path) -> bytes:
            mutations = list(iter_corpus(groups, classes, iterations, seed))
            lines = []
            for m in mutations:
                lines.append(json.dumps({
                    "mutation_id": m.id,
                    "mutation_class": m.mutation_class.value,
                    "group": m.group.value,
                    "offset": m.offset,
                    "seed": m.seed,
                    "payload_len": len(m.payload),
                }, separators=(",", ":"), sort_keys=True))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return path.read_bytes()

        a = dump_jsonl(tmp_path / "a.jsonl")
        b = dump_jsonl(tmp_path / "b.jsonl")
        assert a == b

    def test_different_seed_different_jsonl(self, tmp_path):
        """Different seed => different JSONL output."""
        groups = (Group.MLKEM512,)
        classes = (MutationClass.TRUNCATED,)
        iterations = 10

        def dump_jsonl(path: Path, seed: int) -> bytes:
            mutations = list(iter_corpus(groups, classes, iterations, seed))
            lines = []
            for m in mutations:
                lines.append(json.dumps({
                    "mutation_id": m.id,
                    "mutation_class": m.mutation_class.value,
                }, separators=(",", ":"), sort_keys=True))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return path.read_bytes()

        a = dump_jsonl(tmp_path / "seed1.jsonl", seed=1)
        b = dump_jsonl(tmp_path / "seed2.jsonl", seed=2)
        assert a != b


class TestSARIFRuleIDsMatchOracle:
    def test_sarif_rule_ids_derived_from_clauses(self):
        """SARIF ruleId must be a normalized form of the finding's clause."""
        findings = [
            Finding(
                mutation_id="mlkem512-truncated-0",
                group=Group.MLKEM512,
                mutation_class=MutationClass.TRUNCATED,
                severity=Severity.HIGH,
                expected="ek length must equal 800",
                observed=OutcomeClass.OUTCOME_REJECTED,
                clause="§6.2 ek-length-check",
                detail="truncated ek at offset 0",
            ),
            Finding(
                mutation_id="mlkem768-oversized-0",
                group=Group.MLKEM768,
                mutation_class=MutationClass.OVERSIZED,
                severity=Severity.CRITICAL,
                expected="ek length must equal 1184",
                observed=OutcomeClass.OUTCOME_ACCEPTED,
                clause="§6.2 ek-length-check",
                detail="oversized ek at offset 1185",
            ),
        ]

        report = FuzzReport(
            target="localhost:8443",
            started_utc="2026-01-01T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(),
            findings=tuple(findings),
            p95_latency_ms=10.0,
            false_positive_rate=0.0,
        )

        sarif = report.to_sarif()
        parsed = json.loads(sarif)

        rule_ids = {r["id"] for r in parsed["runs"][0]["tool"]["driver"]["rules"]}
        expected_ids = {"section-6-2-ek-length-check"}
        assert rule_ids == expected_ids

    def test_sarif_results_have_rule_ids(self):
        """Every SARIF result must reference a defined ruleId."""
        findings = [
            Finding(
                mutation_id="mlkem512-bitflip-5",
                group=Group.MLKEM512,
                mutation_class=MutationClass.BITFLIP,
                severity=Severity.MEDIUM,
                expected="single bit flip at offset 5",
                observed=OutcomeClass.OUTCOME_REJECTED,
                clause="§6.2 bitflip-detection",
                detail="bit flipped at byte offset 5",
            ),
        ]

        report = FuzzReport(
            target="localhost:8443",
            started_utc="2026-01-01T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(),
            findings=tuple(findings),
            p95_latency_ms=5.0,
            false_positive_rate=None,
        )

        sarif = report.to_sarif()
        parsed = json.loads(sarif)

        defined = {r["id"] for r in parsed["runs"][0]["tool"]["driver"]["rules"]}
        for result in parsed["runs"][0]["results"]:
            assert result["ruleId"] in defined

    def test_json_output_schema_v1(self):
        """to_json must emit config_version: 1 in the config block."""
        report = FuzzReport(
            target="localhost:8443",
            started_utc="2026-01-01T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(),
            findings=(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        parsed = json.loads(report.to_json())
        assert parsed["config"]["config_version"] == 1

    def test_junit_has_testsuite_root(self):
        """to_junit must produce a <testsuite> root element."""
        report = FuzzReport(
            target="localhost:8443",
            started_utc="2026-01-01T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(),
            findings=(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        junit = report.to_junit()
        assert junit.strip().startswith('<?xml version="1.0" encoding="utf-8"?>')
        assert "<testsuite" in junit
        assert "</testsuite>" in junit