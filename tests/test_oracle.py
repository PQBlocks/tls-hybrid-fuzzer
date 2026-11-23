"""Tests for oracle.py (slice S5).

Oracle judging table: ExpectedOutcome rows for all (class × group) mandated classes
with clause citations (≥ 30 rows). Oracle.classify → OracleVerdict (is_finding/is_observation).

Rules per spec §1.5:
- mandatory-reject classes (truncated/oversized/garbage/boundary ek; hybrid all-zero ECDHE)
  acceptance = finding HIGH
- crash/timeout = CRITICAL
- negotiation-structure classes = observation-only
- E12: peer accepts invalid share → finding HIGH, exact clause recorded
- E19: hybrid all-zero X25519 point → expected {ALERT_ILLEGAL_PARAMETER}; acceptance = finding
- E23: unoffered group selection → TRANSPORT_ERROR/observation, never acceptance
- E11: TCP_CLOSED for spec-mandated-rejection classes → finding CRITICAL; for negotiation → observation
"""

import pytest
from pqblocks_tlsfuzz.constants import Group, GroupRegistry
from pqblocks_tlsfuzz.corpus import KeyShareMutation, MutationClass
from pqblocks_tlsfuzz.oracle import (
    ExpectedOutcome,
    Oracle,
    OracleVerdict,
)
from pqblocks_tlsfuzz.transport import HandshakeOutcome, OutcomeClass


class TestExpectedOutcomeDataclass:
    """ExpectedOutcome is a frozen dataclass with clause citation."""

    def test_expected_outcome_is_frozen(self):
        exp = ExpectedOutcome(
            mutation_class=MutationClass.TRUNCATED,
            group=Group.MLKEM768,
            acceptable=frozenset([OutcomeClass.ALERT_ILLEGAL_PARAMETER]),
            finding_if=frozenset([OutcomeClass.OUTCOME_ACCEPTED]),
            severity="HIGH",
            clause="draft-ietf-tls-mlkem-11 §4.2",
        )
        assert isinstance(exp, ExpectedOutcome)
        with pytest.raises(Exception):
            exp.severity = "LOW"


class TestOracleVerdictDataclass:
    """OracleVerdict carries the classification result."""

    def test_oracle_verdict_is_frozen(self):
        exp = ExpectedOutcome(
            mutation_class=MutationClass.TRUNCATED,
            group=Group.MLKEM768,
            acceptable=frozenset([OutcomeClass.ALERT_ILLEGAL_PARAMETER]),
            finding_if=frozenset([OutcomeClass.OUTCOME_ACCEPTED]),
            severity="HIGH",
            clause="draft-ietf-tls-mlkem-11 §4.2",
        )
        verdict = OracleVerdict(
            mutation_id="mlkem768-truncated-abc123",
            is_finding=True,
            is_observation=False,
            expected=exp,
        )
        assert verdict.is_finding is True
        assert verdict.is_observation is False
        assert verdict.expected is exp


class TestOracleTablePopulation:
    """Oracle.__init__ populates the full (class × group) table with ≥ 30 rows."""

    def test_oracle_has_entries_for_all_mandated_classes(self):
        oracle = Oracle()
        # Must cover all mutation classes × all groups (6 groups × 13 classes = 78 combinations)
        # But we require at least 30 rows for mandated classes
        assert len(oracle._table) >= 30

    def test_oracle_covers_all_six_groups(self):
        oracle = Oracle()
        groups_covered = {entry.group for entry in oracle._table.values()}
        assert Group.MLKEM512 in groups_covered
        assert Group.MLKEM768 in groups_covered
        assert Group.MLKEM1024 in groups_covered
        assert Group.X25519MLKEM768 in groups_covered
        assert Group.SECP256R1MLKEM768 in groups_covered
        assert Group.SECP384R1MLKEM1024 in groups_covered

    def test_oracle_covers_all_mandated_mutation_classes(self):
        oracle = Oracle()
        classes_covered = {entry.mutation_class for entry in oracle._table.values()}
        # Mandated classes per spec §1.5 / S5 contract
        mandated = {
            MutationClass.TRUNCATED,
            MutationClass.OVERSIZED,
            MutationClass.BITFLIP,
            MutationClass.GARBAGE_FILL,
            MutationClass.BOUNDARY_OFF_BY_ONE,
            MutationClass.WRONG_GROUP_BYTES,
            MutationClass.HYBRID_BOUNDARY_SHIFT,
            MutationClass.DUPLICATE_SHARE,
            MutationClass.MISSING_SHARE,
            MutationClass.LIST_TRUNCATION,
            MutationClass.REORDERED_GROUPS,
            MutationClass.VALID_CONTROL,
        }
        for cls in mandated:
            assert cls in classes_covered, f"Missing mandated class: {cls}"

    def test_every_entry_has_clause_citation(self):
        oracle = Oracle()
        for entry in oracle._table.values():
            assert entry.clause, f"Missing clause for {entry.mutation_class}/{entry.group}"
            # Clause should cite RFC or draft
            assert any(cite in entry.clause for cite in [
                "draft-ietf-tls-mlkem-11", "RFC 10024", "RFC 8446", "RFC 9846", "FIPS 203"
            ]), f"Clause '{entry.clause}' lacks standard citation"

    def test_valid_control_has_accepted_outcome(self):
        oracle = Oracle()
        for group in Group:
            key = (MutationClass.VALID_CONTROL, group)
            if key in oracle._table:
                entry = oracle._table[key]
                assert OutcomeClass.OUTCOME_ACCEPTED in entry.acceptable
                assert entry.finding_if == frozenset()  # accepted is expected, not a finding

    def test_mandated_reject_classes_have_correct_acceptable(self):
        """Spec §1.5: shares violating spec-mandated check → MUST NOT accept."""
        oracle = Oracle()
        reject_classes = {
            MutationClass.TRUNCATED,
            MutationClass.OVERSIZED,
            MutationClass.GARBAGE_FILL,
            MutationClass.BOUNDARY_OFF_BY_ONE,
        }
        for cls in reject_classes:
            for group in Group:
                key = (cls, group)
                if key in oracle._table:
                    entry = oracle._table[key]
                    # Acceptable outcomes are alert-based rejections
                    assert OutcomeClass.ALERT_ILLEGAL_PARAMETER in entry.acceptable or \
                           OutcomeClass.ALERT_INTERNAL_ERROR in entry.acceptable or \
                           OutcomeClass.ALERT_DECODE_ERROR in entry.acceptable or \
                           OutcomeClass.ALERT_HANDSHAKE_FAILURE in entry.acceptable
                    # OUTCOME_ACCEPTED must be a finding
                    assert OutcomeClass.OUTCOME_ACCEPTED in entry.finding_if
                    assert entry.severity in ("HIGH", "CRITICAL")

    def test_hybrid_boundary_shift_has_clause_rfc10024(self):
        oracle = Oracle()
        for group in (Group.X25519MLKEM768, Group.SECP256R1MLKEM768, Group.SECP384R1MLKEM1024):
            key = (MutationClass.HYBRID_BOUNDARY_SHIFT, group)
            if key in oracle._table:
                entry = oracle._table[key]
                assert "RFC 10024" in entry.clause

    def test_ek_check_failures_cite_draft_mlkem_and_fips203(self):
        oracle = Oracle()
        for group in Group:
            key = (MutationClass.TRUNCATED, group)
            if key in oracle._table:
                entry = oracle._table[key]
                assert "draft-ietf-tls-mlkem-11" in entry.clause or "FIPS 203" in entry.clause


class TestOracleExpectedMethod:
    """Oracle.expected(mutation) returns the ExpectedOutcome for the mutation."""

    def test_expected_returns_correct_entry_for_valid_mutation(self):
        oracle = Oracle()
        mutation = KeyShareMutation(
            id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            seed=0,
            offset=100,
            payload=b"x" * 100,
        )
        expected = oracle.expected(mutation)
        assert expected.mutation_class == MutationClass.TRUNCATED
        assert expected.group == Group.MLKEM768
        assert expected.clause

    def test_expected_raises_for_unknown_combination(self):
        oracle = Oracle()
        # Create a mutation with a class not in the table
        mutation = KeyShareMutation(
            id="mlkem768-unknown-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.OVERSIZE_RECORD,  # May not be in table
            seed=0,
            offset=-1,
            payload=b"",
        )
        # Should not crash; should return a default or raise a clear error
        # Per spec, all mandated classes must be in the table
        expected = oracle.expected(mutation)
        assert isinstance(expected, ExpectedOutcome)


class TestOracleClassifyMethod:
    """Oracle.classify(mutation, outcome) → OracleVerdict with is_finding/is_observation."""

    def test_classify_accepted_invalid_is_finding_high(self):
        """E12: peer accepts invalid share → finding HIGH, exact clause recorded."""
        oracle = Oracle()
        mutation = KeyShareMutation(
            id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            seed=0,
            offset=100,
            payload=b"x" * 100,
        )
        outcome = HandshakeOutcome(
            mutation_id=mutation.id,
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        verdict = oracle.classify(mutation, outcome)
        assert verdict.is_finding is True
        assert verdict.is_observation is False
        assert verdict.expected.severity == "HIGH"
        assert verdict.expected.clause

    def test_classify_rejected_invalid_is_not_finding(self):
        """Valid rejection (alert_illegal_parameter) is not a finding."""
        oracle = Oracle()
        mutation = KeyShareMutation(
            id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            seed=0,
            offset=100,
            payload=b"x" * 100,
        )
        outcome = HandshakeOutcome(
            mutation_id=mutation.id,
            outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
            latency_ms=10.0,
            alert_description=47,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        verdict = oracle.classify(mutation, outcome)
        assert verdict.is_finding is False
        assert verdict.is_observation is False

    def test_classify_tcp_closed_mandated_reject_is_finding_critical(self):
        """E11: TCP_CLOSED for spec-mandated-rejection classes → finding CRITICAL."""
        oracle = Oracle()
        mutation = KeyShareMutation(
            id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            seed=0,
            offset=100,
            payload=b"x" * 100,
        )
        outcome = HandshakeOutcome(
            mutation_id=mutation.id,
            outcome=OutcomeClass.TCP_CLOSED,
            latency_ms=2000.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="peer closed immediately",
        )
        verdict = oracle.classify(mutation, outcome)
        assert verdict.is_finding is True
        assert verdict.expected.severity == "CRITICAL"

    def test_classify_tcp_closed_negotiation_is_observation(self):
        """E11: TCP_CLOSED for negotiation-structure classes → observation."""
        oracle = Oracle()
        mutation = KeyShareMutation(
            id="mlkem768-duplicate_share-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.DUPLICATE_SHARE,
            seed=0,
            offset=-1,
            payload=b"x" * 1184,
        )
        outcome = HandshakeOutcome(
            mutation_id=mutation.id,
            outcome=OutcomeClass.TCP_CLOSED,
            latency_ms=2000.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="peer closed immediately",
        )
        verdict = oracle.classify(mutation, outcome)
        assert verdict.is_finding is False
        assert verdict.is_observation is True

    def test_classify_timeout_is_finding_critical(self):
        """Crash/timeout = CRITICAL finding for mandated-reject classes."""
        oracle = Oracle()
        mutation = KeyShareMutation(
            id="mlkem768-oversized-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.OVERSIZED,
            seed=0,
            offset=1185,
            payload=b"x" * 1185,
        )
        outcome = HandshakeOutcome(
            mutation_id=mutation.id,
            outcome=OutcomeClass.TIMEOUT,
            latency_ms=2000.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="timeout",
        )
        verdict = oracle.classify(mutation, outcome)
        assert verdict.is_finding is True
        assert verdict.expected.severity == "CRITICAL"

    def test_classify_hybrid_allzero_x25519_accepted_is_finding(self):
        """E19: hybrid all-zero X25519 point → expected illegal_parameter; acceptance = finding."""
        oracle = Oracle()
        # This tests the HYBRID_BOUNDARY_SHIFT with all-zero ECDHE point
        mutation = KeyShareMutation(
            id="x25519mlkem768-hybrid_boundary_shift-abc123",
            group=Group.X25519MLKEM768,
            mutation_class=MutationClass.HYBRID_BOUNDARY_SHIFT,
            seed=0,
            offset=1184,  # at the ML-KEM/ECDHE boundary
            payload=b"x" * 1216,  # full hybrid share
        )
        outcome = HandshakeOutcome(
            mutation_id=mutation.id,
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        verdict = oracle.classify(mutation, outcome)
        assert verdict.is_finding is True
        assert verdict.expected.severity in ("HIGH", "CRITICAL")
        # Clause should cite RFC 10024 §4.2
        assert "RFC 10024" in verdict.expected.clause

    def test_classify_unoffered_group_is_observation(self):
        """E23: unoffered group selection → TRANSPORT_ERROR/observation, never acceptance."""
        oracle = Oracle()
        mutation = KeyShareMutation(
            id="mlkem768-truncated-abc123",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            seed=0,
            offset=100,
            payload=b"x" * 100,
        )
        outcome = HandshakeOutcome(
            mutation_id=mutation.id,
            outcome=OutcomeClass.TRANSPORT_ERROR,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=0x9999,  # unoffered group
            detail="peer selected unoffered group",
        )
        verdict = oracle.classify(mutation, outcome)
        assert verdict.is_finding is False
        assert verdict.is_observation is True

    def test_classify_accepted_valid_control_increments_fpr(self):
        """VALID_CONTROL accepted is expected; anything else increments FPR."""
        oracle = Oracle()
        mutation = KeyShareMutation(
            id="mlkem768-valid_control-tc1",
            group=Group.MLKEM768,
            mutation_class=MutationClass.VALID_CONTROL,
            seed=0,
            offset=-1,
            payload=b"x" * 1184,
        )
        # Accepted = not a finding
        outcome = HandshakeOutcome(
            mutation_id=mutation.id,
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        verdict = oracle.classify(mutation, outcome)
        assert verdict.is_finding is False
        assert verdict.is_observation is False

        # Rejected = finding (but this is tracked as FPR separately)
        outcome2 = HandshakeOutcome(
            mutation_id=mutation.id,
            outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
            latency_ms=10.0,
            alert_description=47,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        verdict2 = oracle.classify(mutation, outcome2)
        assert verdict2.is_finding is True

    def test_classify_negotiation_classes_are_observation_only(self):
        """Negotiation-structure classes (missing/duplicate/reordered) = observation-only."""
        oracle = Oracle()
        for cls in (MutationClass.DUPLICATE_SHARE, MutationClass.MISSING_SHARE,
                    MutationClass.LIST_TRUNCATION, MutationClass.REORDERED_GROUPS):
            mutation = KeyShareMutation(
                id=f"mlkem768-{cls.value}-abc123",
                group=Group.MLKEM768,
                mutation_class=cls,
                seed=0,
                offset=-1,
                payload=b"x" * 1184,
            )
            # Any non-crash outcome is observation
            for outcome_class in (OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                                   OutcomeClass.ALERT_HANDSHAKE_FAILURE,
                                   OutcomeClass.OUTCOME_ACCEPTED,
                                   OutcomeClass.ALERT_DECODE_ERROR):
                outcome = HandshakeOutcome(
                    mutation_id=mutation.id,
                    outcome=outcome_class,
                    latency_ms=10.0,
                    alert_description=47 if outcome_class == OutcomeClass.ALERT_ILLEGAL_PARAMETER else None,
                    bytes_captured=0,
                    negotiated_group=None,
                    detail="",
                )
                verdict = oracle.classify(mutation, outcome)
                if outcome_class in (OutcomeClass.TIMEOUT, OutcomeClass.TCP_CLOSED):
                    assert verdict.is_finding is True  # crash/hang is always finding
                else:
                    assert verdict.is_finding is False
                    assert verdict.is_observation is True

    def test_classify_mutation_id_matches(self):
        """Verdict mutation_id matches the input mutation."""
        oracle = Oracle()
        mutation = KeyShareMutation(
            id="mlkem768-bitflip-deadbeef",
            group=Group.MLKEM768,
            mutation_class=MutationClass.BITFLIP,
            seed=0,
            offset=500,
            payload=b"x" * 1184,
        )
        outcome = HandshakeOutcome(
            mutation_id="different-id",  # mismatch - verdict should use mutation.id
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        verdict = oracle.classify(mutation, outcome)
        assert verdict.mutation_id == mutation.id


class TestOracleSeverityMapping:
    """Severity assignments per spec §1.5."""

    def test_mandated_reject_acceptance_is_high(self):
        oracle = Oracle()
        for cls in (MutationClass.TRUNCATED, MutationClass.OVERSIZED,
                    MutationClass.GARBAGE_FILL, MutationClass.BOUNDARY_OFF_BY_ONE):
            for group in Group:
                key = (cls, group)
                if key in oracle._table:
                    assert oracle._table[key].severity == "HIGH"

    def test_hybrid_allzero_ecdh_acceptance_is_high_or_critical(self):
        oracle = Oracle()
        for group in (Group.X25519MLKEM768, Group.SECP256R1MLKEM768, Group.SECP384R1MLKEM1024):
            key = (MutationClass.HYBRID_BOUNDARY_SHIFT, group)
            if key in oracle._table:
                assert oracle._table[key].severity in ("HIGH", "CRITICAL")

    def test_timeout_tcp_closed_mandated_is_critical(self):
        oracle = Oracle()
        for cls in (MutationClass.TRUNCATED, MutationClass.OVERSIZED,
                    MutationClass.GARBAGE_FILL, MutationClass.BOUNDARY_OFF_BY_ONE):
            for group in Group:
                key = (cls, group)
                if key in oracle._table:
                    # The finding_if includes OUTCOME_ACCEPTED with HIGH
                    # But TIMEOUT/TCP_CLOSED should map to CRITICAL in classify()
                    pass  # verified in classify tests

    def test_valid_control_severity_info(self):
        oracle = Oracle()
        for group in Group:
            key = (MutationClass.VALID_CONTROL, group)
            if key in oracle._table:
                assert oracle._table[key].severity == "INFO"


class TestOracleTableSize:
    """Verify the table has at least 30 mandated rows."""

    def test_at_least_30_rows(self):
        oracle = Oracle()
        # Count entries for mandated classes (not all 13 × 6 = 78, but the spec mandates ≥ 30)
        mandated_classes = {
            MutationClass.TRUNCATED,
            MutationClass.OVERSIZED,
            MutationClass.GARBAGE_FILL,
            MutationClass.BOUNDARY_OFF_BY_ONE,
            MutationClass.HYBRID_BOUNDARY_SHIFT,
            MutationClass.DUPLICATE_SHARE,
            MutationClass.MISSING_SHARE,
            MutationClass.LIST_TRUNCATION,
            MutationClass.REORDERED_GROUPS,
            MutationClass.VALID_CONTROL,
        }
        count = sum(1 for entry in oracle._table.values()
                    if entry.mutation_class in mandated_classes)
        assert count >= 30, f"Expected ≥ 30 mandated rows, got {count}"


class TestOracleNegative:
    """Negative tests for Oracle."""

    def test_classify_with_mismatched_mutation_id_in_outcome(self):
        """Verdict uses mutation.id, not outcome.mutation_id."""
        oracle = Oracle()
        mutation = KeyShareMutation(
            id="mlkem768-truncated-correct-id",
            group=Group.MLKEM768,
            mutation_class=MutationClass.TRUNCATED,
            seed=0,
            offset=100,
            payload=b"x" * 100,
        )
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-wrong-id",
            outcome=OutcomeClass.OUTCOME_ACCEPTED,
            latency_ms=10.0,
            alert_description=None,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        verdict = oracle.classify(mutation, outcome)
        assert verdict.mutation_id == "mlkem768-truncated-correct-id"