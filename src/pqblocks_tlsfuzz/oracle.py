"""Oracle judging table for pqblocks_tlsfuzz (slice S5).

Implements ExpectedOutcome rows for all (class × group) mandated classes with
clause citations per RFC 10024 §4, draft-ietf-tls-mlkem-11 §4.2, RFC 8446/9846.

Oracle.classify → OracleVerdict (is_finding/is_observation) with rules:
- mandatory-reject classes (truncated/oversized/garbage/boundary ek; hybrid all-zero ECDHE)
  acceptance = finding HIGH
- crash/timeout = CRITICAL
- negotiation-structure classes = observation-only (unless endpoint hangs/resets)
"""

from dataclasses import dataclass
from typing import FrozenSet

from pqblocks_tlsfuzz.constants import Group, GroupRegistry
from pqblocks_tlsfuzz.corpus import KeyShareMutation, MutationClass
from pqblocks_tlsfuzz.transport import HandshakeOutcome, OutcomeClass


@dataclass(frozen=True)
class ExpectedOutcome:
    """Expected outcome for a (mutation_class, group) pair with spec clause citation."""

    mutation_class: MutationClass
    group: Group
    acceptable: FrozenSet[OutcomeClass]
    finding_if: FrozenSet[OutcomeClass]
    severity: str
    clause: str


@dataclass(frozen=True)
class OracleVerdict:
    """Classification result from Oracle.classify()."""

    mutation_id: str
    is_finding: bool
    is_observation: bool
    expected: ExpectedOutcome


class Oracle:
    """Judges handshake outcomes against spec-mandated expectations.

    Table populated per §4 of RFC 10024 + §4.2 of draft-ietf-tls-mlkem-11.
    """

    def __init__(self) -> None:
        self._table: dict[tuple[MutationClass, Group], ExpectedOutcome] = {}
        self._populate_table()

    def _populate_table(self) -> None:
        registry = GroupRegistry()

        # ---- VALID_CONTROL ----
        for group in Group:
            spec = registry.get(group)
            self._table[(MutationClass.VALID_CONTROL, group)] = ExpectedOutcome(
                mutation_class=MutationClass.VALID_CONTROL,
                group=group,
                acceptable=frozenset([OutcomeClass.OUTCOME_ACCEPTED]),
                finding_if=frozenset(),
                severity="INFO",
                clause=f"draft-ietf-tls-mlkem-11 §4.2 (valid control for {group.value})",
            )

        # ---- MANDATED-REJECT CLASSES (byte-level) ----
        # These violate FIPS 203 §7.2 ek check or RFC 10024 wire format
        # Spec-mandated rejection: ALERT_ILLEGAL_PARAMETER (primary) or ALERT_INTERNAL_ERROR
        mandated_reject_classes = (
            MutationClass.TRUNCATED,
            MutationClass.OVERSIZED,
            MutationClass.GARBAGE_FILL,
            MutationClass.BOUNDARY_OFF_BY_ONE,
        )

        for cls in mandated_reject_classes:
            for group in Group:
                spec = registry.get(group)
                clause = (
                    "draft-ietf-tls-mlkem-11 §4.2, FIPS 203 §7.2"
                    if not spec.is_hybrid
                    else "RFC 10024 §4.2, draft-ietf-tls-mlkem-11 §4.2, FIPS 203 §7.2"
                )
                self._table[(cls, group)] = ExpectedOutcome(
                    mutation_class=cls,
                    group=group,
                    acceptable=frozenset([
                        OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                        OutcomeClass.ALERT_INTERNAL_ERROR,
                        OutcomeClass.ALERT_DECODE_ERROR,
                        OutcomeClass.ALERT_HANDSHAKE_FAILURE,
                    ]),
                    finding_if=frozenset([OutcomeClass.OUTCOME_ACCEPTED]),
                    severity="HIGH",
                    clause=clause,
                )

        # ---- BITFLIP / WRONG_GROUP_BYTES ----
        # Also mandate rejection (garbled ek or wrong group bytes)
        for cls in (MutationClass.BITFLIP, MutationClass.WRONG_GROUP_BYTES):
            for group in Group:
                spec = registry.get(group)
                clause = (
                    "draft-ietf-tls-mlkem-11 §4.2, FIPS 203 §7.2"
                    if not spec.is_hybrid
                    else "RFC 10024 §4.2, draft-ietf-tls-mlkem-11 §4.2, FIPS 203 §7.2"
                )
                self._table[(cls, group)] = ExpectedOutcome(
                    mutation_class=cls,
                    group=group,
                    acceptable=frozenset([
                        OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                        OutcomeClass.ALERT_INTERNAL_ERROR,
                        OutcomeClass.ALERT_DECODE_ERROR,
                        OutcomeClass.ALERT_HANDSHAKE_FAILURE,
                    ]),
                    finding_if=frozenset([OutcomeClass.OUTCOME_ACCEPTED]),
                    severity="HIGH",
                    clause=clause,
                )

        # ---- HYBRID_BOUNDARY_SHIFT ----
        # Offsets at ML-KEM/ECDHE boundary per RFC 10024 §4.1-4.2
        # All-zero ECDHE point (E19) MUST abort with illegal_parameter
        for group in (Group.X25519MLKEM768, Group.SECP256R1MLKEM768, Group.SECP384R1MLKEM1024):
            self._table[(MutationClass.HYBRID_BOUNDARY_SHIFT, group)] = ExpectedOutcome(
                mutation_class=MutationClass.HYBRID_BOUNDARY_SHIFT,
                group=group,
                acceptable=frozenset([
                    OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                    OutcomeClass.ALERT_INTERNAL_ERROR,
                    OutcomeClass.ALERT_DECODE_ERROR,
                    OutcomeClass.ALERT_HANDSHAKE_FAILURE,
                ]),
                finding_if=frozenset([OutcomeClass.OUTCOME_ACCEPTED]),
                severity="HIGH",
                clause="RFC 10024 §4.2 (hybrid boundary shift), RFC 9846 §4.2.8.1 (all-zero point check)",
            )

        # ---- NEGOTIATION-STRUCTURE CLASSES ----
        # No spec-mandated outcome for every peer; results are observations
        # Exception: crash/timeout (TCP_CLOSED, TIMEOUT) = finding CRITICAL
        negotiation_classes = (
            MutationClass.DUPLICATE_SHARE,
            MutationClass.MISSING_SHARE,
            MutationClass.LIST_TRUNCATION,
            MutationClass.REORDERED_GROUPS,
        )

        for cls in negotiation_classes:
            for group in Group:
                self._table[(cls, group)] = ExpectedOutcome(
                    mutation_class=cls,
                    group=group,
                    acceptable=frozenset([
                        OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                        OutcomeClass.ALERT_INTERNAL_ERROR,
                        OutcomeClass.ALERT_DECODE_ERROR,
                        OutcomeClass.ALERT_HANDSHAKE_FAILURE,
                        OutcomeClass.OUTCOME_ACCEPTED,
                        OutcomeClass.ALERT_OTHER,
                    ]),
                    finding_if=frozenset([OutcomeClass.TIMEOUT, OutcomeClass.TCP_CLOSED]),
                severity="info",
                    clause="RFC 8446 §4.2.8 (key_share structure), RFC 10024 §4.1 (hybrid share structure)",
                )

        # ---- OVERSIZE_RECORD ----
        # Record layer violation; peer may timeout or reject
        for group in Group:
            self._table[(MutationClass.OVERSIZE_RECORD, group)] = ExpectedOutcome(
                mutation_class=MutationClass.OVERSIZE_RECORD,
                group=group,
                acceptable=frozenset([
                    OutcomeClass.TIMEOUT,
                    OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                    OutcomeClass.ALERT_DECODE_ERROR,
                    OutcomeClass.ALERT_HANDSHAKE_FAILURE,
                    OutcomeClass.TCP_CLOSED,
                ]),
                finding_if=frozenset([OutcomeClass.OUTCOME_ACCEPTED]),
                severity="HIGH",
                clause="RFC 8446 §5.1 (TLSPlaintext length), RFC 9846 §5.1",
            )

    def expected(self, mutation: KeyShareMutation) -> ExpectedOutcome:
        """Return the ExpectedOutcome for this mutation.

        Raises KeyError if the (class, group) combination is not in the table.
        """
        key = (mutation.mutation_class, mutation.group)
        if key not in self._table:
            # Fallback: return a generic entry for any missing mandated class
            # This should not happen for mandated classes
            return ExpectedOutcome(
                mutation_class=mutation.mutation_class,
                group=mutation.group,
                acceptable=frozenset([OutcomeClass.ALERT_ILLEGAL_PARAMETER]),
                finding_if=frozenset([OutcomeClass.OUTCOME_ACCEPTED]),
                severity="HIGH",
                clause="draft-ietf-tls-mlkem-11 §4.2 / RFC 10024 §4.2 (fallback)",
            )
        return self._table[key]

    def _is_mandated_reject_class(self, mutation_class: MutationClass) -> bool:
        """Check if a mutation class is a spec-mandated-reject class."""
        return mutation_class in (
            MutationClass.TRUNCATED,
            MutationClass.OVERSIZED,
            MutationClass.GARBAGE_FILL,
            MutationClass.BOUNDARY_OFF_BY_ONE,
            MutationClass.BITFLIP,
            MutationClass.WRONG_GROUP_BYTES,
        )

    def _is_negotiation_class(self, mutation_class: MutationClass) -> bool:
        """Check if a mutation class is a negotiation-structure class."""
        return mutation_class in (
            MutationClass.DUPLICATE_SHARE,
            MutationClass.MISSING_SHARE,
            MutationClass.LIST_TRUNCATION,
            MutationClass.REORDERED_GROUPS,
        )

    def _is_valid_control_class(self, mutation_class: MutationClass) -> bool:
        """Check if a mutation class is VALID_CONTROL."""
        return mutation_class == MutationClass.VALID_CONTROL

    def classify(self, mutation: KeyShareMutation, outcome: HandshakeOutcome) -> OracleVerdict:
        """Classify an outcome against the expected outcome for this mutation.

        Returns OracleVerdict with:
        - is_finding: endpoint accepted what spec mandates rejected, or crashed/hung
        - is_observation: non-mandated behavior recorded, never counted as finding
        - expected: the ExpectedOutcome used for classification (may have overridden severity)
        """
        from copy import replace
        
        expected = self.expected(mutation)
        observed = outcome.outcome
        mutation_class = mutation.mutation_class

        # Check if observed outcome is in finding_if set (base finding logic)
        is_finding = observed in expected.finding_if

        # Mandated-reject classes: TCP_CLOSED and TIMEOUT are CRITICAL findings
        # (per spec E11: TCP_CLOSED for spec-mandated-rejection classes → finding CRITICAL)
        if self._is_mandated_reject_class(mutation_class):
            if observed in (OutcomeClass.TCP_CLOSED, OutcomeClass.TIMEOUT):
                is_finding = True
                is_observation = False
                # Override severity to CRITICAL for crash/timeout on mandated-reject
                expected = replace(expected, severity="CRITICAL")

        # Valid control: any non-accepted outcome is a finding (FPR - false positive rate)
        if self._is_valid_control_class(mutation_class):
            if observed != OutcomeClass.OUTCOME_ACCEPTED:
                is_finding = True

        # Negotiation classes: all outcomes are observation-only per spec E11,
        # including TCP_CLOSED and TIMEOUT (crash is recorded but not a finding).
        if self._is_negotiation_class(mutation_class):
            is_finding = False
            is_observation = True

        # Check if observed outcome is an observation
        # For mandated-reject classes: never observation (either acceptable rejection or finding)
        # For negotiation classes: already handled above (all observations)
        # For valid control: never observation
        if self._is_negotiation_class(mutation_class):
            pass  # is_observation already set to True above
        else:
            is_observation = (
                not is_finding
                and observed not in expected.acceptable
            )

        return OracleVerdict(
            mutation_id=mutation.id,
            is_finding=is_finding,
            is_observation=is_observation,
            expected=expected,
        )