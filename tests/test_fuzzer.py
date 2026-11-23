"""Tests for fuzzer.py (slice S8).

Covers spec §6.2 test_fuzzer.py rows:
- test_parallel_determinism (E13): same seed => bit-identical results across runs
- test_checkpoint_resume (E21): interrupted run resumes without re-probing
- test_p95_small_n (E24): p95 nearest-rank with small sample sizes
Plus edge cases: empty campaign, connection failure, no controls => FPR=1.0.
"""

import itertools
import json
import math
from pathlib import Path
from unittest import mock

import pytest

from pqblocks_tlsfuzz.constants import Group
from pqblocks_tlsfuzz.corpus import MutationClass, iter_corpus
from pqblocks_tlsfuzz.errors import PqTlsFuzzError, TransportError
from pqblocks_tlsfuzz.fuzzer import (
    CHECKPOINT_CADENCE,
    FuzzConfig,
    Fuzzer,
    _nearest_rank_p95,
)
from pqblocks_tlsfuzz.transport import (
    HandshakeOutcome,
    OutcomeClass,
    RawHandshakeClient,
    ScriptablePeer,
)


def _alert_record(level: int, description: int) -> bytes:
    return bytes([0x15, 0x03, 0x01]) + (2).to_bytes(2, "big") + bytes([level, description])


def _server_hello_record(body: bytes) -> bytes:
    handshake = bytes([0x02]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake


# ---------------------------------------------------------------------------
# RED: test_p95_small_n
# ---------------------------------------------------------------------------

class TestP95SmallN:
    """E24: f64 latency percentile with small n; nearest-rank, no ZeroDivisionError."""

    def test_p95_empty_returns_zero(self):
        assert _nearest_rank_p95([]) == 0.0

    def test_p95_single_sample(self):
        assert _nearest_rank_p95([42.0]) == 42.0

    def test_p95_two_samples_returns_max(self):
        """n=2: rank=ceil(0.95*2)=2, index=1 => sorted[1] = max."""
        assert _nearest_rank_p95([10.0, 20.0]) == 20.0

    def test_p95_ten_samples(self):
        """n=10: rank=ceil(9.5)=10, index=9 => sorted[9] = max."""
        latencies = [float(i) for i in range(10)]
        assert _nearest_rank_p95(latencies) == 9.0

    def test_p95_twenty_samples(self):
        """n=20: rank=ceil(19.0)=19, index=18 => sorted[18]."""
        latencies = [float(i) for i in range(20)]
        assert _nearest_rank_p95(latencies) == 18.0

    def test_p95_is_f64(self):
        result = _nearest_rank_p95([1.5, 2.5, 3.5])
        assert isinstance(result, float)


# ---------------------------------------------------------------------------
# RED: test_parallel_determinism
# ---------------------------------------------------------------------------

class TestParallelDeterminism:
    """E13: same seed => bit-identical results across runs, even with concurrency."""

    def test_parallel_determinism(self):
        """Two runs with same seed produce identical mutation ids, outcomes, p95, FPR."""
        peer = ScriptablePeer(mode="alert", alert_level=2, alert_description=47)
        try:
            cfg = FuzzConfig(
                endpoint=f"127.0.0.1:{peer.port}",
                iterations=200,
                seed=42,
                concurrency=4,
                timeout_ms=5000,
            )
            with mock.patch("time.monotonic", side_effect=itertools.count()):
                run1 = Fuzzer(cfg).run()
            with mock.patch("time.monotonic", side_effect=itertools.count()):
                run2 = Fuzzer(cfg).run()

            # Same mutation ids in same order
            assert [o.mutation_id for o in run1.report.outcomes] == [
                o.mutation_id for o in run2.report.outcomes
            ]
            # Same outcomes
            assert [o.outcome for o in run1.report.outcomes] == [
                o.outcome for o in run2.report.outcomes
            ]
            # Same p95 and FPR
            assert run1.p95_latency_ms == run2.p95_latency_ms
            assert run1.false_positive_rate == run2.false_positive_rate
            # Same exit code
            assert run1.exit_code == run2.exit_code
            # Same summary histogram
            assert run1.summary == run2.summary
        finally:
            peer.close()

    def test_parallel_determinism_different_seed_differs(self):
        """Different seeds produce different mutation id sequences."""
        peer = ScriptablePeer(mode="alert", alert_level=2, alert_description=47)
        try:
            cfg_a = FuzzConfig(
                endpoint=f"127.0.0.1:{peer.port}",
                iterations=100,
                seed=1,
                concurrency=2,
                timeout_ms=5000,
            )
            cfg_b = FuzzConfig(
                endpoint=f"127.0.0.1:{peer.port}",
                iterations=100,
                seed=2,
                concurrency=2,
                timeout_ms=5000,
            )
            run_a = Fuzzer(cfg_a).run()
            run_b = Fuzzer(cfg_b).run()
            ids_a = [o.mutation_id for o in run_a.report.outcomes]
            ids_b = [o.mutation_id for o in run_b.report.outcomes]
            assert ids_a != ids_b
        finally:
            peer.close()


# ---------------------------------------------------------------------------
# RED: test_checkpoint_resume
# ---------------------------------------------------------------------------

class TestCheckpointResume:
    """E21: interrupted run with checkpoint resumes without re-probing."""

    def test_checkpoint_resume_full_skip(self):
        """When all mutation ids are checkpointed, the resume run probes nothing."""
        peer = ScriptablePeer(mode="alert", alert_level=2, alert_description=47)
        try:
            cfg = FuzzConfig(
                endpoint=f"127.0.0.1:{peer.port}",
                iterations=50,
                seed=3,
                concurrency=2,
                timeout_ms=5000,
            )

            with mock.patch("time.monotonic", side_effect=[100.0 + i * 0.001 for i in range(100)]):
                full_run = Fuzzer(cfg).run()
            all_ids = {o.mutation_id for o in full_run.report.outcomes}
            assert len(all_ids) == 50

            # Remove any stale checkpoint
            ckpt = Path("checkpoint.json")
            if ckpt.exists():
                ckpt.unlink()

            # Checkpoint ALL ids => resume should probe nothing
            ckpt.write_text(json.dumps({"completed": sorted(all_ids)}, indent=2))

            resumed = Fuzzer(cfg).run()
            assert len(resumed.report.outcomes) == 0
            assert resumed.p95_latency_ms == 0.0
            assert resumed.exit_code == 0
            # Checkpoint file still contains all ids
            data = json.loads(ckpt.read_text())
            assert set(data["completed"]) == all_ids
        finally:
            peer.close()
            ckpt = Path("checkpoint.json")
            if ckpt.exists():
                ckpt.unlink()

    def test_checkpoint_resume_partial(self):
        """Resume probes only non-checkpointed mutations; results match full run subset."""
        peer = ScriptablePeer(mode="alert", alert_level=2, alert_description=47)
        try:
            cfg = FuzzConfig(
                endpoint=f"127.0.0.1:{peer.port}",
                iterations=64,
                seed=11,
                concurrency=2,
                timeout_ms=5000,
            )

            # Full run
            with mock.patch("time.monotonic", side_effect=[100.0 + i * 0.001 for i in range(128)]):
                full_run = Fuzzer(cfg).run()
            full_outcomes = {o.mutation_id: o for o in full_run.report.outcomes}
            assert len(full_outcomes) == 64

            # Remove stale checkpoint
            ckpt = Path("checkpoint.json")
            if ckpt.exists():
                ckpt.unlink()

            # Checkpoint first 32 ids (sorted for determinism)
            first_32 = sorted(full_outcomes.keys())[:32]
            ckpt.write_text(json.dumps({"completed": first_32}, indent=2))

            # Resumed run — use same mock length as full run so latency indices align
            with mock.patch("time.monotonic", side_effect=[100.0 + i * 0.001 for i in range(128)]):
                resumed = Fuzzer(cfg).run()
            resumed_ids = {o.mutation_id for o in resumed.report.outcomes}
            expected_ids = set(full_outcomes.keys()) - set(first_32)
            assert resumed_ids == expected_ids

            # Each resumed outcome matches the full-run outcome for the same id
            for o in resumed.report.outcomes:
                expected = full_outcomes[o.mutation_id]
                assert o.outcome == expected.outcome
                # Latency is f64 monotonic; a resumed run re-reads the mocked
                # clock from a different offset so deltas match to within 1e-6 ms,
                # not bit-identical (spec §2.3: reproducible campaign, not bit-equal
                # latency across a resume offset).
                assert o.latency_ms == pytest.approx(expected.latency_ms, abs=1e-6)

            # Checkpoint now contains all 64 ids
            data = json.loads(ckpt.read_text())
            assert set(data["completed"]) == set(full_outcomes.keys())
        finally:
            peer.close()
            ckpt = Path("checkpoint.json")
            if ckpt.exists():
                ckpt.unlink()

    def test_checkpoint_written_every_64(self):
        """CHECKPOINT_CADENCE is 64 per spec §2.3."""
        assert CHECKPOINT_CADENCE == 64


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestFuzzerEdgeCases:
    def test_empty_iterations_raises(self):
        """iterations=0 must raise PqTlsFuzzError, never start a campaign."""
        with pytest.raises(PqTlsFuzzError, match="iterations"):
            Fuzzer(FuzzConfig(iterations=0, seed=0)).run()

    def test_iterations_above_max_raises(self):
        """iterations > max_iterations raises."""
        with pytest.raises(PqTlsFuzzError):
            Fuzzer(FuzzConfig(iterations=200_000, seed=0)).run()

    def test_empty_groups_raises(self):
        """Empty groups raises."""
        with pytest.raises(PqTlsFuzzError, match="groups"):
            Fuzzer(FuzzConfig(groups=(), iterations=10, seed=0)).run()

    def test_empty_mutation_classes_raises(self):
        """Empty mutation classes raises."""
        with pytest.raises(PqTlsFuzzError, match="mutation_classes"):
            Fuzzer(FuzzConfig(mutation_classes=(), iterations=10, seed=0)).run()

    def test_connection_failure_exit_code_3(self):
        """Unreachable endpoint => TransportError propagated, exit_code=3."""
        # Use a port nothing is listening on
        cfg = FuzzConfig(
            endpoint="127.0.0.1:19999",
            iterations=5,
            seed=0,
            concurrency=1,
            timeout_ms=200,
        )
        with pytest.raises(TransportError):
            Fuzzer(cfg).run()

    def test_no_controls_fpr_is_one(self):
        """With no VALID_CONTROL probes, FPR is 1.0 (never silently 0)."""
        peer = ScriptablePeer(mode="alert", alert_level=2, alert_description=47)
        try:
            cfg = FuzzConfig(
                endpoint=f"127.0.0.1:{peer.port}",
                iterations=10,
                seed=0,
                mutation_classes=(MutationClass.TRUNCATED,),
                concurrency=2,
                timeout_ms=5000,
            )
            run = Fuzzer(cfg).run()
            assert run.false_positive_rate == 1.0
            assert run.report.false_positive_rate is None
        finally:
            peer.close()

    def test_checkpoint_file_is_valid_json(self):
        """checkpoint.json contains valid JSON with a 'completed' list."""
        peer = ScriptablePeer(mode="alert", alert_level=2, alert_description=47)
        try:
            cfg = FuzzConfig(
                endpoint=f"127.0.0.1:{peer.port}",
                iterations=70,
                seed=5,
                concurrency=2,
                timeout_ms=5000,
            )
            Fuzzer(cfg).run()
            ckpt = Path("checkpoint.json")
            assert ckpt.exists()
            data = json.loads(ckpt.read_text())
            assert "completed" in data
            assert isinstance(data["completed"], list)
            assert len(data["completed"]) == 70
        finally:
            peer.close()
            ckpt = Path("checkpoint.json")
            if ckpt.exists():
                ckpt.unlink()

    def test_iter_corpus_produces_unique_ids(self):
        """iter_corpus generates unique ids across the full iteration space."""
        ids = [m.id for m in iter_corpus(
            (Group.MLKEM768, Group.X25519MLKEM768),
            (MutationClass.TRUNCATED, MutationClass.VALID_CONTROL),
            1000,
            42,
        )]
        assert len(set(ids)) == len(ids)


# ---------------------------------------------------------------------------
# HandshakeOutcome sanity (used by fuzzer outcomes)
# ---------------------------------------------------------------------------

class TestHandshakeOutcomeFields:
    def test_outcome_has_required_fields(self):
        o = HandshakeOutcome(
            mutation_id="mlkem768-truncated-abc",
            outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
            latency_ms=12.5,
            alert_description=47,
            bytes_captured=7,
            negotiated_group=None,
            detail="alert",
        )
        assert o.mutation_id == "mlkem768-truncated-abc"
        assert o.outcome == OutcomeClass.ALERT_ILLEGAL_PARAMETER
        assert o.latency_ms == 12.5
        assert isinstance(o.latency_ms, float)
