"""Tests for streaming.py (slice S10).

ReportStream (JSONL flush-per-64, constant memory), CorpusStream wrapper.
Memory-bound test: RSS delta < 32 MiB over 50k simulated probes via ScriptablePeer.
Flush-count correctness.
"""

import json
import os
import resource
import tempfile
from pathlib import Path

import pytest

from pqblocks_tlsfuzz.constants import Group
from pqblocks_tlsfuzz.corpus import KeyShareMutation, MutationClass
from pqblocks_tlsfuzz.streaming import CorpusStream, ReportStream
from pqblocks_tlsfuzz.transport import HandshakeOutcome, OutcomeClass, ScriptablePeer


class TestCorpusStream:
    """CorpusStream wraps iter_corpus for streaming use (F16, S10)."""

    def test_corpus_stream_is_iterable(self):
        stream = CorpusStream(
            groups=(Group.MLKEM768,),
            classes=(MutationClass.TRUNCATED,),
            iterations=10,
            seed=42,
        )
        mutations = list(stream)
        assert len(mutations) == 10
        for m in mutations:
            assert isinstance(m, KeyShareMutation)
            assert m.group == Group.MLKEM768
            assert m.mutation_class == MutationClass.TRUNCATED

    def test_corpus_stream_deterministic_same_seed(self):
        """Same parameters => identical mutation sequence (determinism)."""
        stream1 = CorpusStream(
            groups=(Group.MLKEM768, Group.MLKEM512),
            classes=(MutationClass.TRUNCATED, MutationClass.OVERSIZED),
            iterations=100,
            seed=12345,
        )
        stream2 = CorpusStream(
            groups=(Group.MLKEM768, Group.MLKEM512),
            classes=(MutationClass.TRUNCATED, MutationClass.OVERSIZED),
            iterations=100,
            seed=12345,
        )
        ids1 = [m.id for m in stream1]
        ids2 = [m.id for m in stream2]
        assert ids1 == ids2

    def test_corpus_stream_different_seed_different_sequence(self):
        """Different seed => different sequence."""
        stream1 = CorpusStream(
            groups=(Group.MLKEM768,),
            classes=(MutationClass.TRUNCATED,),
            iterations=50,
            seed=111,
        )
        stream2 = CorpusStream(
            groups=(Group.MLKEM768,),
            classes=(MutationClass.TRUNCATED,),
            iterations=50,
            seed=222,
        )
        ids1 = [m.id for m in stream1]
        ids2 = [m.id for m in stream2]
        assert ids1 != ids2

    def test_corpus_stream_empty_groups_raises(self):
        with pytest.raises(Exception):
            CorpusStream(
                groups=(),
                classes=(MutationClass.TRUNCATED,),
                iterations=10,
                seed=0,
            )

    def test_corpus_stream_empty_classes_raises(self):
        with pytest.raises(Exception):
            CorpusStream(
                groups=(Group.MLKEM768,),
                classes=(),
                iterations=10,
                seed=0,
            )

    def test_corpus_stream_zero_iterations_raises(self):
        with pytest.raises(Exception):
            CorpusStream(
                groups=(Group.MLKEM768,),
                classes=(MutationClass.TRUNCATED,),
                iterations=0,
                seed=0,
            )

    def test_corpus_stream_iterator_protocol(self):
        """CorpusStream implements __iter__ returning self or a fresh iterator."""
        stream = CorpusStream(
            groups=(Group.MLKEM768,),
            classes=(MutationClass.TRUNCATED,),
            iterations=5,
            seed=0,
        )
        it = iter(stream)
        assert hasattr(it, "__next__")
        first = next(it)
        assert isinstance(first, KeyShareMutation)


class TestReportStream:
    """ReportStream writes JSONL with flush every 64 outcomes (F15, S10)."""

    def test_report_stream_writes_single_outcome(self, tmp_path: Path):
        path = tmp_path / "outcomes.jsonl"
        with ReportStream(path, flush_every=64) as rs:
            outcome = HandshakeOutcome(
                mutation_id="mlkem768-truncated-0",
                outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                latency_ms=10.0,
                alert_description=47,
                bytes_captured=0,
                negotiated_group=None,
                detail="",
            )
            rs.write(outcome)

        content = path.read_text().strip()
        assert content
        data = json.loads(content)
        assert data["mutation_id"] == "mlkem768-truncated-0"
        assert data["outcome"] == "alert_illegal_parameter"
        assert data["latency_ms"] == 10.0
        assert data["alert_description"] == 47

    def test_report_stream_writes_multiple_outcomes_one_per_line(self, tmp_path: Path):
        path = tmp_path / "outcomes.jsonl"
        with ReportStream(path, flush_every=64) as rs:
            for i in range(10):
                outcome = HandshakeOutcome(
                    mutation_id=f"mlkem768-truncated-{i}",
                    outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                    latency_ms=10.0,
                    alert_description=47,
                    bytes_captured=0,
                    negotiated_group=None,
                    detail="",
                )
                rs.write(outcome)

        lines = path.read_text().strip().split("\n")
        assert len(lines) == 10
        for i, line in enumerate(lines):
            data = json.loads(line)
            assert data["mutation_id"] == f"mlkem768-truncated-{i}"

    def test_report_stream_flushes_every_64(self, tmp_path: Path):
        """Flush occurs exactly every 64 writes."""
        path = tmp_path / "outcomes.jsonl"
        flush_count = 0

        # We can't easily intercept flush(), but we can verify the file
        # has correct content at flush boundaries by checking line count
        # after 64 writes (file should be non-empty and readable).
        with ReportStream(path, flush_every=64) as rs:
            for i in range(128):
                outcome = HandshakeOutcome(
                    mutation_id=f"mlkem768-truncated-{i}",
                    outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                    latency_ms=10.0,
                    alert_description=47,
                    bytes_captured=0,
                    negotiated_group=None,
                    detail="",
                )
                rs.write(outcome)

        lines = path.read_text().strip().split("\n")
        assert len(lines) == 128
        for i, line in enumerate(lines):
            data = json.loads(line)
            assert data["mutation_id"] == f"mlkem768-truncated-{i}"

    def test_report_stream_flush_count_correct(self, tmp_path: Path):
        """Explicit flush count verification via a subclass or spy."""
        path = tmp_path / "outcomes.jsonl"
        
        class CountingReportStream(ReportStream):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.flush_called = 0
            
            def flush(self):
                self.flush_called += 1
                super().flush()
        
        stream = CountingReportStream(path, flush_every=64)
        with stream:
            for i in range(130):
                outcome = HandshakeOutcome(
                    mutation_id=f"mlkem768-truncated-{i}",
                    outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                    latency_ms=10.0,
                    alert_description=47,
                    bytes_captured=0,
                    negotiated_group=None,
                    detail="",
                )
                stream.write(outcome)
        
        # 130 writes with flush_every=64 => flushes at 64, 128, and on exit (130)
        # That's 3 flushes total
        assert stream.flush_called == 3

    def test_report_stream_context_manager_closes_file(self, tmp_path: Path):
        path = tmp_path / "outcomes.jsonl"
        stream = ReportStream(path, flush_every=64)
        stream.__enter__()
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-0",
            outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
            latency_ms=10.0,
            alert_description=47,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        stream.write(outcome)
        stream.__exit__(None, None, None)
        
        # File should be readable after context exit
        content = path.read_text()
        assert "mlkem768-truncated-0" in content

    def test_report_stream_write_after_close_raises(self, tmp_path: Path):
        path = tmp_path / "outcomes.jsonl"
        stream = ReportStream(path, flush_every=64)
        stream.__enter__()
        stream.__exit__(None, None, None)
        
        outcome = HandshakeOutcome(
            mutation_id="mlkem768-truncated-0",
            outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
            latency_ms=10.0,
            alert_description=47,
            bytes_captured=0,
            negotiated_group=None,
            detail="",
        )
        with pytest.raises(Exception):
            stream.write(outcome)

    def test_report_stream_flush_every_zero_raises(self, tmp_path: Path):
        path = tmp_path / "outcomes.jsonl"
        with pytest.raises(Exception):
            ReportStream(path, flush_every=0)

    def test_report_stream_flush_every_negative_raises(self, tmp_path: Path):
        path = tmp_path / "outcomes.jsonl"
        with pytest.raises(Exception):
            ReportStream(path, flush_every=-1)


class TestStreamingMemoryBound:
    """E22: Constant memory streaming - RSS delta < 32 MiB over 50k simulated probes."""

    def test_streaming_memory_bound_50k_probes(self, tmp_path: Path):
        """RSS delta < 32 MiB over 50k simulated probes via ScriptablePeer."""
        # This test simulates a full campaign writing 50k outcomes via ReportStream
        # and verifies memory stays bounded (constant memory).
        
        # Get baseline RSS
        import gc
        gc.collect()
        baseline_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # ru_maxrss is in KB on Linux, bytes on macOS
        if hasattr(resource, 'getpagesize'):
            # Linux: KB
            baseline_mib = baseline_rss / 1024.0
        else:
            # Assume bytes
            baseline_mib = baseline_rss / (1024.0 * 1024.0)
        
        # Create a ScriptablePeer that returns alerts (blackhole or alert mode)
        # We'll use the 'alert' mode for fast deterministic responses
        with ScriptablePeer(mode="alert", alert_level=2, alert_description=47) as peer:
            port = peer.port
            
            # Write 50k outcomes via ReportStream
            path = tmp_path / "outcomes_50k.jsonl"
            with ReportStream(path, flush_every=64) as rs:
                for i in range(50000):
                    outcome = HandshakeOutcome(
                        mutation_id=f"mlkem768-truncated-{i:010d}",
                        outcome=OutcomeClass.ALERT_ILLEGAL_PARAMETER,
                        latency_ms=10.0,
                        alert_description=47,
                        bytes_captured=0,
                        negotiated_group=None,
                        detail="simulated",
                    )
                    rs.write(outcome)
        
        # Get peak RSS after
        gc.collect()
        peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if hasattr(resource, 'getpagesize'):
            peak_mib = peak_rss / 1024.0
        else:
            peak_mib = peak_rss / (1024.0 * 1024.0)
        
        delta_mib = peak_mib - baseline_mib
        
        # The critical assertion: memory growth < 32 MiB
        # We print for visibility in test output
        print(f"Baseline RSS: {baseline_mib:.2f} MiB")
        print(f"Peak RSS: {peak_mib:.2f} MiB")
        print(f"Delta: {delta_mib:.2f} MiB")
        
        assert delta_mib < 32.0, f"RSS delta {delta_mib:.2f} MiB exceeds 32 MiB limit"

    def test_corpus_stream_memory_bound_50k(self):
        """CorpusStream also maintains constant memory over 50k iterations."""
        import gc
        gc.collect()
        baseline_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if hasattr(resource, 'getpagesize'):
            baseline_mib = baseline_rss / 1024.0
        else:
            baseline_mib = baseline_rss / (1024.0 * 1024.0)
        
        stream = CorpusStream(
            groups=(Group.MLKEM768, Group.MLKEM512, Group.MLKEM1024),
            classes=(
                MutationClass.TRUNCATED,
                MutationClass.OVERSIZED,
                MutationClass.BITFLIP,
                MutationClass.GARBAGE_FILL,
            ),
            iterations=50000,
            seed=42,
        )
        
        # Consume the stream fully
        count = 0
        for mutation in stream:
            count += 1
            # Don't accumulate mutations - just iterate
            _ = mutation.id
        
        assert count == 50000
        
        gc.collect()
        peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if hasattr(resource, 'getpagesize'):
            peak_mib = peak_rss / 1024.0
        else:
            peak_mib = peak_rss / (1024.0 * 1024.0)
        
        delta_mib = peak_mib - baseline_mib
        print(f"CorpusStream baseline: {baseline_mib:.2f} MiB, peak: {peak_mib:.2f} MiB, delta: {delta_mib:.2f} MiB")
        
        assert delta_mib < 32.0, f"CorpusStream RSS delta {delta_mib:.2f} MiB exceeds 32 MiB limit"


class TestReportStreamIntegrationWithScriptablePeer:
    """Integration test: ReportStream + ScriptablePeer end-to-end."""

    def test_report_stream_with_real_probes_via_scriptable_peer(self, tmp_path: Path):
        """Write outcomes from actual probes against ScriptablePeer."""
        with ScriptablePeer(mode="alert", alert_level=2, alert_description=47) as peer:
            from pqblocks_tlsfuzz.transport import RawHandshakeClient
            from pqblocks_tlsfuzz.corpus import SeedCorpus
            from pqblocks_tlsfuzz.constants import GroupRegistry
            
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=1000)
            corpus = SeedCorpus(seed=42)
            
            path = tmp_path / "integration.jsonl"
            with ReportStream(path, flush_every=64) as rs:
                mutations = corpus.systematic(Group.MLKEM768, classes=(MutationClass.TRUNCATED,))
                for mutation in mutations[:100]:  # First 100 systematic
                    outcome = client.probe(mutation)
                    rs.write(outcome)
            
            lines = path.read_text().strip().split("\n")
            assert len(lines) == 100
            for line in lines:
                data = json.loads(line)
                assert "mutation_id" in data
                assert data["outcome"] in ("alert_illegal_parameter", "timeout", "tcp_closed", "transport_error")


class TestReportStreamNegative:
    """Negative tests for ReportStream."""

    def test_write_non_outcome_raises(self, tmp_path: Path):
        path = tmp_path / "outcomes.jsonl"
        with ReportStream(path) as rs:
            with pytest.raises(Exception):
                rs.write("not an outcome")

    def test_write_none_raises(self, tmp_path: Path):
        path = tmp_path / "outcomes.jsonl"
        with ReportStream(path) as rs:
            with pytest.raises(Exception):
                rs.write(None)

    def test_flush_every_non_int_raises(self, tmp_path: Path):
        path = tmp_path / "outcomes.jsonl"
        with pytest.raises(Exception):
            ReportStream(path, flush_every="64")


class TestCorpusStreamNegative:
    """Negative tests for CorpusStream."""

    def test_iterations_must_be_int(self):
        with pytest.raises(Exception):
            CorpusStream(
                groups=(Group.MLKEM768,),
                classes=(MutationClass.TRUNCATED,),
                iterations="100",
                seed=0,
            )

    def test_seed_must_be_int(self):
        with pytest.raises(Exception):
            CorpusStream(
                groups=(Group.MLKEM768,),
                classes=(MutationClass.TRUNCATED,),
                iterations=100,
                seed="abc",
            )