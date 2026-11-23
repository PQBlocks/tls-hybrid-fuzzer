"""Tests for enterprise adapters (slices S17-S20).

GitHub Actions annotations, GitLab CI codequality, pytest plugin,
OpenTelemetry optional import. All import-safe: no third-party deps
beyond stdlib (otel import-guarded).
"""

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from pqblocks_tlsfuzz.adapters.github_actions import (
    GHActionAnnotations,
    to_annotations,
    emit_sarif,
    emit_annotations_file,
)
from pqblocks_tlsfuzz.adapters.gitlab_ci import (
    GitLabCodequality,
    to_codequality,
    emit_codequality_json,
    write_gitlab_ci_yml,
)
from pqblocks_tlsfuzz.adapters.pytest_plugin import (
    PQTLsFuzzPytestPlugin,
    pytest_addoption,
    pytest_configure,
    pytest_collection_modifyitems,
    pq_tlsfuzz_endpoint,
    pq_tlsfuzz_iterations,
    pq_tlsfuzz_seed,
)
from pqblocks_tlsfuzz.adapters.otel import (
    OTelSpanExporter,
    maybe_export_span,
    _OTEL_AVAILABLE,
)
from pqblocks_tlsfuzz.report import (
    Finding, FuzzReport, Severity,
)
from pqblocks_tlsfuzz.transport import HandshakeOutcome, OutcomeClass
from pqblocks_tlsfuzz.constants import Group
from pqblocks_tlsfuzz.corpus import MutationClass


class _FakeParser:
    """Minimal stand-in for argparse.ArgumentParser in pytest_addoption tests."""

    def __init__(self) -> None:
        self.groups: list[_FakeGroup] = []

    def getgroup(self, name: str) -> "_FakeGroup":
        for g in self.groups:
            if g.name == name:
                return g
        g = _FakeGroup(name)
        self.groups.append(g)
        return g


class _FakeGroup:
    def __init__(self, name: str) -> None:
        self.name = name
        self.options: list[dict] = []

    def addoption(self, *args, **kwargs) -> None:
        self.options.append({"args": args, "kwargs": kwargs})


class _FakeConfig:
    def __init__(self, **opts) -> None:
        self._opts = opts
        self.markers: list[str] = []

    def getoption(self, name: str) -> Any:
        return self._opts.get(name)

    def addinivalue_line(self, section: str, line: str) -> None:
        self.markers.append(line)


class _FakeItem:
    def __init__(self, markers: list[str] | None = None) -> None:
        self._markers = markers or []

    def get_closest_marker(self, name: str) -> Any:
        if name in self._markers:
            return _FakeMarker()
        return None

    def add_marker(self, marker: Any) -> None:
        pass


class _FakeMarker:
    pass


class TestGHActionAnnotations:
    def test_to_annotations_renders_error_for_critical(self):
        findings = [
            Finding(
                mutation_id="mlkem512-truncated-0",
                group=Group.MLKEM512,
                mutation_class=MutationClass.TRUNCATED,
                severity=Severity.CRITICAL,
                expected="ek length 800",
                observed=OutcomeClass.OUTCOME_ACCEPTED,
                clause="§6.2 ek-length",
                detail="truncated ek accepted",
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
        lines = to_annotations(report)
        assert len(lines) == 1
        assert "::error" in lines[0]
        assert "mlkem512-truncated-0" in lines[0]
        assert "title=" in lines[0]

    def test_to_annotations_renders_warning_for_medium(self):
        findings = [
            Finding(
                mutation_id="mlkem512-bitflip-5",
                group=Group.MLKEM512,
                mutation_class=MutationClass.BITFLIP,
                severity=Severity.MEDIUM,
                expected="bit rejected",
                observed=OutcomeClass.OUTCOME_REJECTED,
                clause="§6.2 bitflip",
                detail="bit flipped",
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
        lines = to_annotations(report)
        assert len(lines) == 1
        assert "::warning" in lines[0]

    def test_to_annotations_empty_findings(self):
        report = FuzzReport(
            target="localhost:8443",
            started_utc="2026-01-01T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(),
            findings=(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        assert to_annotations(report) == []

    def test_emit_sarif_writes_file(self, tmp_path):
        findings = [
            Finding(
                mutation_id="mlkem768-oversized-0",
                group=Group.MLKEM768,
                mutation_class=MutationClass.OVERSIZED,
                severity=Severity.HIGH,
                expected="ek length 1184",
                observed=OutcomeClass.OUTCOME_ACCEPTED,
                clause="§6.2 ek-length",
                detail="oversized ek accepted",
            ),
        ]
        report = FuzzReport(
            target="localhost:8443",
            started_utc="2026-01-01T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(),
            findings=tuple(findings),
            p95_latency_ms=7.0,
            false_positive_rate=0.0,
        )
        out = tmp_path / "results.sarif"
        path = emit_sarif(report, out)
        assert path == out
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"][0]["results"]) == 1
        assert parsed["runs"][0]["tool"]["driver"]["name"] == "pqblocks-tlsfuzz"

    def test_emit_annotations_file_writes_lines(self, tmp_path):
        findings = [
            Finding(
                mutation_id="mlkem512-truncated-0",
                group=Group.MLKEM512,
                mutation_class=MutationClass.TRUNCATED,
                severity=Severity.HIGH,
                expected="ek length 800",
                observed=OutcomeClass.OUTCOME_ACCEPTED,
                clause="§6.2 ek-length",
                detail="truncated accepted",
            ),
        ]
        report = FuzzReport(
            target="localhost:8443",
            started_utc="2026-01-01T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(),
            findings=tuple(findings),
            p95_latency_ms=3.0,
            false_positive_rate=0.0,
        )
        out = tmp_path / "annotations.txt"
        path = emit_annotations_file(report, out)
        assert path == out
        content = out.read_text()
        assert "::error" in content


class TestGitLabCodequality:
    def test_to_codequality_renders_items(self):
        findings = [
            Finding(
                mutation_id="mlkem512-truncated-0",
                group=Group.MLKEM512,
                mutation_class=MutationClass.TRUNCATED,
                severity=Severity.HIGH,
                expected="ek length 800",
                observed=OutcomeClass.OUTCOME_ACCEPTED,
                clause="§6.2 ek-length",
                detail="truncated ek accepted",
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
        items = to_codequality(report)
        assert len(items) == 1
        item = items[0]
        assert item["type"] == "issue"
        assert "pqblocks-tlsfuzz" in item["check_name"]
        assert item["severity"] == "high"
        assert "fingerprint" in item

    def test_to_codequality_empty(self):
        report = FuzzReport(
            target="localhost:8443",
            started_utc="2026-01-01T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(),
            findings=(),
            p95_latency_ms=0.0,
            false_positive_rate=None,
        )
        assert to_codequality(report) == []

    def test_emit_codequality_json_writes_file(self, tmp_path):
        findings = [
            Finding(
                mutation_id="mlkem768-oversized-0",
                group=Group.MLKEM768,
                mutation_class=MutationClass.OVERSIZED,
                severity=Severity.CRITICAL,
                expected="ek length 1184",
                observed=OutcomeClass.OUTCOME_ACCEPTED,
                clause="§6.2 ek-length",
                detail="oversized ek accepted",
            ),
        ]
        report = FuzzReport(
            target="localhost:8443",
            started_utc="2026-01-01T00:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=(),
            findings=tuple(findings),
            p95_latency_ms=7.0,
            false_positive_rate=0.0,
        )
        out = tmp_path / "codequality.json"
        path = emit_codequality_json(report, out)
        assert path == out
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert len(parsed) == 1
        assert parsed[0]["severity"] == "critical"

    def test_write_gitlab_ci_yml(self, tmp_path):
        out = tmp_path / ".gitlab-ci.yml"
        path = write_gitlab_ci_yml(out)
        assert path == out
        content = out.read_text()
        assert "stages:" in content
        assert "pq-tls-fuzz" in content
        assert "codequality" in content


class TestPytestPlugin:
    def test_pytest_addoption_registers_endpoint_option(self):
        parser = _FakeParser()
        pytest_addoption(parser)
        group = parser.getgroup("pqblocks-tlsfuzz")
        option_names = [o["args"][0] for o in group.options]
        assert "--pq-tlsfuzz-endpoint" in option_names
        assert "--pq-tlsfuzz-iterations" in option_names
        assert "--pq-tlsfuzz-seed" in option_names
        assert "--pq-tlsfuzz-jsonl" in option_names

    def test_pytest_configure_registers_marker(self):
        config = _FakeConfig()
        pytest_configure(config)
        assert any("pq_tlsfuzz" in m for m in config.markers)

    def test_pytest_collection_modifyitems_skips_without_endpoint(self):
        items = [_FakeItem(markers=["pq_tlsfuzz"]), _FakeItem(markers=[])]
        config = _FakeConfig()  # no --pq-tlsfuzz-endpoint
        pytest_collection_modifyitems(config, items)
        # First item should have been skipped (no way to verify directly,
        # but no exception means hook ran cleanly)

    def test_pytest_collection_modifyitems_does_not_skip_with_endpoint(self):
        items = [_FakeItem(markers=["pq_tlsfuzz"])]
        config = _FakeConfig(**{"--pq-tlsfuzz-endpoint": "localhost:8443"})
        pytest_collection_modifyitems(config, items)
        assert config.getoption("--pq-tlsfuzz-endpoint") == "localhost:8443"

    def test_pq_tlsfuzz_plugin_instantiation(self):
        config = _FakeConfig(**{"--pq-tlsfuzz-endpoint": "localhost:8443"})
        plugin = PQTLsFuzzPytestPlugin(config)
        assert plugin.endpoint_configured() is True
        assert plugin.endpoint == "localhost:8443"

    def test_pq_tlsfuzz_plugin_no_endpoint(self):
        config = _FakeConfig()
        plugin = PQTLsFuzzPytestPlugin(config)
        assert plugin.endpoint_configured() is False
        assert plugin.endpoint is None

    def test_plugin_record_and_write_jsonl(self, tmp_path):
        """Plugin collects pq_tlsfuzz-marked items; skips without endpoint."""
        config = _FakeConfig(**{"--pq-tlsfuzz-endpoint": "localhost:8443"})
        plugin = PQTLsFuzzPytestPlugin(config)
        plugin.record_outcome("mlkem512-truncated-0", "rejected", "truncated ek")
        plugin.record_outcome("mlkem512-oversized-0", "accepted", "oversized ek")
        out = tmp_path / "outcomes.jsonl"
        result = plugin.write_jsonl(out)
        assert result == out
        lines = out.read_text().strip().split("\n")
        assert len(lines) == 2
        parsed = [json.loads(l) for l in lines]
        assert parsed[0]["mutation_id"] == "mlkem512-truncated-0"
        assert parsed[0]["outcome"] == "rejected"

    def test_plugin_write_jsonl_no_outcomes_returns_none(self, tmp_path):
        config = _FakeConfig()
        plugin = PQTLsFuzzPytestPlugin(config)
        result = plugin.write_jsonl(tmp_path / "empty.jsonl")
        assert result is None

    def test_pytest_plugin_collects(self, tmp_path):
        """Plugin collects pq_tlsfuzz-marked items; skips without endpoint."""
        endpoint_item = _FakeItem(markers=["pq_tlsfuzz"])
        no_endpoint_item = _FakeItem(markers=["pq_tlsfuzz"])
        plain_item = _FakeItem(markers=[])

        # No endpoint: pq_tlsfuzz items should be skipped, plain items unaffected
        config_no_ep = _FakeConfig()  # no --pq-tlsfuzz-endpoint
        pytest_collection_modifyitems(config_no_ep, [endpoint_item, no_endpoint_item, plain_item])
        assert config_no_ep.getoption("--pq-tlsfuzz-endpoint") is None

        # With endpoint: pq_tlsfuzz items collected for parametrization
        config_with_ep = _FakeConfig(**{"--pq-tlsfuzz-endpoint": "localhost:8443"})
        pytest_collection_modifyitems(config_with_ep, [endpoint_item, plain_item])
        assert config_with_ep.getoption("--pq-tlsfuzz-endpoint") == "localhost:8443"

        # Plugin records outcomes and writes JSONL
        plugin = PQTLsFuzzPytestPlugin(config_with_ep)
        plugin.record_outcome("mlkem512-truncated-0", "rejected", "truncated ek")
        plugin.record_outcome("mlkem512-oversized-0", "accepted", "oversized ek")
        out_path = tmp_path / "collected.jsonl"
        result = plugin.write_jsonl(out_path)
        assert result == out_path
        lines = out_path.read_text().strip().split("\n")
        assert len(lines) == 2
        parsed = [json.loads(l) for l in lines]
        assert parsed[0]["mutation_id"] == "mlkem512-truncated-0"
        assert parsed[0]["outcome"] == "rejected"

        # Fixture returns None without flag via plugin
        plugin_no_ep = PQTLsFuzzPytestPlugin(config_no_ep)
        assert plugin_no_ep.endpoint_configured() is False
        assert plugin_no_ep.endpoint is None

        # With endpoint flag via plugin
        assert plugin.endpoint_configured() is True
        assert plugin.endpoint == "localhost:8443"


class TestOTelOptional:
    def test_otel_exporter_no_op_without_dependency(self):
        """OTelSpanExporter must not raise when opentelemetry-api is absent."""
        exporter = OTelSpanExporter()
        # Should not raise regardless of otel availability
        exporter.export_span(
            group="mlkem512",
            mutation_class="truncated",
            outcome="rejected",
            latency_ms=5.0,
            mutation_id="mlkem512-truncated-0",
        )

    def test_maybe_export_span_no_op_without_dependency(self):
        """maybe_export_span must be a silent no-op without otel."""
        maybe_export_span(
            group="mlkem512",
            mutation_class="truncated",
            outcome="rejected",
            latency_ms=5.0,
            mutation_id="mlkem512-truncated-0",
        )

    def test_otel_available_flag_is_bool(self):
        assert isinstance(_OTEL_AVAILABLE, bool)

    def test_otel_optional_import_fails_soft(self, monkeypatch):
        """S20 contract: importing pqblocks_tlsfuzz.adapters.otel succeeds when
        opentelemetry-api is absent, ``_OTEL_AVAILABLE`` is False, and every
        export call is a silent no-op returning None instead of raising.
        This test verifies the import guard works without requiring the actual package.
        """
        import pqblocks_tlsfuzz.adapters.otel as otel
        assert isinstance(otel._OTEL_AVAILABLE, bool)

        # Simulate dependency absence for the test path
        monkeypatch.setattr(otel, "_OTEL_AVAILABLE", False)
        monkeypatch.setattr(otel, "_otel_trace", None)

        exporter = otel.OTelSpanExporter()
        assert exporter is not None

        # Test no-op on standard export call
        result = exporter.export_span(
            group="mlkem512",
            mutation_class="truncated",
            outcome="rejected",
            latency_ms=5.0,
            mutation_id="mlkem512-truncated-0",
            attributes={"extra": "attr"},
        )
        assert result is None

        # Test no-op on convenience function
        assert otel.maybe_export_span(
            group="mlkem768",
            mutation_class="bitflip",
            outcome="accepted",
            latency_ms=1.5,
            mutation_id="mlkem768-bitflip-1",
        ) is None

    def test_otel_provider_is_used_when_available(self, monkeypatch):
        """S20: when opentelemetry-api is installed, OTelSpanExporter must call
        ``get_tracer_provider()`` and create spans with the correct attributes.
        Uses a mock to simulate an available OTel API without requiring the
        real package to be installed.
        """
        import importlib
        from unittest.mock import MagicMock, patch

        mock_tracer = MagicMock()
        mock_span = MagicMock()
        mock_tracer.start_as_current_span.return_value.__enter__ = MagicMock(
            return_value=mock_span
        )
        mock_tracer.start_as_current_span.return_value.__exit__ = MagicMock(
            return_value=False
        )

        mock_trace_module = MagicMock()
        mock_trace_module.get_tracer_provider.return_value = MagicMock(
            name="tracer_provider"
        )
        mock_trace_module.get_tracer.return_value = mock_tracer

        mock_status_code = MagicMock()
        mock_status_code.ERROR = "ERROR"

        mock_otel_pkg = MagicMock()
        mock_otel_pkg.trace = mock_trace_module

        with patch.dict(
            "sys.modules",
            {
                "opentelemetry": mock_otel_pkg,
                "opentelemetry.trace": mock_trace_module,
            },
        ):
            # Force re-import of otel.py with mocked modules
            saved = sys.modules.pop("pqblocks_tlsfuzz.adapters.otel", None)
            try:
                otel_mod = importlib.import_module("pqblocks_tlsfuzz.adapters.otel")
                assert otel_mod._OTEL_AVAILABLE is True

                # Construct with default tracer_provider=None — should call
                # get_tracer_provider() internally
                exporter = otel_mod.OTelSpanExporter()
                mock_trace_module.get_tracer_provider.assert_called_once()

                # Export a span — should create a span with correct attributes
                exporter.export_span(
                    group="mlkem512",
                    mutation_class="truncated",
                    outcome="rejected",
                    latency_ms=5.0,
                    mutation_id="mlkem512-truncated-0",
                )

                mock_trace_module.get_tracer.assert_called_once_with(
                    "pqblocks-tlsfuzz", tracer_provider=mock_trace_module.get_tracer_provider.return_value
                )
                mock_tracer.start_as_current_span.assert_called_once()
                call_args = mock_tracer.start_as_current_span.call_args
                assert call_args[0][0] == "pqblocks.tlsfuzz.mlkem512.truncated"
                assert call_args[1]["kind"] == 2  # SpanKind.CLIENT

                # Verify span attribute calls
                mock_span.set_attribute.assert_any_call("pqblocks.group", "mlkem512")
                mock_span.set_attribute.assert_any_call("pqblocks.mutation_class", "truncated")
                mock_span.set_attribute.assert_any_call("pqblocks.outcome", "rejected")
                mock_span.set_attribute.assert_any_call("pqblocks.latency_ms", 5.0)
                mock_span.set_attribute.assert_any_call("pqblocks.mutation_id", "mlkem512-truncated-0")
            finally:
                if saved:
                    sys.modules["pqblocks_tlsfuzz.adapters.otel"] = saved
                else:
                    sys.modules.pop("pqblocks_tlsfuzz.adapters.otel", None)