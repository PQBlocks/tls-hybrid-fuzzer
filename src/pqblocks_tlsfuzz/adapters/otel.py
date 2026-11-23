"""OpenTelemetry adapter (slice S20).

Export OpenTelemetry spans per probe (attributes: group, class, outcome,
latency_ms). Import-guarded on ``opentelemetry-api``: hard no-op without the
dependency — importing this module never raises, and ``maybe_export_span``
is a silent pass-through when otel is unavailable.
"""

from __future__ import annotations

from typing import Any

_OTEL_AVAILABLE = False
try:  # pragma: no cover - depends on optional dependency
    from opentelemetry import trace as _otel_trace
    from opentelemetry.trace import SpanKind as _OTelSpanKind
    from opentelemetry.trace import StatusCode as _OTelStatusCode
    _OTEL_AVAILABLE = True
except ImportError:
    _otel_trace = None  # type: ignore[assignment]
    _OTelSpanKind = None  # type: ignore[assignment, misc]
    _OTelStatusCode = None  # type: ignore[assignment, misc]


def _resolve_client_span_kind() -> int:
    """Return SpanKind.CLIENT as a plain int.

    opentelemetry.trace.SpanKind is an IntEnum with CLIENT == 2 (stable per the
    OTel spec). When the real package is importable we use its member (kept as
    int); otherwise (dependency absent, or a non-int stand-in such as a test
    double) we fall back to the spec value 2.
    """
    if _OTelSpanKind is not None:
        candidate = getattr(_OTelSpanKind, "CLIENT", None)
        if isinstance(candidate, int):
            return int(candidate)
    return 2


_SPAN_KIND_CLIENT = _resolve_client_span_kind()


class OTelSpanExporter:
    """Export one span per probe to an OpenTelemetry tracer provider.

    If ``opentelemetry-api`` is not installed, all methods are no-ops and the
    exporter is safe to construct and call.
    """

    def __init__(self, tracer_provider: Any = None, service_name: str = "pqblocks-tlsfuzz") -> None:
        self._available = _OTEL_AVAILABLE
        self._tracer = None
        if self._available and _otel_trace is not None:
            if tracer_provider is None:
                tracer_provider = _otel_trace.get_tracer_provider()
            self._tracer = _otel_trace.get_tracer(service_name, tracer_provider=tracer_provider)

    def export_span(
        self,
        *,
        group: str,
        mutation_class: str,
        outcome: str,
        latency_ms: float,
        mutation_id: str,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        """Start and end one span for a probe. No-op when otel is unavailable."""
        if not self._available or self._tracer is None:
            return
        span_name = f"pqblocks.tlsfuzz.{group}.{mutation_class}"
        span_attrs: dict[str, Any] = {
            "pqblocks.group": group,
            "pqblocks.mutation_class": mutation_class,
            "pqblocks.outcome": outcome,
            "pqblocks.latency_ms": latency_ms,
            "pqblocks.mutation_id": mutation_id,
        }
        if attributes:
            span_attrs.update(attributes)
        # _SPAN_KIND_CLIENT is SpanKind.CLIENT (IntEnum) when the real package is
        # importable, else the spec literal 2 — Pyright cannot see the fallback,
        # so suppress the arg-type complaint for the optional-dependency path.
        with self._tracer.start_as_current_span(
            span_name, kind=_SPAN_KIND_CLIENT  # type: ignore[arg-type]
        ) as span:
            for key, value in span_attrs.items():
                span.set_attribute(key, value)
            if _OTelStatusCode is not None and outcome not in ("accepted", "valid_control"):
                span.set_status(_OTelStatusCode.ERROR, f"outcome={outcome}")


def maybe_export_span(
    *,
    group: str,
    mutation_class: str,
    outcome: str,
    latency_ms: float,
    mutation_id: str,
    attributes: dict[str, Any] | None = None,
) -> None:
    """Convenience function: export one span if OTel is available, else no-op.

    Safe to call anywhere without checking import status first.
    """
    exporter = OTelSpanExporter()
    exporter.export_span(
        group=group,
        mutation_class=mutation_class,
        outcome=outcome,
        latency_ms=latency_ms,
        mutation_id=mutation_id,
        attributes=attributes,
    )