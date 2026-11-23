"""Enterprise adapter package for pqblocks_tlsfuzz (slices S17-S20).

Provides framework-middleware adapters that translate FuzzReport into
CI-native formats: GitHub Actions SARIF + annotations, GitLab CI codequality,
pytest plugin, and optional OpenTelemetry spans.

Each adapter follows the middleware contract: import-safe (hard no-op when
optional dependencies are absent), no side effects on import, and a single
public callable that consumes a FuzzReport.
"""

from pqblocks_tlsfuzz.adapters.github_actions import (
    GHActionAnnotations,
    to_annotations,
)
from pqblocks_tlsfuzz.adapters.gitlab_ci import (
    GitLabCodequality,
    to_codequality,
)
from pqblocks_tlsfuzz.adapters.pytest_plugin import (
    PQTLsFuzzPytestPlugin,
    pytest_configure,
)
from pqblocks_tlsfuzz.adapters.otel import (
    OTelSpanExporter,
    maybe_export_span,
)

__all__ = [
    "GHActionAnnotations",
    "to_annotations",
    "GitLabCodequality",
    "to_codequality",
    "PQTLsFuzzPytestPlugin",
    "pytest_configure",
    "OTelSpanExporter",
    "maybe_export_span",
]