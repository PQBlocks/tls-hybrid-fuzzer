"""Public API for pqblocks_tlsfuzz."""

from .adapters import (
    GHActionAnnotations,
    GitLabCodequality,
    OTelSpanExporter,
    PQTLsFuzzPytestPlugin,
    maybe_export_span,
    to_annotations,
    to_codequality,
)
from .config import FuzzConfig, load_config
from .constants import (
    Group,
    GroupSpec,
    GroupRegistry,
    CorpusError,
    MLKEMParams,
    MLKEM512_PARAMS,
    MLKEM768_PARAMS,
    MLKEM1024_PARAMS,
)
from .corpus import (
    KeyShareMutation,
    MutationClass,
    SeedCorpus,
    iter_corpus,
)
from .errors import (
    PqTlsFuzzError,
    TransportError,
    ConfigError,
    SelfcheckFailed,
    CaptureLimitError,
    HarnessError,
)
from .fuzzer import (
    CHECKPOINT_CADENCE,
    FuzzRun,
    Fuzzer,
    _nearest_rank_p95,
)
from .harness import (
    HarnessError as _HarnessError,  # re-exported via errors above
    generate_harness_keypair,
    generate_throwaway_ca,
    generate_throwaway_leaf,
    is_cert_expired,
    cert_to_pem,
    cert_to_der,
    load_cert_from_pem,
    load_cert_from_der,
    pem_der_roundtrip,
    cert_fingerprint_sha256,
    cert_validity_window,
    write_cert_files,
    verify_leaf_signed_by_ca,
)
from .oracle import (
    ExpectedOutcome,
    Oracle,
    OracleVerdict,
)
from .report import Finding, FuzzReport, Severity
from .transport import (
    HandshakeOutcome,
    OutcomeClass,
    RawHandshakeClient,
    ScriptablePeer,
)

__all__ = [
    "Group",
    "GroupSpec",
    "GroupRegistry",
    "KeyShareMutation",
    "MutationClass",
    "SeedCorpus",
    "iter_corpus",
    "CorpusError",
    "MLKEMParams",
    "MLKEM512_PARAMS",
    "MLKEM768_PARAMS",
    "MLKEM1024_PARAMS",
    "PqTlsFuzzError",
    "TransportError",
    "ConfigError",
    "SelfcheckFailed",
    "CaptureLimitError",
    "ExpectedOutcome",
    "Oracle",
    "OracleVerdict",
    "HandshakeOutcome",
    "OutcomeClass",
    "RawHandshakeClient",
    "ScriptablePeer",
    "FuzzConfig",
    "load_config",
    "FuzzRun",
    "Fuzzer",
    "CHECKPOINT_CADENCE",
    "_nearest_rank_p95",
    "Finding",
    "FuzzReport",
    "Severity",
    "GHActionAnnotations",
    "GitLabCodequality",
    "OTelSpanExporter",
    "PQTLsFuzzPytestPlugin",
    "maybe_export_span",
    "to_annotations",
    "to_codequality",
    "generate_harness_keypair",
    "generate_throwaway_ca",
    "generate_throwaway_leaf",
    "is_cert_expired",
    "cert_to_pem",
    "cert_to_der",
    "load_cert_from_pem",
    "load_cert_from_der",
    "pem_der_roundtrip",
    "cert_fingerprint_sha256",
    "cert_validity_window",
    "write_cert_files",
    "verify_leaf_signed_by_ca",
]

__version__ = "0.1.0"