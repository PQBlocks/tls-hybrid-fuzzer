"""Error taxonomy for pqblocks_tlsfuzz.

Per spec §1.6: PqTlsFuzzError (base) with TransportError, ConfigError,
CorpusError, SelfcheckFailed subclasses.
"""

class PqTlsFuzzError(Exception):
    """Base error for all pqblocks_tlsfuzz exceptions."""

    pass


class TransportError(PqTlsFuzzError):
    """Raised when a transport/connection to the endpoint fails."""

    pass


class ConfigError(PqTlsFuzzError):
    """Raised when configuration is invalid or a key is unknown."""

    pass


class CorpusError(PqTlsFuzzError):
    """Raised when a group, corpus, or parameter is unknown or invalid."""

    pass


class SelfcheckFailed(PqTlsFuzzError):
    """Raised when the selfcheck command detects a failure."""

    pass


class WireParseError(PqTlsFuzzError):
    """Raised when TLS record/handshake parsing fails on malformed or unexpected bytes."""

    pass


class CaptureLimitError(PqTlsFuzzError):
    """Raised when a peer response exceeds the capture cap.

    Never fatal: the capture is clamped at the cap and the probe continues.
    """

    pass


class HarnessError(PqTlsFuzzError):
    """Raised when certificate generation or PEM/DER round-trip fails."""

    pass