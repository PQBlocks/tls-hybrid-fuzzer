"""Command-line interface for pqblocks_tlsfuzz (slice S11).

Commands: fuzz, corpus.
Exit codes per spec §1.6: 0 clean, 1 findings, 2 usage/config, 3 transport, 4 selfcheck failure.
"""

import argparse
import json
import sys
from pathlib import Path
import socket
import subprocess

from pqblocks_tlsfuzz.config import FuzzConfig, load_config
from pqblocks_tlsfuzz.constants import Group
from pqblocks_tlsfuzz.corpus import MutationClass, SeedCorpus
from pqblocks_tlsfuzz.errors import (
    CorpusError,
    PqTlsFuzzError,
    SelfcheckFailed,
    TransportError,
)
from pqblocks_tlsfuzz.fuzzer import Fuzzer
from pqblocks_tlsfuzz.report import FuzzReport
from pqblocks_tlsfuzz.streaming import CorpusStream

#: F18: a selfcheck run must see at least this many valid controls accepted.
SELFCHECK_MIN_CONTROLS = 50

#: F19: ``openssl list -tls-groups`` spells the ML-KEM groups in upper case.
_OPENSSL_MLKEM_MARKER = "MLKEM"


def main() -> int:
    """Run CLI with fuzz and corpus subcommands."""
    parser = argparse.ArgumentParser(
        prog="pqblocks-tlsfuzz",
        description="TLS 1.3 ML-KEM key-share fuzzer",
    )
    subparsers = parser.add_subparsers(dest="command", help="sub-command help")

    # fuzz subcommand
    fuzz_parser = subparsers.add_parser("fuzz", help="run fuzz campaign")
    fuzz_parser.add_argument("--endpoint", help="target endpoint (host:port)")
    fuzz_parser.add_argument(
        "--groups",
        nargs="+",
        help="groups to test (default: all six)",
    )
    fuzz_parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="iterations per group (default: 1000)",
    )
    fuzz_parser.add_argument(
        "--seed",
        type=int,
        default=0,
        help="random seed (default: 0)",
    )
    fuzz_parser.add_argument(
        "--config",
        type=Path,
        help="YAML config file",
    )
    fuzz_parser.add_argument(
        "--format",
        choices=["json", "junit", "sarif", "jsonl"],
        default="json",
        help="output format (default: json)",
    )
    fuzz_parser.add_argument(
        "--out",
        type=Path,
        help="output file path (default: stdout)",
    )

    # corpus subcommand
    corpus_parser = subparsers.add_parser("corpus", help="dump corpus as JSONL")
    corpus_parser.add_argument(
        "--groups",
        nargs="+",
        required=True,
        help="groups to include",
    )
    corpus_parser.add_argument(
        "--iterations",
        type=int,
        required=True,
        help="iterations per group",
    )
    corpus_parser.add_argument(
        "--seed",
        type=int,
        default=0,
        help="random seed (default: 0)",
    )
    corpus_parser.add_argument(
        "--format",
        choices=["json", "jsonl"],
        default="jsonl",
        help="output format (default: jsonl)",
    )
    corpus_parser.add_argument(
        "--out",
        type=Path,
        help="output file path (default: stdout)",
    )

    # doctor subcommand
    doctor_parser = subparsers.add_parser("doctor", help="print capability matrix")
    doctor_parser.add_argument("--endpoint", help="target endpoint (host:port)")

    # selfcheck subcommand
    selfcheck_parser = subparsers.add_parser("selfcheck", help="validate endpoint ML-KEM support")
    selfcheck_parser.add_argument("--endpoint", help="target endpoint (host:port)")
    selfcheck_parser.add_argument("--iterations", type=int, default=100, help="control probes (default: 100)")

    args = parser.parse_args()

    if args.command == "fuzz":
        return _cmd_fuzz(args)
    elif args.command == "corpus":
        return _cmd_corpus(args)
    elif args.command == "doctor":
        return _cmd_doctor(args)
    elif args.command == "selfcheck":
        return _cmd_selfcheck(args)
    else:
        parser.print_help()
        return 2


def _cmd_fuzz(args: argparse.Namespace) -> int:
    """Run fuzz command."""
    try:
        # Validate args: either --config or --endpoint must be provided
        if not args.config and not args.endpoint:
            print("Error: either --config or --endpoint must be provided", file=sys.stderr)
            return 2

        # Load config
        if args.config:
            cfg = load_config(args.config)
            # CLI args override config
            if args.endpoint:
                cfg = FuzzConfig(
                    endpoint=args.endpoint,
                    groups=cfg.groups,
                    iterations=cfg.iterations,
                    mutation_classes=cfg.mutation_classes,
                    seed=cfg.seed,
                    timeout_ms=cfg.timeout_ms,
                    concurrency=cfg.concurrency,
                    capture_cap_bytes=cfg.capture_cap_bytes,
                    max_iterations=cfg.max_iterations,
                    config_version=cfg.config_version,
                )
            if args.iterations:
                cfg = FuzzConfig(
                    endpoint=cfg.endpoint,
                    groups=cfg.groups,
                    iterations=args.iterations,
                    mutation_classes=cfg.mutation_classes,
                    seed=cfg.seed,
                    timeout_ms=cfg.timeout_ms,
                    concurrency=cfg.concurrency,
                    capture_cap_bytes=cfg.capture_cap_bytes,
                    max_iterations=cfg.max_iterations,
                    config_version=cfg.config_version,
                )
            if args.seed:
                cfg = FuzzConfig(
                    endpoint=cfg.endpoint,
                    groups=cfg.groups,
                    iterations=cfg.iterations,
                    mutation_classes=cfg.mutation_classes,
                    seed=args.seed,
                    timeout_ms=cfg.timeout_ms,
                    concurrency=cfg.concurrency,
                    capture_cap_bytes=cfg.capture_cap_bytes,
                    max_iterations=cfg.max_iterations,
                    config_version=cfg.config_version,
                )
        else:
            # Parse groups
            from pqblocks_tlsfuzz.constants import Group

            groups = None
            if args.groups:
                try:
                    groups = tuple(Group(g.lower()) for g in args.groups)
                except ValueError as e:
                    print(f"Error: unknown group: {e}", file=sys.stderr)
                    return 2

            cfg = FuzzConfig(
                endpoint=args.endpoint,
                groups=groups,
                iterations=args.iterations,
                seed=args.seed,
            )

        # Run fuzzer
        fuzzer = Fuzzer(cfg)
        result = fuzzer.run()

        # Write output
        output = _format_output(result.report, args.format)
        if args.out:
            args.out.write_text(output)
        else:
            print(output)

        # Return exit code based on findings
        if result.exit_code != 0:
            return result.exit_code
        if result.report.findings:
            return 1
        return 0

    except TransportError as e:
        print(f"Transport error: {e}", file=sys.stderr)
        return 3
    except PqTlsFuzzError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 2


def _cmd_corpus(args: argparse.Namespace) -> int:
    """Dump corpus as JSONL."""
    try:
        from pqblocks_tlsfuzz.constants import Group

        # Parse groups
        try:
            groups = [Group(g.lower()) for g in args.groups]
        except ValueError as e:
            print(f"Error: unknown group: {e}", file=sys.stderr)
            return 2

        # Create corpus stream
        stream = CorpusStream(
            groups=groups,
            classes=list(MutationClass),
            iterations=args.iterations,
            seed=args.seed,
        )

        # Write JSONL output
        lines = []
        for mutation in stream:
            line = json.dumps(
                {
                    "id": mutation.id,
                    "group": mutation.group.value,
                    "mutation_class": mutation.mutation_class.value,
                    "seed": mutation.seed,
                    "offset": mutation.offset,
                    "payload_hex": mutation.payload.hex(),
                    "structural": mutation.structural,
                    "note": mutation.note,
                },
                separators=(",", ":"),
            )
            lines.append(line)

        output = "\n".join(lines)
        if args.out:
            args.out.write_text(output + "\n")
        else:
            print(output)

        return 0

    except PqTlsFuzzError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 2


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    """Split ``host:port`` into ``(host, port)`` or raise PqTlsFuzzError.

    IPv6 literals are accepted with or without brackets (``::1:443``,
    ``[::1]:443``). A missing or non-numeric port is a usage error, not a
    traceback.
    """
    text = endpoint.strip()
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise PqTlsFuzzError(
                f"invalid endpoint {endpoint!r}: expected [host]:port"
            )
        port_str = rest[1:]
    else:
        host, sep, port_str = text.rpartition(":")
        if not sep:
            raise PqTlsFuzzError(
                f"invalid endpoint {endpoint!r}: expected host:port"
            )
    if not host:
        raise PqTlsFuzzError(f"invalid endpoint {endpoint!r}: empty host")
    try:
        port = int(port_str)
    except ValueError:
        raise PqTlsFuzzError(
            f"invalid endpoint {endpoint!r}: port {port_str!r} is not an integer"
        ) from None
    if not 1 <= port <= 65535:
        raise PqTlsFuzzError(f"invalid endpoint {endpoint!r}: port {port} out of range")
    return host, port


def _openssl_capabilities() -> tuple[bool, list[str]]:
    """Return ``(openssl_present, mlkem_groups)`` from ``openssl list -tls-groups``.

    A missing binary or a non-zero exit is reported as absence, never raised:
    doctor's job is to describe the machine, not to fail on it.
    """
    try:
        result = subprocess.run(
            ["openssl", "list", "-tls-groups"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False, []

    if result.returncode != 0:
        return False, []

    groups: list[str] = []
    for token in (result.stdout + " " + result.stderr).replace(",", " ").split():
        if _OPENSSL_MLKEM_MARKER in token.upper():
            groups.append(token.strip())
    return True, groups


def _port_reachable(host: str, port: int, timeout_s: float = 2.0) -> bool:
    """True when a TCP connect to ``host:port`` succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def _fixtures_capability() -> tuple[bool, str]:
    """Return ``(present, detail)`` for the valid-control fixture corpus (F27).

    The remediation string names the exact env var and the fixture file stems so
    a user can act on it without reading the docs.
    """
    import os

    explicit = os.environ.get("PQTLSFUZZ_FIXTURES_DIR")
    if explicit and Path(explicit).is_dir():
        return True, f"present (PQTLSFUZZ_FIXTURES_DIR={explicit})"
    try:
        SeedCorpus().valid_controls(Group.MLKEM768, limit=1)
    except CorpusError:
        return False, (
            "missing (remediation: set PQTLSFUZZ_FIXTURES_DIR to a directory of "
            "Wycheproof mlkem_512_test/mlkem_768_test/mlkem_1024_testek JSON files)"
        )
    return True, "present (vector fixtures)"


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Print the capability matrix (F19); exit 3 when the endpoint is unreachable."""
    lines = ["capability matrix (doctor)"]
    lines.append("=" * 40)

    openssl_present, mlkem_groups = _openssl_capabilities()
    lines.append(f"openssl: {'yes' if openssl_present else 'no'}")
    if mlkem_groups:
        lines.append(f"tls-groups: {', '.join(mlkem_groups)}")
    else:
        lines.append("tls-groups: none (no ML-KEM groups advertised)")

    fixtures_present, fixtures_detail = _fixtures_capability()
    lines.append(f"fixtures: {fixtures_detail}")

    reachable = None
    if args.endpoint:
        host, port = _parse_endpoint(args.endpoint)
        reachable = _port_reachable(host, port)
        lines.append(f"port-reachable: {args.endpoint}: {'yes' if reachable else 'no'}")

    print("\n".join(lines))

    if reachable is False:
        print(
            f"doctor: endpoint {args.endpoint} unreachable (remediation: check the "
            "host, port, and firewall; nothing was fuzzed)",
            file=sys.stderr,
        )
        return 3
    return 0


def _cmd_selfcheck(args: argparse.Namespace) -> int:
    """Validate that the endpoint accepts ML-KEM key shares (F18, E20).

    Sends ``--iterations`` untouched Wycheproof ek controls and counts how many
    the endpoint accepted. Fewer than ``SELFCHECK_MIN_CONTROLS`` accepted is a
    selfcheck failure with exit 4: the endpoint is not a usable reference and
    fuzzing it would produce a 100 % false-positive rate (E20).
    """
    if not args.endpoint:
        print("Error: --endpoint must be provided for selfcheck", file=sys.stderr)
        return 2
    if args.iterations < 1:
        print(
            f"Error: --iterations must be >= 1, got {args.iterations}",
            file=sys.stderr,
        )
        return 2

    try:
        host, port = _parse_endpoint(args.endpoint)
        from pqblocks_tlsfuzz.transport import OutcomeClass, RawHandshakeClient

        # F18: controls are untouched Wycheproof ek bytes, drawn directly from
        # the fixture corpus. iter_corpus() cycles mutation classes, so it
        # cannot be used here: a 10-iteration run would contain no
        # VALID_CONTROL at all.
        corpus = SeedCorpus()
        controls: list = []
        for group in (Group.MLKEM512, Group.MLKEM768, Group.MLKEM1024):
            controls.extend(corpus.valid_controls(group, limit=args.iterations))
            if len(controls) >= args.iterations:
                break
        controls = controls[: args.iterations]
        if not controls:
            raise SelfcheckFailed(
                "no valid controls available (remediation: provide the Wycheproof "
                "ML-KEM fixtures via PQTLSFUZZ_FIXTURES_DIR)"
            )

        client = RawHandshakeClient(host=host, port=port, timeout_ms=2000)
        accepted = 0
        attempted = 0
        transport_failures = 0

        for control in controls:
            attempted += 1
            try:
                outcome = client.probe(control)
            except TransportError:
                # Cannot connect/send: the control was not accepted. Counting
                # it as anything else would hide a dead endpoint.
                transport_failures += 1
                continue
            if outcome.outcome == OutcomeClass.OUTCOME_ACCEPTED:
                accepted += 1

        if accepted < SELFCHECK_MIN_CONTROLS:
            print(
                f"Error: selfcheck failed - only {accepted} of {attempted} "
                f"valid controls accepted (minimum {SELFCHECK_MIN_CONTROLS} required"
                + (f", {transport_failures} probes could not reach the endpoint"
                   if transport_failures else "")
                + ")",
                file=sys.stderr,
            )
            print(
                "selfcheck: valid control acceptance rate too low: "
                f"{accepted}/{attempted}",
                file=sys.stderr,
            )
            return 4

        print(
            f"selfcheck passed - {accepted} of {attempted} valid controls accepted"
        )
        return 0

    except SelfcheckFailed as e:
        print(f"Error: selfcheck: {e}", file=sys.stderr)
        return 4
    except PqTlsFuzzError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 - CLI boundary: no traceback
        print(f"Error: selfcheck: unexpected error: {e}", file=sys.stderr)
        return 2


def _format_output(report: FuzzReport, format: str) -> str:
    """Format report according to format."""
    if format == "json":
        return report.to_json()
    elif format == "junit":
        return report.to_junit()
    elif format == "sarif":
        return report.to_sarif()
    elif format == "jsonl":
        # For jsonl, we need to write to a temp file
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            report.to_jsonl(Path(f.name))
            return Path(f.name).read_text()
    else:
        raise ValueError(f"unknown format: {format}")


if __name__ == "__main__":
    sys.exit(main())