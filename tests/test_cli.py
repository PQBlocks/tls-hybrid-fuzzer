"""Tests for cli.py (slice S11).

Test plan per spec §6.2:
- test_exit_codes: exit 0/1/2/3/4 for various scenarios
- test_corpus_dump: deterministic JSONL output
- test_no_stack_trace_on_config_error: loud error without traceback
- test_fuzz_exit_code_on_findings: returns exit code 1 when findings are detected

"""

import json
import subprocess
import sys
import os
from pathlib import Path

import pytest

from pqblocks_tlsfuzz.constants import Group
from pqblocks_tlsfuzz.corpus import MutationClass
from pqblocks_tlsfuzz.errors import ConfigError
from pqblocks_tlsfuzz.cli import main
from pqblocks_tlsfuzz.fuzzer import FuzzRun
from pqblocks_tlsfuzz.report import FuzzReport, Finding, Severity
from pqblocks_tlsfuzz.transport import HandshakeOutcome, OutcomeClass

SRC_DIR = str(Path(__file__).resolve().parent.parent / "src")


def test_exit_codes(tmp_path, monkeypatch):
    """Exit codes: 0 clean, 1 findings, 2 usage/config, 3 transport, 4 selfcheck failure."""
    # Test 0: clean run (will fail to connect, but that's ok for now)
    # We'll test that invalid config returns 2
    config_file = tmp_path / "config.yaml"
    config_file.write_text("invalid: yaml: content: [\n")

    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR

    result = subprocess.run(
        [sys.executable, "-m", "pqblocks_tlsfuzz.cli", "fuzz", "--endpoint", "localhost:443", "--config", str(config_file)],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 2
    assert "Error:" in result.stderr
    assert "Traceback" not in result.stderr

    # Test 1: missing required argument (no --config and no --endpoint)
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR
    result = subprocess.run(
        [sys.executable, "-m", "pqblocks_tlsfuzz.cli", "fuzz"],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 2
    assert "endpoint" in result.stderr.lower()

    # Test 2: invalid group name
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pqblocks_tlsfuzz.cli",
            "fuzz",
            "--endpoint",
            "localhost:443",
            "--groups",
            "invalidgroup",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 2
    assert "unknown group" in result.stderr.lower()


def test_corpus_dump(tmp_path, capsys):
    """Corpus dump produces deterministic JSONL."""
    # Generate corpus
    from pqblocks_tlsfuzz.streaming import CorpusStream

    stream = CorpusStream(
        groups=[Group.MLKEM512],
        classes=list(MutationClass)[:3],  # First 3 classes
        iterations=10,
        seed=42,
    )

    # Write to file
    output_file = tmp_path / "corpus.jsonl"

    # Call CLI via subprocess
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pqblocks_tlsfuzz.cli",
            "corpus",
            "--groups",
            "mlkem512",
            "--iterations",
            "10",
            "--seed",
            "42",
            "--out",
            str(output_file),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 0

    # Verify output file exists and has content
    assert output_file.exists()
    content = output_file.read_text()
    lines = content.strip().split("\n")
    assert len(lines) == 10  # 10 iterations

    # Verify each line is valid JSON
    for line in lines:
        data = json.loads(line)
        assert "id" in data
        assert "group" in data
        assert "mutation_class" in data
        assert "payload_hex" in data

    # Verify determinism: same seed produces same output
    output_file2 = tmp_path / "corpus2.jsonl"
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pqblocks_tlsfuzz.cli",
            "corpus",
            "--groups",
            "mlkem512",
            "--iterations",
            "10",
            "--seed",
            "42",
            "--out",
            str(output_file2),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 0
    content2 = output_file2.read_text()
    assert content == content2


def test_no_stack_trace_on_config_error(tmp_path, capsys):
    """Config errors should not show traceback."""
    config_file = tmp_path / "bad_config.yaml"
    config_file.write_text("""
endpoint: localhost:443
unknown_key: value
""")

    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR

    result = subprocess.run(
        [sys.executable, "-m", "pqblocks_tlsfuzz.cli", "fuzz", "--endpoint", "localhost:443", "--config", str(config_file)],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 2
    assert "Error:" in result.stderr
    assert "unknown_key" in result.stderr
    assert "Traceback" not in result.stderr


def test_corpus_determinism_same_seed(tmp_path):
    """Same seed produces byte-identical corpus."""
    from pqblocks_tlsfuzz.streaming import CorpusStream

    # Generate two corpora with same seed
    stream1 = CorpusStream(
        groups=[Group.MLKEM512, Group.MLKEM768],
        classes=list(MutationClass)[:5],
        iterations=20,
        seed=123,
    )

    stream2 = CorpusStream(
        groups=[Group.MLKEM512, Group.MLKEM768],
        classes=list(MutationClass)[:5],
        iterations=20,
        seed=123,
    )

    # Convert to lists
    mutations1 = list(stream1)
    mutations2 = list(stream2)

    # Should be identical
    assert len(mutations1) == len(mutations2)
    for m1, m2 in zip(mutations1, mutations2):
        assert m1.id == m2.id
        assert m1.payload == m2.payload


def test_fuzz_exit_code_on_transport_error(tmp_path):
    """Transport errors should return exit code 3."""
    # Try to connect to a port that's likely not open
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pqblocks_tlsfuzz.cli",
            "fuzz",
            "--endpoint",
            "localhost:59999",
            "--iterations",
            "1",
            "--groups",
            "mlkem512",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env=env
    )
    # Should get transport error exit code 3
    assert result.returncode == 3
    assert "Transport" in result.stderr or "transport" in result.stderr.lower()


def test_fuzz_exit_code_on_findings(tmp_path, monkeypatch):
    """Fuzz runs with findings should return exit code 1."""
    # Build a mock FuzzRun with findings but exit_code=0 to prove findings
    # alone force exit code 1.
    mock_run = FuzzRun(
        report=FuzzReport(
            target="host:port",
            started_utc="2026-11-19T12:00:00Z",
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(),
            findings=tuple([
                Finding(
                    mutation_id="mock-id",
                    group=Group.MLKEM512,
                    mutation_class=MutationClass.BITFLIP,
                    severity=Severity.HIGH,
                    expected="expected clause",
                    observed=OutcomeClass.ALERT_HANDSHAKE_FAILURE,
                    clause="test clause",
                    detail="Mock finding detail",
                )
            ]),
            p95_latency_ms=10.5,
            false_positive_rate=0.1,
        ),
        summary={"OUTCOME_ACCEPTED": 9, "ALERT_HANDSHAKE_FAILURE": 1},
        p95_latency_ms=10.5,
        false_positive_rate=0.1,
        exit_code=0,
    )

    # Patch Fuzzer.run in-process (subprocess would not see monkeypatch).
    monkeypatch.setattr("pqblocks_tlsfuzz.fuzzer.Fuzzer.run", lambda self: mock_run)

    monkeypatch.setattr(
        sys,
        "argv",
        ["pqblocks-tlsfuzz", "fuzz", "--endpoint", "localhost:443", "--groups", "mlkem512", "--iterations", "1"],
    )

    rc = main()
    assert rc == 1


def test_corpus_invalid_group():
    """Invalid group name should return exit code 2."""
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pqblocks_tlsfuzz.cli",
            "corpus",
            "--groups",
            "invalidgroup",
            "--iterations",
            "10",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 2
    assert "unknown group" in result.stderr.lower()


def test_corpus_missing_required_args():
    """Missing required args should return exit code 2."""
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR
    result = subprocess.run(
        [sys.executable, "-m", "pqblocks_tlsfuzz.cli", "corpus"],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 2


def test_fuzz_missing_endpoint():
    """Missing endpoint should return exit code 2."""
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR
    result = subprocess.run(
        [sys.executable, "-m", "pqblocks_tlsfuzz.cli", "fuzz"],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 2
    assert "endpoint" in result.stderr.lower()


def test_doctor_matrix(tmp_path):
    """Doctor command prints capability matrix with openssl presence and tls-groups."""
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR

    result = subprocess.run(
        [sys.executable, "-m", "pqblocks_tlsfuzz.cli", "doctor"],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 0
    assert "openssl" in result.stdout.lower()
    assert "tls-groups" in result.stdout.lower() or "tls_groups" in result.stdout.lower()
    # Should have a matrix-like output
    assert "capability" in result.stdout.lower() or "matrix" in result.stdout.lower()


def test_doctor_exit_3_on_unreachable(tmp_path):
    """Doctor exits 3 when port is unreachable."""
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR

    result = subprocess.run(
        [sys.executable, "-m", "pqblocks_tlsfuzz.cli", "doctor", "--endpoint", "127.0.0.1:59999"],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    # Should exit 3 for unreachable
    assert result.returncode == 3


def test_selfcheck_fails_on_plain_endpoint(tmp_path):
    """E20: Selfcheck against a plain (non-ML-KEM) endpoint should fail with exit 4."""
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR

    # Connect to a plain HTTP server (or any non-TLS endpoint)
    # We'll use a port that's likely to have a plain HTTP server or just refuse
    # The key is that valid_control shares should NOT be accepted
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pqblocks_tlsfuzz.cli",
            "selfcheck",
            "--endpoint",
            "127.0.0.1:59999",  # unreachable port
            "--iterations",
            "50",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env
    )
    # Should exit 4 because < 50 controls accepted (in fact 0)
    assert result.returncode == 4
    assert "selfcheck" in result.stderr.lower() or "valid" in result.stderr.lower() or "accepted" in result.stderr.lower()


def test_selfcheck_requires_50_controls(tmp_path):
    """Selfcheck requires at least 50 valid controls accepted, else exit 4."""
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR

    # With iterations=10, only ~10% are VALID_CONTROL (~1 control), far below 50
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pqblocks_tlsfuzz.cli",
            "selfcheck",
            "--endpoint",
            "127.0.0.1:59999",
            "--iterations",
            "10",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env
    )
    assert result.returncode == 4


def test_selfcheck_exit_2_on_missing_endpoint():
    """Selfcheck without endpoint returns exit code 2."""
    env = os.environ.copy()
    env['PYTHONPATH'] = SRC_DIR

    result = subprocess.run(
        [sys.executable, "-m", "pqblocks_tlsfuzz.cli", "selfcheck"],
        capture_output=True,
        text=True,
        check=False,
        env=env
    )
    assert result.returncode == 2
    assert "endpoint" in result.stderr.lower()