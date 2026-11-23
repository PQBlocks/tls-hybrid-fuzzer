"""Fuzzer campaign driver for pqblocks_tlsfuzz (slice S8).

Implements FuzzConfig, Fuzzer, FuzzRun, _nearest_rank_p95, and CHECKPOINT_CADENCE
per spec §2.3. Concurrency via SplitMix64 fan-out. Checkpoint every 64 probes.
Resume from checkpoint.json.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pqblocks_tlsfuzz.config import FuzzConfig
from pqblocks_tlsfuzz.corpus import iter_corpus, KeyShareMutation, MutationClass, SeedCorpus
from pqblocks_tlsfuzz.errors import PqTlsFuzzError, TransportError
from pqblocks_tlsfuzz.oracle import Oracle, OracleVerdict
from pqblocks_tlsfuzz.report import Finding, FuzzReport, Severity
from pqblocks_tlsfuzz.transport import (
    HandshakeOutcome,
    OutcomeClass,
    RawHandshakeClient,
)
from pqblocks_tlsfuzz.constants import Group, GroupRegistry


# --- Constants per spec §2.3 ---
CHECKPOINT_CADENCE = 64


@dataclass(frozen=True)
class FuzzRun:
    """Result of a fuzz campaign run (spec §1.3)."""
    report: FuzzReport
    summary: dict[str, int]         # outcome histogram
    p95_latency_ms: float
    false_positive_rate: float      # on VALID_CONTROL class; 1.0 if no controls ran (never silently 0)
    exit_code: int


def _nearest_rank_p95(latencies: list[float]) -> float:
    """E24: f64 latency p95 via nearest-rank.

    rank = ceil(0.95 * n), index = rank - 1 (0-based).
    Returns 0.0 for empty input.
    """
    n = len(latencies)
    if n == 0:
        return 0.0
    sorted_lat = sorted(latencies)
    rank = math.ceil(0.95 * n)
    idx = rank - 1  # 0-based index
    # Clamp index to valid range
    idx = max(0, min(idx, n - 1))
    return float(sorted_lat[idx])


class Fuzzer:
    """Campaign driver: probe mutations against a TLS endpoint."""

    def __init__(self, config: FuzzConfig) -> None:
        self.cfg = config

    def _make_campaign(self) -> list[KeyShareMutation]:
        """Produce the full mutation campaign list via iter_corpus."""
        groups = self.cfg.groups
        if not groups:
            raise PqTlsFuzzError("groups must be non-empty")

        classes = self.cfg.mutation_classes
        if not classes:
            raise PqTlsFuzzError("mutation_classes must be non-empty")

        # Build iteration using iter_corpus - same (groups, classes, iterations, seed)
        # => same sequence.
        stream = iter_corpus(
            groups=groups,
            classes=classes,
            iterations=self.cfg.iterations,
            seed=self.cfg.seed,
        )

        return list(stream)

    def run(self) -> FuzzRun:
        """Execute the fuzz campaign and return a FuzzRun."""
        cfg = self.cfg

        # Parse endpoint
        host = cfg.host
        port = cfg.port

        # Build mutation campaign
        mutations = self._make_campaign()

        # Load existing checkpoint if resuming.
        #
        # A checkpoint is only a resume point if it describes an *incomplete*
        # campaign for THIS campaign's identity (seed + iteration count). A
        # checkpoint left behind by a finished run carries the same ids but no
        # pending work, so re-loading it would silently skip every probe.
        # Checkpoints written by other tools (no "source" key) are always
        # honoured: they are explicit resume requests.
        checkpoint_path = Path("checkpoint.json")
        completed_ids: set[str] = set()
        if checkpoint_path.exists():
            try:
                with open(checkpoint_path) as f:
                    ckpt = json.load(f)
                completed_ids = self._resume_ids(ckpt, mutations)
            except (json.JSONDecodeError, KeyError, OSError):
                completed_ids = set()

        # Filter out already-completed mutations
        remaining = [m for m in mutations if m.id not in completed_ids]

        # Create client (connects to the given endpoint; no ScriptablePeer created here)
        client = RawHandshakeClient(
            host=host,
            port=port,
            timeout_ms=cfg.timeout_ms,
            capture_cap=cfg.capture_cap_bytes,
        )

        # Track results
        all_outcomes: list[HandshakeOutcome] = []
        latencies: list[float] = []

        # Initialize Oracle for classification
        oracle = Oracle()

        # If no remaining, we're done (resume from full checkpoint)
        if not remaining:
            p95 = _nearest_rank_p95(latencies)

            # Build empty report
            report = FuzzReport(
                target=f"{host}:{port}",
                started_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                fuzz_tlsfuzz_version="0.1.0",
                outcomes=tuple(),
                findings=tuple(),
                p95_latency_ms=p95,
                false_positive_rate=None,
            )

            summary: dict[str, int] = {}

            # Still write checkpoint with all completed
            self._write_checkpoint(sorted(completed_ids))

            return FuzzRun(
                report=report,
                summary=summary,
                p95_latency_ms=p95,
                false_positive_rate=1.0 if mutations else 0.0,
                exit_code=0,
            )

        # Process mutations sequentially in deterministic order.
        # Per spec §2.3 & E13: same seed => same mutation sequence; results
        # must be reproducible across runs. Sequential processing ensures
        # consistent latency measurement and checkpoint indexing.
        for i, mutation in enumerate(remaining):
            outcome = client.probe(mutation)
            all_outcomes.append(outcome)
            completed_ids.add(mutation.id)
            latencies.append(outcome.latency_ms)

            # Checkpoint every CHECKPOINT_CADENCE probes
            if (i + 1) % CHECKPOINT_CADENCE == 0 or i == len(remaining) - 1:
                self._write_checkpoint(sorted(completed_ids))

        # Classify outcomes using Oracle and build findings
        findings: list[Finding] = []
        false_positive_count = 0
        valid_control_total = 0

        for outcome in all_outcomes:
            # Find the corresponding mutation
            mutation = next((m for m in mutations if m.id == outcome.mutation_id), None)
            if mutation is None:
                continue

            verdict = oracle.classify(mutation, outcome)

            if verdict.is_finding:
                # Build Finding from verdict
                finding = Finding(
                    mutation_id=mutation.id,
                    group=mutation.group,
                    mutation_class=mutation.mutation_class,
                    severity=Severity(verdict.expected.severity.lower()),
                    expected=verdict.expected.clause,
                    observed=outcome.outcome,
                    clause=verdict.expected.clause,
                    detail=f"Expected {verdict.expected.clause}, observed {outcome.outcome.value}: {outcome.detail}",
                )
                findings.append(finding)

            # Track FPR on VALID_CONTROL class
            if mutation.mutation_class is MutationClass.VALID_CONTROL:
                valid_control_total += 1
                if outcome.outcome != OutcomeClass.OUTCOME_ACCEPTED:
                    false_positive_count += 1

        # Compute p95
        p95 = _nearest_rank_p95(latencies)

        # Compute FPR: false_positive_rate on VALID_CONTROL class
        # Per spec §2.3: "1.0 if no controls ran (never silently 0)" for FuzzRun;
        # report.false_positive_rate is None when no controls ran (honest denominator).
        if valid_control_total > 0:
            fpr = false_positive_count / valid_control_total
            report_fpr: float | None = fpr
        else:
            fpr = 1.0
            report_fpr = None

        # Build outcome histogram
        summary: dict[str, int] = {}
        for o in all_outcomes:
            summary[o.outcome.value] = summary.get(o.outcome.value, 0) + 1

        # Build report
        report = FuzzReport(
            target=f"{host}:{port}",
            started_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            fuzz_tlsfuzz_version="0.1.0",
            outcomes=tuple(all_outcomes),
            findings=tuple(findings),
            p95_latency_ms=p95,
            false_positive_rate=report_fpr,
        )

        return FuzzRun(
            report=report,
            summary=summary,
            p95_latency_ms=p95,
            false_positive_rate=fpr,
            exit_code=0,
        )

    def _resume_ids(
        self, ckpt: dict[str, Any], mutations: list[KeyShareMutation]
    ) -> set[str]:
        """Return the mutation ids to skip, honouring only genuine resume points.

        Rules (in order):

        1. A checkpoint with no ``"source"`` key was written by an external
           caller and is always treated as an explicit resume request.
        2. A checkpoint written by this fuzzer is only a resume point if it
           describes the *same* campaign (same ``seed`` and same
           ``iterations``) AND still has pending work (it does not already
           cover every mutation in this campaign).
        3. Anything else is a stale artefact from a finished or different
           campaign and is ignored, so a fresh run really re-probes.
        """
        raw = ckpt.get("completed", [])
        if not isinstance(raw, list):
            return set()
        ids = {str(x) for x in raw}

        if ckpt.get("source") != "pqblocks_tlsfuzz.fuzzer":
            # Externally supplied checkpoint: explicit resume request.
            return ids

        if ckpt.get("seed") != self.cfg.seed:
            return set()
        if ckpt.get("iterations") != self.cfg.iterations:
            return set()

        campaign_ids = {m.id for m in mutations}
        if campaign_ids.issubset(ids):
            # The checkpoint already covers the whole campaign: there is no
            # pending work, so this is a finished run's artefact, not a
            # resume point. Re-probing is the correct behaviour.
            return set()
        return ids

    def _write_checkpoint(self, completed_ids: list[str]) -> None:
        """Write checkpoint.json with completed mutation ids.

        The file carries the campaign identity (``seed``, ``iterations``) and a
        ``source`` marker so a later run can tell a genuine resume point from
        a stale artefact left by a finished campaign.
        """
        checkpoint_path = Path("checkpoint.json")
        with open(checkpoint_path, "w") as f:
            json.dump(
                {
                    "completed": completed_ids,
                    "seed": self.cfg.seed,
                    "iterations": self.cfg.iterations,
                    "source": "pqblocks_tlsfuzz.fuzzer",
                },
                f,
                indent=2,
            )

