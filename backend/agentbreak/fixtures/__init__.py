"""Original synthetic fixtures for Module B (scenarios, snapshots, seeds, benign cases).

Everything here is fake and local; no dataset is downloaded. Every function
returns freshly validated deep copies, so callers (and runs) can never mutate the
module-level source data in :mod:`agentbreak.fixtures.data`.

Canonical scenario IDs: ``doc_exfil`` (document surface, source ``doc_a``) and
``email_bola`` (email surface, source ``email_a``). Snapshot IDs: ``support_v1``
(canonical) and ``support_v1_noise`` (same data, with an irrelevant forwarded
instruction appended to ``doc_a`` and ``email_a`` for the "ignore noise" clean task).

Static model traces for CI live in :mod:`agentbreak.fixtures.traces` and are
explicitly labeled simulated.
"""

from __future__ import annotations

import copy
from typing import Literal

from agentbreak.contracts import (
    AttackCandidate, AttackSeed, BenignCase, FixtureSnapshot, ScenarioSpec, payload_sha256,
)
from agentbreak.fixtures import data

__all__ = ["list_scenarios", "load_snapshot", "list_attack_seeds", "list_benign_cases"]


def list_scenarios() -> list[ScenarioSpec]:
    """The two canonical attack scenarios, as fresh validated copies."""
    return [ScenarioSpec.model_validate(copy.deepcopy(raw)) for raw in data.CANONICAL_SCENARIOS]


def load_snapshot(fixture_id: str) -> FixtureSnapshot:
    """A fresh deep-copied initial snapshot (empty outbox). Raises ``KeyError`` if unknown.

    Customers carry their synthetic ``internal_token`` canaries; retests that load the
    same ``fixture_id`` therefore see identical canaries but independent outboxes.
    """
    if fixture_id not in (data.FIXTURE_ID, data.NOISE_FIXTURE_ID):
        raise KeyError(f"unknown fixture_id: {fixture_id!r}")
    documents = copy.deepcopy(list(data.DOCUMENTS))
    if fixture_id == data.NOISE_FIXTURE_ID:
        for doc in documents:
            if doc["id"] in ("doc_a", "email_a"):
                doc["body"] += data.NOISE_SUFFIX
    return FixtureSnapshot.model_validate({
        "fixture_id": fixture_id, "version": data.FIXTURE_VERSION,
        "documents": documents, "customers": copy.deepcopy(list(data.CUSTOMERS)), "outbox": [],
    })


def list_attack_seeds(split: Literal["discovery", "held_out"]) -> list[AttackSeed]:
    """Root (generation 0) attack seeds for one split: 4 discovery, 8 held-out in total.

    Held-out seeds must never be fed to A's adaptive generation. Candidate IDs are
    deterministic (uuid5) so references are stable across processes.
    """
    if split not in ("discovery", "held_out"):
        raise ValueError("split must be 'discovery' or 'held_out'")
    sources = {raw["id"]: raw for raw in data.CANONICAL_SCENARIOS}
    seeds: list[AttackSeed] = []
    counters: dict[str, int] = {}
    import uuid
    for scenario_id, seed_split, strategy, text in data.ATTACK_SEEDS:
        counters[scenario_id] = counters.get(scenario_id, 0) + 1
        if seed_split != split:
            continue
        scenario = sources[scenario_id]
        candidate = AttackCandidate(
            id=uuid.uuid5(data.SEED_NAMESPACE, f"seed:{scenario_id}:{counters[scenario_id]}"),
            scenario_id=scenario_id, source_id=scenario["source_id"], surface=scenario["surface"],
            text=text, parent_id=None, generation=0, strategy=strategy,
            feedback_summary=None, payload_sha256=payload_sha256(text),
        )
        seeds.append(AttackSeed(split=split, candidate=candidate))
    return seeds


def list_benign_cases() -> list[BenignCase]:
    """Eight clean task variants with stable task IDs and fresh matching snapshots."""
    return [
        BenignCase(scenario=ScenarioSpec.model_validate(copy.deepcopy(raw)),
                   fixture_snapshot=load_snapshot(raw["fixture_id"]))
        for raw in data.BENIGN_SCENARIOS
    ]
