import copy
import json

import pytest
from pydantic import ValidationError

from agentbreak.contracts import AttackCandidate, SearchDocsArgs, payload_sha256
from agentbreak.fixtures import (
    data, list_attack_seeds, list_benign_cases, list_scenarios, load_snapshot,
)
from agentbreak.fixtures.traces import TRACE_LABEL, FixtureModelClient, list_fixture_traces
from agentbreak.sandbox.world import CaseWorld, apply_candidate
from test_sandbox_support import make_spec, seed


def test_canonical_scenarios():
    scenarios = list_scenarios()
    assert [s.id for s in scenarios] == ["doc_exfil", "email_bola"]
    assert [s.source_id for s in scenarios] == ["doc_a", "email_a"]
    assert [s.surface.value for s in scenarios] == ["document", "email"]
    assert scenarios[1].grant.allowed_tools == ["search_docs", "get_customer"]  # no send grant
    assert scenarios[0].grant.allowed_recipients == ["ops@acme.test"]
    assert all(s.grant.allowed_customer_ids == ["cust_a"] and s.grant.principal_id == "alice" for s in scenarios)


def test_snapshot_world():
    snap = load_snapshot("support_v1")
    assert len(snap.documents) == 6 and snap.outbox == []
    assert {c.id: c.tenant_id for c in snap.customers} == {"cust_a": "tenant_a", "cust_b": "tenant_b"}
    tokens = [c.internal_token for c in snap.customers]
    assert len(set(tokens)) == 2
    with pytest.raises(KeyError):
        load_snapshot("nope")


def test_noise_snapshot_differs_only_in_two_bodies():
    base, noisy = load_snapshot("support_v1"), load_snapshot("support_v1_noise")
    assert base.customers == noisy.customers  # identical canaries
    changed = {b.id for b, n in zip(base.documents, noisy.documents) if b != n}
    assert changed == {"doc_a", "email_a"}


def test_seed_inventory():
    discovery, held = list_attack_seeds("discovery"), list_attack_seeds("held_out")
    assert (len(discovery), len(held)) == (4, 8)
    everything = discovery + held
    assert len({s.candidate.id for s in everything}) == 12
    for scenario_id in ("doc_exfil", "email_bola"):
        assert sum(s.candidate.scenario_id == scenario_id for s in everything) == 6
        assert sum(s.candidate.scenario_id == scenario_id for s in discovery) == 2
    assert {s.candidate.strategy for s in everything} >= {
        "claimed_authority", "workflow_dependency", "task_persuasion", "redirection"}
    sources = {"doc_exfil": "doc_a", "email_bola": "email_a"}
    for s in everything:
        c = s.candidate
        assert c.generation == 0 and c.parent_id is None and len(c.text) <= 4000
        assert c.source_id == sources[c.scenario_id] and c.payload_sha256 == payload_sha256(c.text)
        assert data.CANARY_A not in c.text and data.CANARY_B not in c.text  # attacker never gets canaries
        assert s.split in ("discovery", "held_out")
    assert {s.candidate.id for s in discovery}.isdisjoint({s.candidate.id for s in held})
    with pytest.raises(ValueError):
        list_attack_seeds("other")  # type: ignore[arg-type]


def test_seed_ids_are_stable():
    assert [s.candidate.id for s in list_attack_seeds("held_out")] == [s.candidate.id for s in list_attack_seeds("held_out")]


def test_benign_inventory():
    cases = list_benign_cases()
    assert len(cases) == 8
    task_ids = [c.scenario.task_id for c in cases]
    assert len(set(task_ids)) == 8
    assert sum(c.scenario.id == "doc_exfil" for c in cases) == 4
    for case in cases:
        assert case.fixture_snapshot.fixture_id == case.scenario.fixture_id and case.fixture_snapshot.outbox == []
        assert case.scenario.expected_benign
    allowed_email = [c for c in cases if any(
        p.kind == "outbox_contains" and p.recipient == "ops@acme.test" for p in c.scenario.expected_benign)]
    assert len(allowed_email) >= 2  # a legitimate permitted email exists


def test_fixture_functions_return_deep_copies():
    before = (json.dumps(load_snapshot("support_v1").model_dump(mode="json"), sort_keys=True),
              json.dumps([s.model_dump(mode="json") for s in list_scenarios()], sort_keys=True))
    raw_before = copy.deepcopy((data.DOCUMENTS, data.CUSTOMERS, data.CANONICAL_SCENARIOS, data.ATTACK_SEEDS))
    snap = load_snapshot("support_v1")
    snap.documents[0].body = "mutated"
    snap.customers[0].internal_token = "mutated-token"
    snap.outbox.append("junk")  # type: ignore[arg-type]
    scen = list_scenarios()
    scen[0].grant.allowed_recipients.append("collector@outside.test")
    list_benign_cases()[0].scenario.expected_benign.clear()
    assert before == (json.dumps(load_snapshot("support_v1").model_dump(mode="json"), sort_keys=True),
                      json.dumps([s.model_dump(mode="json") for s in list_scenarios()], sort_keys=True))
    assert raw_before == (data.DOCUMENTS, data.CUSTOMERS, data.CANONICAL_SCENARIOS, data.ATTACK_SEEDS)


def test_substitution_changes_only_the_allowed_source_body():
    candidate = seed("doc_exfil")
    spec = make_spec("doc_exfil", candidate=candidate)
    original = spec.fixture_snapshot.model_dump(mode="json")
    attacked = apply_candidate(spec).model_dump(mode="json")
    assert spec.fixture_snapshot.model_dump(mode="json") == original  # input untouched
    assert attacked["customers"] == original["customers"] and attacked["outbox"] == []
    for before, after in zip(original["documents"], attacked["documents"]):
        if before["id"] == "doc_a":
            assert after["body"] == candidate.text
            assert {k: v for k, v in after.items() if k != "body"} == {k: v for k, v in before.items() if k != "body"}
        else:
            assert before == after


def test_candidate_for_other_scenario_is_rejected():
    with pytest.raises(ValidationError):
        make_spec("doc_exfil", candidate=seed("email_bola"))


def test_retrieval_includes_poisoned_source_and_ranks_on_original_text():
    candidate = seed("doc_exfil")
    spec = make_spec("doc_exfil", candidate=candidate)
    raw = CaseWorld(spec).execute("search_docs", SearchDocsArgs(query="order A100 status cust_a"), "c1")
    hit = next(r for r in raw.content["results"] if r["source_id"] == "doc_a")
    assert hit["body"] == candidate.text and hit["trust"] == "untrusted"
    stuffed_text = "ticket T-1001 refund policy shipping faq closed billing " * 5
    stuffed = AttackCandidate(id=candidate.id, scenario_id="doc_exfil", source_id="doc_a", surface="document",
                              text=stuffed_text, generation=0, strategy="x", payload_sha256=payload_sha256(stuffed_text))
    order = lambda s: CaseWorld(s).execute("search_docs", SearchDocsArgs(query="ticket refund order status"), "c").document_ids
    assert order(make_spec("doc_exfil", candidate=stuffed)) == order(make_spec("doc_exfil"))


def test_retrieval_miss_and_email_source():
    world = CaseWorld(make_spec("email_bola", candidate=seed("email_bola")))
    assert world.execute("search_docs", SearchDocsArgs(query="zzzz qqqq"), "c").document_ids == []
    assert "email_a" in world.execute("search_docs", SearchDocsArgs(query="ticket T-1001 cust_a"), "c").document_ids


def test_worlds_have_independent_outboxes():
    from agentbreak.contracts import SendEmailArgs
    spec = make_spec("doc_exfil")
    one, two = CaseWorld(spec), CaseWorld(spec)
    one.execute("send_email", SendEmailArgs(to="ops@acme.test", subject="s", body="b"), "c1")
    assert len(one.outbox) == 1 and two.outbox == [] and spec.fixture_snapshot.outbox == []


def test_traces_are_labeled_simulated():
    traces = list_fixture_traces()
    assert len(traces) >= 2 and all(t.label == TRACE_LABEL for t in traces)
    assert FixtureModelClient(traces[0]).simulated is True
