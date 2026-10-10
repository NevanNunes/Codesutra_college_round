import pytest

from agentbreak.contracts import DefensePreset, PolicyDecision, ToolCall
from agentbreak.policies import (
    PROTECTED_FIELDS, ToolGateway, build_gateway, normalize_recipient, policy_artifact_sha256,
    tool_schemas,
)
from test_sandbox_support import scenario

BASE, GATE = DefensePreset.BASELINE, DefensePreset.GATEWAY
TENANTS = {"cust_a": "tenant_a", "cust_b": "tenant_b"}


def gw(defense, scenario_id="doc_exfil", grant=None):
    return build_gateway(defense=defense, grant=grant or scenario(scenario_id).grant,
                         policy_version="test-v1", customer_tenants=TENANTS)


def call(name, **args):
    return ToolCall(call_id="c1", name=name, arguments=args)


def test_customer_acl():
    assert gw(GATE).review(call("get_customer", customer_id="cust_a")).decision.allow
    denied = gw(GATE).review(call("get_customer", customer_id="cust_b")).decision
    assert not denied.allow and denied.reason_codes == ["customer_not_granted"] and "GW-CUSTOMER-ACL" in denied.rule_ids
    assert gw(BASE).review(call("get_customer", customer_id="cust_b")).decision.allow  # baseline omits ACL


def test_tenant_mismatch_even_if_listed():
    grant = scenario("doc_exfil").grant.model_copy(update={"allowed_customer_ids": ["cust_a", "cust_b"]})
    assert gw(GATE, grant=grant).review(call("get_customer", customer_id="cust_b")).decision.reason_codes == ["tenant_mismatch"]


def test_send_requires_tool_grant():
    review = gw(GATE, "email_bola").review(call("send_email", to="ops@acme.test", subject="s", body="b"))
    assert not review.decision.allow and review.decision.reason_codes == ["tool_not_granted"]
    assert gw(BASE, "email_bola").review(call("send_email", to="ops@acme.test", subject="s", body="b")).decision.allow


def test_exact_recipient_allowed_and_lookalikes_denied():
    assert gw(GATE).review(call("send_email", to="ops@acme.test", subject="s", body="b")).decision.allow
    for bad in ["collector@outside.test", "ops@acme.test.evil.test", "evil-ops@acme.test", "xops@acme.test",
                "ops+x@acme.test", "ops@sub.acme.test", "ops@acme.test.test"]:
        decision = gw(GATE).review(call("send_email", to=bad, subject="s", body="b")).decision
        assert not decision.allow and decision.reason_codes == ["recipient_not_allowed"], bad
        assert gw(BASE).review(call("send_email", to=bad, subject="s", body="b")).decision.allow  # baseline omits it


@pytest.mark.parametrize("defense", [BASE, GATE])
@pytest.mark.parametrize("bad", [
    "ops@acme.test\n", "ops@acme.test,collector@outside.test", "OPS@ACME.TEST", " ops@acme.test",
    "ops@acme.test ", "ops@\u0430cme.test", "Alice <ops@acme.test>", "ops@acme.com", "ops@acme.test;x@y.test",
    "a@b.test\r\nBcc: x@y.test", "ops@acme.test\x00",
])
def test_unsupported_recipient_syntax_denied_in_both_presets(defense, bad):
    review = gw(defense).review(call("send_email", to=bad, subject="s", body="b"))
    assert not review.decision.allow and review.args is None


def test_normalize_recipient_table():
    assert normalize_recipient("ops@acme.test") == "ops@acme.test"
    assert normalize_recipient("OPS@Acme.Test") == "ops@acme.test"
    for bad in [None, 5, "", "ops", "a@b@c.test", "a@b.com", "a b@c.test", "a@c.test\n", "a@c.test,b@c.test",
                "a@\u0441.test", "<a@c.test>", '"a"@c.test', "a@c.test\t", "x" * 300 + "@c.test"]:
        assert normalize_recipient(bad) is None, bad


def test_subject_control_characters_denied_by_gateway_only():
    args = dict(to="ops@acme.test", subject="Hi\nBcc: x@y.test", body="b")
    decision = gw(GATE).review(call("send_email", **args)).decision
    assert not decision.allow and decision.reason_codes == ["subject_invalid"]
    assert gw(BASE).review(call("send_email", **args)).decision.allow


@pytest.mark.parametrize("defense", [BASE, GATE])
@pytest.mark.parametrize("extra", ["role", "approved", "admin", "tenant_id", "grant", "principal_id", "override"])
def test_privileged_arguments_rejected(defense, extra):
    review = gw(defense).review(call("get_customer", customer_id="cust_a", **{extra: "admin"}))
    assert not review.decision.allow and review.args is None
    assert "privileged_argument_rejected" in review.decision.reason_codes


@pytest.mark.parametrize("defense", [BASE, GATE])
def test_unknown_tool_and_malformed_args_denied(defense):
    assert gw(defense).review(call("delete_everything", x=1)).decision.reason_codes == ["unknown_tool"]
    for bad in [call("search_docs", query=5), call("search_docs"), call("send_email", to="ops@acme.test"),
                call("get_customer", customer_id="bad id"), call("search_docs", query="ok", extra="x")]:
        review = gw(defense).review(bad)
        assert not review.decision.allow and "schema_invalid" in review.decision.reason_codes


def test_validation_errors_never_echo_values():
    review = gw(GATE).review(call("get_customer", customer_id="SECRET VALUE with spaces"))
    assert "SECRET" not in " ".join(review.validation_errors) and review.validation_errors


def test_internal_policy_error_denies(monkeypatch):
    gateway = gw(GATE)
    monkeypatch.setattr(ToolGateway, "_decide_gateway", lambda self, tool, args: 1 / 0)
    decision = gateway.review(call("get_customer", customer_id="cust_a")).decision
    assert not decision.allow and decision.reason_codes == ["policy_internal_error"]


def test_protected_field_stripping():
    content = {"customer": {"id": "cust_a", "order_id": "A100", "internal_token": "TOKEN-123456"}}
    snapshot = {"customer": dict(content["customer"])}
    filtered, stripped = gw(GATE).filter_result("get_customer", content)
    assert "internal_token" not in filtered["customer"] and stripped == ["internal_token"]
    assert content == snapshot  # input not mutated
    kept, none = gw(BASE).filter_result("get_customer", content)
    assert kept["customer"]["internal_token"] == "TOKEN-123456" and none == []
    assert PROTECTED_FIELDS == {"internal_token"}


def test_decisions_are_valid_contract_objects():
    review = gw(GATE).review(call("get_customer", customer_id="cust_b"))
    assert isinstance(review.decision, PolicyDecision) and review.decision.policy_version == "test-v1"


def test_tool_schemas_are_closed_and_complete():
    schemas = tool_schemas()
    assert [s.name for s in schemas] == ["search_docs", "get_customer", "send_email"]
    assert all(s.input_schema["additionalProperties"] is False for s in schemas)


def test_policy_artifact_hashes():
    a, b = policy_artifact_sha256(BASE), policy_artifact_sha256(GATE)
    assert a != b and len(a) == len(b) == 64
