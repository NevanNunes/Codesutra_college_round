import pytest
from uuid import uuid4
from fastapi.testclient import TestClient

from agentbreak.main import app
from agentbreak.storage.database import Database
from agentbreak.contracts import RunRequest, DefensePreset, ExecutionMode, Budget, RunSummary, RunStatus, OracleOutcome
from agentbreak.fixtures import list_scenarios
from tests.test_compare import _mock_result

client = TestClient(app)

@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    db = Database(str(db_path))
    db.initialize()
    app.state.db = db
    return db

def test_get_run_report_not_found(db):
    response = client.get(f"/api/reports/runs/{uuid4()}")
    assert response.status_code == 404

def test_get_run_report(db):
    run_id = uuid4()
    req = RunRequest(scenario_ids=["doc_exfil"], operation="discover", defense=DefensePreset.BASELINE, execution_mode=ExecutionMode.FIXTURE, budget=Budget(), seed=42)
    db.create_run(run_id, req)
    db.update_run_status(run_id, RunStatus.COMPLETED)
    
    # Add some mock cases
    # Add some mock cases
    from agentbreak.contracts import CaseSpec, ModelSettings
    from agentbreak.fixtures import list_scenarios, load_snapshot
    scenario = list_scenarios()[0]
    snapshot = load_snapshot(scenario.fixture_id)
    case_res = _mock_result(candidate_id=uuid4(), task_id="task_1", benign_success=None, oracle_outcome=OracleOutcome.FAILURE)
    spec = CaseSpec(run_id=run_id, trial_id=case_res.trial_id, scenario=scenario, defense=DefensePreset.BASELINE, execution_mode=ExecutionMode.FIXTURE, fixture_snapshot=snapshot, seed=42, model_settings=ModelSettings(provider="test", target_model_id="test", attacker_model_id="test", temperature=0, max_tokens=1), policy_version="v1")
    db.save_case_spec(run_id, spec)
    db.save_case_result(run_id, case_res)
    
    response = client.get(f"/api/reports/runs/{run_id}")
    assert response.status_code == 200
    data = response.json()
    assert "security_overview" in data
    assert data["security_overview"]["run_id"] == str(run_id)
    assert data["security_overview"]["target_profile"] == "baseline"

def test_compare_runs(db):
    b_run_id = uuid4()
    d_run_id = uuid4()
    req = RunRequest(scenario_ids=["doc_exfil"], operation="discover", defense=DefensePreset.BASELINE, execution_mode=ExecutionMode.FIXTURE, budget=Budget(), seed=42)
    db.create_run(b_run_id, req)
    db.create_run(d_run_id, req)
    
    from agentbreak.contracts import CaseSpec, ModelSettings
    from agentbreak.fixtures import list_scenarios, load_snapshot
    scenario = list_scenarios()[0]
    snapshot = load_snapshot(scenario.fixture_id)

    # Baseline case
    cid = uuid4()
    b_res = _mock_result(candidate_id=cid, defense=DefensePreset.BASELINE, oracle_outcome=OracleOutcome.FAILURE)
    spec_b = CaseSpec(run_id=b_run_id, trial_id=b_res.trial_id, scenario=scenario, defense=DefensePreset.BASELINE, execution_mode=ExecutionMode.FIXTURE, fixture_snapshot=snapshot, seed=42, model_settings=ModelSettings(provider="test", target_model_id="test", attacker_model_id="test", temperature=0, max_tokens=1), policy_version="v1")
    db.save_case_spec(b_run_id, spec_b)
    db.save_case_result(b_run_id, b_res)
    
    # Defended case
    d_res = _mock_result(candidate_id=cid, defense=DefensePreset.GATEWAY, oracle_outcome=OracleOutcome.FAILURE)
    spec_d = CaseSpec(run_id=d_run_id, trial_id=d_res.trial_id, scenario=scenario, defense=DefensePreset.GATEWAY, execution_mode=ExecutionMode.FIXTURE, fixture_snapshot=snapshot, seed=42, model_settings=ModelSettings(provider="test", target_model_id="test", attacker_model_id="test", temperature=0, max_tokens=1), policy_version="v1")
    db.save_case_spec(d_run_id, spec_d)
    db.save_case_result(d_run_id, d_res)
    
    response = client.get(f"/api/reports/compare?baseline_run_id={b_run_id}&defended_run_id={d_run_id}")
    assert response.status_code == 200
    data = response.json()
    assert "utility" in data
    assert "categories" in data
