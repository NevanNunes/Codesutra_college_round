from fastapi import APIRouter, Depends, Header, Request, Query
from fastapi.responses import JSONResponse
from uuid import UUID

from agentbreak.storage.database import Database
from agentbreak.api.routes import _error, _check_auth
from agentbreak.evaluation.metrics import calculate_metrics
from agentbreak.evaluation.scoring import score_finding
from agentbreak.evaluation.report import generate_dashboard_report, DashboardReport
from agentbreak.evaluation.compare import compare_runs, ComparisonReport

report_router = APIRouter(prefix="/api/reports")

@report_router.get("/runs/{run_id}", response_model=DashboardReport)
async def get_run_report(
    run_id: UUID,
    request: Request,
    authorization: str | None = Header(default=None),
) -> DashboardReport | JSONResponse:
    auth_err = _check_auth(authorization)
    if auth_err:
        return auth_err
        
    db: Database = request.app.state.db
    run = db.get_run(run_id)
    if run is None:
        return _error(404, "not_found", "Run not found.")
        
    cases = db.get_full_cases(run_id)
    results = [result for spec, result in cases]
    events = db.get_events(run_id, limit=500).items
    
    # Generate sub-reports
    metrics = calculate_metrics(results)
    
    scores = []
    for r in results:
        for v in r.violations:
            scores.append(score_finding(r.trial_id, v, is_executed=True))
        for av in r.attempted_violations:
            scores.append(score_finding(r.trial_id, av, is_executed=False))

    return generate_dashboard_report(run_id, results, events, metrics, scores, None)


@report_router.get("/compare", response_model=ComparisonReport)
async def get_comparison_report(
    request: Request,
    baseline_run_id: UUID = Query(...),
    defended_run_id: UUID = Query(...),
    authorization: str | None = Header(default=None),
) -> ComparisonReport | JSONResponse:
    auth_err = _check_auth(authorization)
    if auth_err:
        return auth_err
        
    db: Database = request.app.state.db
    
    b_cases = db.get_full_cases(baseline_run_id)
    d_cases = db.get_full_cases(defended_run_id)
    
    if not b_cases:
        return _error(404, "not_found", "Baseline run not found or has no cases.")
    if not d_cases:
        return _error(404, "not_found", "Defended run not found or has no cases.")
        
    b_results = [result for spec, result in b_cases]
    d_results = [result for spec, result in d_cases]
    
    report = compare_runs(b_results, d_results)
    return report
