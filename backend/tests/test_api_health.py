"""Transport and error sanitization checks for the AgentBreak application."""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agentbreak.main import create_app


@pytest.mark.parametrize("configured", [False, True])
def test_health_is_not_live_ready(monkeypatch, configured):
    variables = {
        "ALLOW_LIVE_RUNS": "true",
        "ANTHROPIC_API_KEY": "synthetic-test-secret",
        "ATTACKER_MODEL_ID": "test-attacker",
        "TARGET_MODEL_ID": "test-target",
    }
    for key, value in variables.items():
        if configured:
            monkeypatch.setenv(key, value)
        else:
            monkeypatch.delenv(key, raising=False)

    with TestClient(create_app()) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {
        "status": "ok", "schema_version": 1, "live_ready": False
    }


@pytest.mark.parametrize(
    "method,path",
    [("GET", "/missing/synthetic-secret"), ("GET", "/api/missing")],
)
def test_missing_routes_are_sanitized_404(method, path):
    with TestClient(create_app()) as client:
        response = client.request(method, path)
    assert response.status_code == 404
    assert response.json() == {
        "error": {"code": "not_found", "message": "Resource not found."}
    }


def test_routes_are_registered():
    from agentbreak.api.routes import router
    paths = {f"/api{r.path}" for r in router.routes}
    assert "/api/health" in paths
    assert "/api/scenarios" in paths
    assert "/api/runs" in paths
    assert "/api/runs/{id}" in paths
    assert "/api/runs/{id}/events" in paths
    assert "/api/runs/{id}/retest" in paths
    assert "/api/runs/{id}/cancel" in paths
    assert "/api/runs/{id}/export" in paths


def test_wrong_method_is_sanitized():
    with TestClient(create_app()) as client:
        response = client.post("/api/health")
    assert response.status_code == 405
    assert response.headers["allow"] == "GET"
    assert response.json() == {
        "error": {"code": "method_not_allowed", "message": "Method not allowed."}
    }


def test_validation_handler_does_not_echo_input():
    app = create_app()

    @app.get("/_test/validate")
    async def validate(count: int):
        return {"count": count}

    with TestClient(app) as client:
        response = client.get("/_test/validate?count=synthetic-secret")
    assert response.status_code == 422
    assert response.json() == {
        "error": {"code": "validation_error", "message": "Request validation failed."}
    }


def test_http_error_does_not_echo_detail():
    app = create_app()

    @app.get("/_test/missing")
    async def missing():
        raise HTTPException(404, detail="synthetic-secret")

    with TestClient(app) as client:
        response = client.get("/_test/missing")
    assert response.status_code == 404
    assert response.json() == {
        "error": {"code": "not_found", "message": "Resource not found."}
    }


def test_unexpected_error_does_not_echo_exception():
    app = create_app()

    @app.get("/_test/fail")
    async def fail():
        raise RuntimeError("synthetic-secret")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/_test/fail")
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "internal_error", "message": "Internal server error."}
    }
