"""Export the design-time API contract; this does not register HTTP routes."""

import argparse
import json
from pathlib import Path

from pydantic.json_schema import models_json_schema

from agentbreak import contracts as c


# Path, method, request model, success model, success status.
ROUTES = [
    ("/api/health", "get", None, c.HealthResponse, 200),
    ("/api/scenarios", "get", None, c.ScenariosResponse, 200),
    ("/api/runs", "post", c.RunRequest, c.RunAccepted, 202),
    ("/api/runs", "get", None, c.RunsResponse, 200),
    ("/api/runs/{id}", "get", None, c.RunDetailResponse, 200),
    ("/api/runs/{id}/events", "get", None, c.EventsResponse, 200),
    ("/api/runs/{id}/retest", "post", c.RetestRequest, c.RetestAccepted, 202),
    ("/api/runs/{id}/cancel", "post", None, c.CancelResponse, 202),
    ("/api/runs/{id}/export", "get", None, c.ReplayBundle, 200),
]


def _ref(model):
    return {"$ref": f"#/components/schemas/{model.__name__}"}


def build_contract_openapi():
    models = {c.ErrorResponse}
    for _, _, request, response, _ in ROUTES:
        models.add(response)
        if request:
            models.add(request)
    _, schema = models_json_schema(
        [(model, "validation") for model in sorted(models, key=lambda model: model.__name__)],
        ref_template="#/components/schemas/{model}",
    )
    paths = {}
    for path, method, request, response, status in ROUTES:
        implemented = path == "/api/health"
        success_content = {"application/json": {"schema": _ref(response)}}
        operation = {
            "operationId": method + "_" + path.strip("/").replace("/", "_").replace("{id}", "by_id"),
            "x-agentbreak-implementation": "implemented" if implemented else "pending",
            "description": "Health scaffold." if implemented else "Design contract only; runtime route not implemented.",
            "responses": {str(status): {"description": "Success", "content": success_content}},
        }
        if request:
            operation["requestBody"] = {
                "required": True, "content": {"application/json": {"schema": _ref(request)}},
            }
        parameters = []
        if "{id}" in path:
            parameters.append({"name": "id", "in": "path", "required": True,
                               "schema": {"type": "string", "format": "uuid"}})
        query_model = c.EventsQuery if path.endswith("/events") else c.RunsQuery if (path, method) == ("/api/runs", "get") else None
        if query_model:
            for name, definition in query_model.model_json_schema()["properties"].items():
                parameters.append({"name": name, "in": "query", "schema": definition})
        if path.endswith("/export"):
            parameters.append({"name": "format", "in": "query",
                               "schema": {"type": "string", "enum": ["json", "markdown"], "default": "json"}})
            success_content["text/markdown"] = {"schema": {"type": "string"}}
        if parameters:
            operation["parameters"] = parameters
        if not implemented:
            operation["security"] = [{"demoBearer": []}]
            for code in (401, 404, 409, 422, 429, 500):
                operation["responses"][str(code)] = {
                    "description": "Sanitized API error",
                    "content": {"application/json": {"schema": _ref(c.ErrorResponse)}},
                }
        paths.setdefault(path, {})[method] = operation
    return {
        "openapi": "3.1.0",
        "info": {"title": "AgentBreak design-time contract", "version": "1",
                 "description": "Only health is implemented. Other operations and bearer auth are planned, not runtime capabilities."},
        "paths": paths,
        "components": {"schemas": schema["$defs"], "securitySchemes": {
            "demoBearer": {"type": "http", "scheme": "bearer",
                           "description": "Planned shared demo access token; never a provider API key."},
        }},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="Generated JSON artifact destination; parent must exist")
    args = parser.parse_args()
    args.output.write_text(json.dumps(build_contract_openapi(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
