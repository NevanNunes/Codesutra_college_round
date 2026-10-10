import json
from pathlib import Path

from agentbreak.api.contract_schema import build_contract_openapi


def test_published_openapi_is_current_and_refs_resolve():
    schema = build_contract_openapi()
    artifact = Path(__file__).resolve().parents[2] / "docs" / "contract-openapi.json"
    assert json.loads(artifact.read_text(encoding="utf-8")) == schema

    def visit(value):
        if isinstance(value, dict):
            if "$ref" in value:
                target = schema
                for segment in value["$ref"].removeprefix("#/").split("/"):
                    target = target[segment]
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(schema)
    for path, methods in schema["paths"].items():
        for operation in methods.values():
            assert operation["x-agentbreak-implementation"] == ("implemented" if path == "/api/health" else "pending")
    assert schema["components"]["schemas"]["RunRequest"]["additionalProperties"] is False
