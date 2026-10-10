"""FastAPI application for AgentBreak."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException

from agentbreak.api.routes import get_orchestrator, router


def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    orchestrator = get_orchestrator()
    orchestrator.start()
    yield
    await orchestrator.stop()


def create_app() -> FastAPI:
    """Construct the AgentBreak FastAPI application."""
    app = FastAPI(
        title="AgentBreak",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.exception_handler(RequestValidationError)
    async def validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return _error_response(422, "validation_error", "Request validation failed.")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        error_map = {
            404: ("not_found", "Resource not found."),
            405: ("method_not_allowed", "Method not allowed."),
            401: ("unauthorized", "Unauthorized request."),
            429: ("rate_limited", "Rate limit exceeded."),
        }
        detail_map = {
            "queue_full": "Queue capacity reached.",
            "invalid_transition": "Invalid state transition.",
            "live_not_ready": "Live mode is not configured or enabled.",
            "not_found": "Resource not found.",
            "unauthorized": "Unauthorized request.",
        }

        if exc.status_code == 409:
            code = exc.detail if exc.detail in detail_map else "conflict"
            message = detail_map.get(exc.detail, "Conflict.")
        elif exc.status_code in error_map:
            code, message = error_map[exc.status_code]
        else:
            code = "http_error"
            message = "Request failed."

        response = _error_response(exc.status_code, code, message)
        if exc.status_code == 405 and exc.headers and "Allow" in exc.headers:
            response.headers["Allow"] = exc.headers["Allow"]
        return response

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        return _error_response(500, "internal_error", "Internal server error.")

    # Mount API routes
    app.include_router(router, prefix="/api")

    # Serve built frontend only if FRONTEND_DIST is explicitly set
    frontend_dist_str = os.environ.get("FRONTEND_DIST")
    if frontend_dist_str:
        frontend_dist = Path(frontend_dist_str)
        if frontend_dist.is_dir():
            @app.get("/{full_path:path}", include_in_schema=False)
            async def serve_frontend(full_path: str):
                if full_path.startswith("api/") or full_path == "api":
                    return _error_response(404, "not_found", "Resource not found.")
                target = frontend_dist / full_path
                if target.is_file():
                    return FileResponse(target)
                index_path = frontend_dist / "index.html"
                if index_path.is_file():
                    return FileResponse(index_path)
                return _error_response(404, "not_found", "Resource not found.")

    return app


app = create_app()
