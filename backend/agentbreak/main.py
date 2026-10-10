"""Health-only ASGI application; execution adapters are not implemented yet."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from agentbreak.contracts import HealthResponse


def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def create_app() -> FastAPI:
    """Construct an isolated app with no jobs, storage, or provider side effects."""
    app = FastAPI(
        title="AgentBreak scaffold",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(RequestValidationError)
    async def validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Validation details can contain submitted input and must not be echoed.
        return _error_response(422, "validation_error", "Request validation failed.")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        errors = {
            404: ("not_found", "Resource not found."),
            405: ("method_not_allowed", "Method not allowed."),
        }
        code, message = errors.get(exc.status_code, ("http_error", "Request failed."))
        response = _error_response(exc.status_code, code, message)
        # Preserve routing's Allow header without reflecting arbitrary details.
        if exc.status_code == 405 and exc.headers and "Allow" in exc.headers:
            response.headers["Allow"] = exc.headers["Allow"]
        return response

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        return _error_response(500, "internal_error", "Internal server error.")

    @app.get("/api/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        # Environment values alone cannot make an unimplemented adapter ready.
        return HealthResponse(status="ok", schema_version=1, live_ready=False)

    return app


app = create_app()
