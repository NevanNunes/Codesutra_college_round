# Health-only Python scaffold. No frontend assets are built or served yet.
# When C supplies a frontend, D can add the planned Node 22 builder stage
# and copy its built assets into the Python runtime (two-stage deployment).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ALLOW_LIVE_RUNS=false

WORKDIR /app
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/requirements.lock ./requirements.lock
COPY backend/agentbreak ./agentbreak
RUN python -m pip install -c requirements.lock . \
    && useradd --system --uid 10001 --no-create-home agentbreak

USER agentbreak
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import json, urllib.request; r = json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)); assert r['status'] == 'ok'"

CMD ["python", "-m", "uvicorn", "agentbreak.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
