# Multi-stage build: Node 22 frontend builder + Python 3.12 runtime.
FROM node:22-slim AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ALLOW_LIVE_RUNS=false \
    FRONTEND_DIST=/app/frontend/dist \
    AGENTBREAK_DB_PATH=/data/agentbreak.db

WORKDIR /app
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/requirements.lock ./requirements.lock
COPY backend/agentbreak ./agentbreak
RUN python -m pip install -c requirements.lock . \
    && mkdir -p /data /app/frontend/dist \
    && useradd --system --uid 10001 --no-create-home agentbreak \
    && chown -R agentbreak:agentbreak /data /app

COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist
RUN chown -R agentbreak:agentbreak /app/frontend/dist

VOLUME ["/data"]
USER agentbreak
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import json, urllib.request; r = json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)); assert r['status'] == 'ok'"

CMD ["python", "-m", "uvicorn", "agentbreak.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
