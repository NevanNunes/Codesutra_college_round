# Multi-stage Docker build:
# Stage 1: Build the React/Vite frontend with Node 22
FROM node:22-slim AS frontend-builder

WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Python runtime serving both FastAPI and built frontend assets
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ALLOW_LIVE_RUNS=false \
    STATIC_DIR=/app/frontend/dist

WORKDIR /app

COPY backend/pyproject.toml ./pyproject.toml
COPY backend/requirements.lock ./requirements.lock
COPY backend/agentbreak ./agentbreak

RUN python -m pip install -c requirements.lock . \
    && useradd --system --uid 10001 --no-create-home agentbreak \
    && mkdir -p /data /app/frontend/dist \
    && chown -R agentbreak:agentbreak /data /app

# Copy built frontend assets from Stage 1
COPY --from=frontend-builder --chown=agentbreak:agentbreak /build/dist /app/frontend/dist

USER agentbreak
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import json, urllib.request; r = json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)); assert r['status'] == 'ok'"

CMD ["python", "-m", "uvicorn", "agentbreak.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
