# How to Run AgentBreak Locally

This guide explains how to start, verify, and stop the AgentBreak servers locally in the future.

---

## 🚀 Option 1: Native Local Development (Recommended)

This runs the backend with Uvicorn auto-reload and the frontend with Vite hot-reloading.

### 1. Start the Backend (FastAPI)
Open a terminal in the project root:
```bash
# From repository root:
PYTHONPATH=backend backend/.venv/bin/uvicorn agentbreak.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Backend API:** [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Endpoint:** [http://localhost:8000/api/health](http://localhost:8000/api/health)

### 2. Start the Frontend (Vite)
Open a second terminal window:
```bash
cd frontend
npm run dev
```
- **Web Dashboard:** [http://localhost:5173](http://localhost:5173)  
*(Vite automatically proxies `/api` calls to port 8000).*

---

## 🐳 Option 2: Containerized Execution (Docker Compose)

This builds the production container where FastAPI serves both the API endpoints and the compiled frontend single-page application (SPA).

```bash
# Build and run the single-origin container:
docker compose up --build
```
- **Combined Web App & API:** [http://localhost:8000](http://localhost:8000)
- To stop: press `Ctrl + C` or run `docker compose down`.

---

## 🧪 Testing & Verification Commands

### 1. Run the CLI Regression Test Suite
Runs a deterministic 16-case evaluation against the local running backend:
```bash
# Against Gateway defense preset (blocks attacks):
PYTHONPATH=backend backend/.venv/bin/python -m agentbreak.cli regress --mode fixture --defense gateway

# Against Baseline preset (demonstrates vulnerabilities):
PYTHONPATH=backend backend/.venv/bin/python -m agentbreak.cli regress --mode fixture --defense baseline
```

### 2. Run Backend Unit & Integration Tests (284 Tests)
```bash
PYTHONPATH=backend backend/.venv/bin/pytest backend/tests
```

### 3. Run Frontend Tests & Build (17 Tests)
```bash
cd frontend
npm test -- --run
npm run build
```

---

## 🛑 How to Stop the Servers

1. In the terminal windows where Uvicorn and Vite are running, press `Ctrl + C`.
2. If any background process remains attached to the ports, run:
```bash
# Free port 8000 (Backend)
lsof -ti :8000 | xargs kill -9

# Free port 5173 (Frontend)
lsof -ti :5173 | xargs kill -9
```
