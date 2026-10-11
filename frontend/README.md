# AgentBreak Dashboard (Frontend) 💻

The web dashboard for **AgentBreak**, providing real-time evaluation monitoring, interactive execution trace visualization, case evidence inspection, and automated before/after mitigation comparisons.

Built with **React 19**, **TypeScript**, **Vite**, and **ReactFlow (`@xyflow/react`)**.

---

## 🌟 Key UI Features

1. **Run Setup (`RunSetup.tsx`)**:
   - Scenario selector (`doc_exfil`, `email_bola`).
   - Operation mode (Suite vs. Discover).
   - Defense presets (`baseline` vs. `gateway`).
   - Execution mode: Simulation Mode (default, zero cost) or Live Mode.
   - Resource budgets (turn limits, tool count, timeout).

2. **Run Overview (`RunOverview.tsx`)**:
   - Terminal status and real-time execution progress bar.
   - Formal metrics cards: Attack Success Rate (ASR), Attempt Rate, Block Rate, Utility Pass Rate.
   - Categorical Policy Matrix (P1–P5) breakdown.
   - Download links for Markdown (`↓ MD`) and JSON (`↓ JSON`) audit bundles.

3. **Case Results Table (`CaseList.tsx`)**:
   - Differentiated case titles showing specific benign variants (e.g. *Canonical Status Email*, *Lookup Only / Zero-Email*, *Distractor Noise Filtering*) and attack vectors (*Canary Exfil*, *Cross-Account Read / BOLA*).
   - Badges for Oracle outcomes, Benign status, and tool counts (`proposed / denied / executed`).

4. **Rich Case Evidence Modal (`CaseEvidence.tsx`)**:
   - Distinct display for **Attacker Objectives & Threat Vectors** vs. **Legitimate Task Variants**.
   - Highlights injected adversarial payloads from untrusted context.
   - Interactive tool execution trace: displays proposed arguments, policy decisions (`🛡️ BLOCKED by Policy Gateway` with reason codes, or `⚠️ EXECUTED in Sandbox`).
   - Cryptographic canary token leak warnings and state diff effects.

5. **Execution Trace Visualizer (`EventGraph.tsx`)**:
   - Interactive node-link dependency graph powered by `@xyflow/react`.
   - Chronological event timeline linking `case_started` $\rightarrow$ `source_injected` $\rightarrow$ `model_request` $\rightarrow$ `tool_proposed` $\rightarrow$ `policy_decision` $\rightarrow$ `tool_blocked` / `tool_executed`.
   - Side panel inspecting raw JSON event parameters.

6. **Mitigation Comparison View (`Comparison.tsx`)**:
   - Automated side-by-side comparison between baseline and guarded retests.
   - Displays relative ASR reduction (e.g. 100% reduction) and utility regression rates (0% regressions).

---

## 🛠️ Available Scripts

Run from the `frontend/` directory:

```bash
# Start local development server with HMR at http://localhost:5173
npm run dev

# Run unit and contract tests (Vitest)
npm test -- --run

# Check TypeScript types
npm run typecheck

# Build optimized production bundle to dist/
npm run build
```

---

## 🔌 API Proxying

In development, Vite proxies all `/api` requests to the FastAPI backend running at `http://localhost:8000`:

```ts
// vite.config.ts
server: {
  proxy: {
    '/api': 'http://localhost:8000',
  },
}
```

In production, the compiled assets in `dist/` are copied to the Docker image and served directly by FastAPI under static routes with single-page application (SPA) routing fallback to `index.html`.
