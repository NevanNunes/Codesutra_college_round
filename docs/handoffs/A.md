# Session A — pending

Status: no attack/evaluation implementation has been completed.

- Own `backend/agentbreak/attacks/`, `evaluation/`, `cli.py`, attack/metric
  tests, and `integrations/promptfoo/`.
- Package directories are documented empty scaffolds. The CLI exits 2 with
  an unimplemented message; it is not a regression runner.
- Next: review frozen contracts, then implement bounded discovery and pure
  evaluation/reporting against the shared async seams.
- Checks: no A module behavior has been tested. Record actual commands and
  outcomes here when implemented; request dependencies/schema changes from D.
