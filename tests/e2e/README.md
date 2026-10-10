# End-to-end smoke test — pending session D

No full application or browser smoke test is implemented. Add the planned
Playwright click path only after C's UI and D's run API are integrated. The
current health endpoint tests are in `backend/tests/test_api_health.py`;
they do not prove attack, guard, retest, export, or live-model behavior.
