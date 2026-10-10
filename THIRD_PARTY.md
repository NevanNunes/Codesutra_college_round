# Third-party inventory

This initial scaffold contains original project code and no copied benchmark
data, external attack corpora, or vendored third-party source. Dependencies
below are declared in `backend/pyproject.toml`; tested resolved versions are
recorded in `backend/requirements.lock` and `backend/requirements-dev.lock`.
Transitive license notices still need review before a release.
This table is not a completed redistribution audit.

| Dependency | Purpose | Declared range | Upstream license/reference |
| --- | --- | --- | --- |
| FastAPI | HTTP application | `>=0.115,<1` | MIT; https://github.com/fastapi/fastapi |
| Pydantic | Shared validation models | `>=2.9,<3` | MIT; https://github.com/pydantic/pydantic |
| Uvicorn | ASGI server | `>=0.30,<1` | BSD-3-Clause; https://github.com/encode/uvicorn |
| pytest | Development tests | `>=8.3,<10` | MIT; https://github.com/pytest-dev/pytest |
| pytest-asyncio | Async test support | `>=0.24,<2` | Apache-2.0; https://github.com/pytest-dev/pytest-asyncio |
| HTTPX | Test HTTP transport | `>=0.27,<1` | BSD-3-Clause; https://github.com/encode/httpx |
| setuptools | Package build backend | `>=75,<83` | MIT; https://github.com/pypa/setuptools |

The optional container uses the `python:3.12-slim` image (Python and Debian
components with their respective licenses). Pin an image digest and review
the selected image's component notices before a release. No Node runtime or
frontend dependency is installed by this scaffold.

AgentDojo, Promptfoo, PyRIT, garak, NeMo Guardrails, OPA, and OWASP are research
references in the build guide, not bundled integrations or licensed assets in
this scaffold. Importing datasets or code later requires recording the exact
source/version, artifact license, changes, and required attribution here.
An Anthropic SDK transport is planned but no SDK dependency or adapter exists.
