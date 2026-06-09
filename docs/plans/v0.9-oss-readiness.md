# v0.9 — Open-Source Readiness

Goal: take Horus from "well-engineered personal project" to "a stranger
can find it, trust it, install it, and contribute." Everything below is
hygiene/scaffolding — no new product features.

## Tier 1 — blockers (do these first)

- [ ] **`LICENSE`** at repo root. Without one, the code is legally
      unusable by anyone but the author. Recommend MIT or Apache-2.0.
- [ ] **CI** — `.github/workflows/test.yml` running `pytest tests/` on
      every push + PR against Python 3.10 / 3.11 / 3.12 / 3.13.
- [ ] **`pyproject.toml`** replacing `setup.py`. Modern Python packaging
      (`[project]`, `[tool.ruff]`, `[tool.pytest.ini_options]`).
- [ ] **Tag `v0.8.0`** on GitHub and create a Release with the diff
      summary as the body.

## Tier 2 — credibility

- [ ] **`CHANGELOG.md`** — the README already links it; needs to exist.
      Use [Keep a Changelog] format.
- [ ] **`CONTRIBUTING.md`** — how to set up the venv, run the tests,
      style guide, PR checklist.
- [ ] **`SECURITY.md`** — vulnerability-reporting policy. (For a CVE
      scanner, this is non-negotiable for trust.)
- [ ] **`CODE_OF_CONDUCT.md`** — Contributor Covenant v2.1 is the
      default.
- [ ] **Issue/PR templates** under `.github/ISSUE_TEMPLATE/`:
      `bug_report.md`, `feature_request.md`, `pull_request_template.md`.
- [ ] **README badges** — CI status, Python versions, license, latest
      release. These are the first thing a new visitor reads.

## Tier 3 — distribution

- [ ] **Publish to PyPI** as `horus-scanner` (the name `horus` is
      taken). `pip install horus-scanner` is the goal.
- [ ] **Publish Docker image** to `ghcr.io/yusif-v/horus`. The README
      already has a Dockerfile — wire it into a release workflow that
      builds + tags `:0.8.0` and `:latest`.
- [ ] **`HORUS_STATE_DIR` env var** override for the SQLite path so
      `docker run -v /data:/data -e HORUS_STATE_DIR=/data` works without
      bind-mounting the package itself.

## Tier 4 — code quality enforcement

- [ ] **`ruff`** as both linter and formatter; config in
      `pyproject.toml`. Add a `pre-commit` hook.
- [ ] **`mypy --strict`** on `horus/core/` and `horus/pipeline.py`
      (start small — full-package strict is a separate fight).
- [ ] **Test coverage gate** — wire `pytest-cov` into CI, fail under
      70 %.
- [ ] **Drop the `datetime.utcnow()` deprecation warnings** surfaced
      by the test run (~40 of them).

## Tier 5 — documentation polish

- [ ] **Web UI screenshots** in the README — Overview + Triage at
      minimum. A 5-second GIF of switching pages would close the gap
      between "looks like a CLI tool" and "real product."
- [ ] **Plugin authoring guide** at `docs/plugins.md`: the `run()` /
      `enrich()` contract, return shape, registration rules. Today this
      is implied by reading four source files.
- [ ] **API reference** at `docs/api.md` for `/api/stats` and
      `/api/cve/<id>` — schema, fields, examples. The endpoints already
      exist; consumers shouldn't have to read SQL to use them.
- [ ] **Comparison table** ("Why Horus vs nuclei / vuls / Trivy?") so a
      visitor knows in 30 seconds whether this is for them.

## Tier 6 — community

- [ ] Enable **GitHub Discussions**.
- [ ] **Stale-bot** for issues idle 90+ days.
- [ ] **Dependabot** for `pyproject.toml` + the GHA workflows.
- [ ] **Code owners** (`.github/CODEOWNERS`).

## Out of scope (deliberately)

These would be nice but cross from "OSS hygiene" into "new features":
- Web UI auth / multi-tenant mode
- HTTP API beyond `/api/stats` + `/api/cve/<id>`
- Plugin marketplace
- A hosted demo

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
