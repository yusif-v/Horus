# Code-Quality Tooling

Modernise the Python toolchain. Target: a contributor opens the repo
and the editor + CI already enforce style, types, and packaging norms
without any setup beyond `pip install -e ".[dev]"`.

Slot into a future v0.9 or v0.10 — undecided.

## Tier 1 — packaging

- [ ] **Replace `setup.py` with `pyproject.toml`** ([PEP 621]).
      Everything that's in `setup.py` today moves into a `[project]`
      table; `setuptools` stays as the build backend so the install
      story (`pip install -e .`) doesn't change.
- [ ] **Consolidate dependency sources.** Today `requirements.txt` and
      `setup.py`'s `extras_require` can drift. Pick one: keep the
      `[project.optional-dependencies]` in `pyproject.toml` as the
      source of truth, delete `requirements.txt` (or auto-generate it
      from the project metadata for legacy tooling).
- [ ] **`python_requires` consistency.** `setup.py` currently says
      `>=3.10`. Match it to:
      - `pyproject.toml` `requires-python`
      - the CI matrix (when it lands — see `oss-readiness.md`)
      - a `.python-version` file (3.12 as the dev default)
      - the Dockerfile base image
      One number, four places, never drifting.

## Tier 2 — lint + format

- [ ] **`ruff`** as both linter and formatter. Config in
      `[tool.ruff]` inside `pyproject.toml` — no separate `ruff.toml`.
      Suggested ruleset to start:
      - `E`, `F`, `W` (pyflakes + pycodestyle)
      - `I` (isort import ordering)
      - `B` (bugbear — catches real bugs, not just style)
      - `UP` (pyupgrade — keeps us on modern syntax)
      - `SIM` (simplify)
      - `RUF` (ruff's own rules)
- [ ] **`ruff format`** replaces black (it's drop-in compatible and
      ~30× faster).
- [ ] **Pre-commit hook** (`pre-commit` package, `.pre-commit-config.yaml`)
      so `git commit` runs ruff + ruff format locally. Same hook runs
      in CI as a fall-back.

## Tier 3 — type checking

- [ ] **`mypy --strict` on `horus/core/` and `horus/pipeline.py`
      first.** These are pure-Python, no I/O — easiest to type cleanly.
      Get them green before expanding.
- [ ] Then **expand to `horus/storage/`** (well-bounded contract:
      sqlite3 rows in, dataclasses out).
- [ ] Then **`horus/sources/` + `horus/enrichers/`** — these talk to
      JSON APIs, so add `TypedDict` for the dicts and stop using `Any`.
- [ ] Leave `horus/web/` for last — Flask + Jinja typing is a fight
      that isn't worth picking first.
- [ ] Config in `[tool.mypy]` with per-module strictness overrides:
      `[tool.mypy.overrides]` so we can ratchet section by section
      without one giant flag day.

## Tier 4 — testing

- [ ] **`pytest-cov`** in dev extras; CI fails under 70 %.
- [ ] **`hypothesis`** for property tests on the reputation-score
      formula (today it's only example-based) and the merge-dedup logic.
- [ ] Drop the **`datetime.utcnow()` deprecation warnings** that the
      test run currently surfaces (`db.py`, `web/_render.py`, the
      dataclass defaults in `core/model.py`). Replace with
      `datetime.now(timezone.utc)`.

## Tier 5 — supply chain

- [ ] **`pip-audit`** in CI, gated on `cve_severity >= HIGH` so it
      doesn't fail the build on every advisory.
- [ ] **Dependabot** for `pyproject.toml` + the GHA workflows
      (overlaps with `oss-readiness.md` — track in whichever lands
      first).
- [ ] **`SBOM`** (CycloneDX) generated on release. Nice-to-have, not
      blocking.

## Definition of done

After this rolls in:

```bash
$ pip install -e ".[dev]"
$ pre-commit install
$ ruff check .          # 0 errors
$ ruff format --check . # 0 diffs
$ mypy horus/core horus/pipeline  # 0 errors
$ pytest --cov=horus    # ≥ 70 %
```

And `setup.py`, `requirements.txt`, and the version-string drift are
all gone.

[PEP 621]: https://peps.python.org/pep-0621/
