HORUS — FULL ARCHITECTURAL AUDIT & STRATEGIC PLAN
v0.11.2 PATCH PLAN + v0.12 UPGRADE ROADMAP
==============================================

## PART 1: CURRENT STATE AUDIT (v0.11.x)

### 1.1 Architecture Overview

Horus is a Python/Flask CVE intelligence platform with a plugin-based
architecture. It ingests from 7+ data sources (NVD, GitHub, GitLab,
Codeberg, X/Twitter, Exploit-DB, RSS news feeds), enriches with EPSS
and KEV, stores in SQLite, and provides:
  - Web UI (Flask + Jinja2, 19 templates)
  - Telegram Bot (long-polling, 8 commands)
  - JSON API (/api/stats, /api/cves, /api/cve/<id>)
  - CLI (--server daemon mode, --query, --export-json)

### 1.2 Plugin Architecture (STRENGTH)

The auto-discovery system is already well-designed:
  - `pkgutil.iter_modules` scans `horus/sources/` for files exporting `run(ctx)`
  - Same for `horus/enrichers/` exporting `enrich(ctx)`
  - `SourceContext` / `EnricherContext` dataclasses define clean contracts
  - `PROVIDES` / `CONSUMES` mechanism enables inter-source handoff
    (x_twitter discovers URLs → GitHub enriches them)

This means adding a new data source = drop a .py file with `run(ctx)`.
No registry changes needed. This is already close to OpenCTI's connector
model in spirit.

### 1.3 Data Sources Current State

| Source        | Status  | Auth              | Mandatory? |
|---------------|---------|-------------------|------------|
| NVD           | Active  | None              | YES (core) |
| X/Twitter     | Active  | X/Chrome Auth     | Optional   |
| GitHub        | Active  | GitHub token      | Optional   |
| GitLab        | Active  | None              | Optional   |
| Codeberg      | Active  | Codeberg token    | Optional   |
| Exploit-DB    | Active  | None              | Optional   |
| News (RSS)    | Active  | None              | Optional   |
| Resources     | Active  | X/Chrome Auth     | Optional   |

PROBLEM: All sources are always active. No way to disable them without
deleting files or commenting out code. No configuration layer to
toggle sources on/off.

### 1.4 Docker Setup (MAJOR GAP)

Current Dockerfile:
  - Single-stage python:3.12-slim
  - No non-root user (runs as root)
  - No healthcheck instruction
  - No multi-stage build (includes pip cache)
  - Volumes declared but not in practice
  - Entrypoint: python -m horus --server

MISSING:
  - docker-compose.yml (does not exist)
  - Reverse proxy config (nginx/caddy)
  - Database backup volume
  - Environment variable templating (.env.sample)
  - Health check endpoints
  - Logging driver config

This is the #1 blocker for easy deployment on another server.

### 1.5 Configuration (MODERATE GAP)

Current env handling:
  - Custom stdlib .env parser (no python-dotenv dep)
  - Existing env vars win over .env file
  - TELEGRAM_BOT_TOKEN, HORUS_SECRET_KEY configured here

Server config: YAML or JSON file with poll_intervals and sources_enabled.

PROBLEM: `sources_enabled` toggles exist in YAML config but:
  1. No documentation on the YAML format
  2. No UI for configuration
  3. No per-source auth configuration via env
  4. Sources requiring secrets (GitHub, Codeberg, X) just fail silently
     if tokens are missing
  5. No "source health" feedback — user doesn't know which sources work

### 1.6 Security (MIXED)

Strengths:
  - Werkzeug password hashing (pbkdf2:sha256)
  - Timing attack prevention (dummy hash on failed login)
  - CSRF via Flask-WTF
  - RBAC: admin/analyst/viewer + red/blue team isolation
  - Safe redirect validation (_is_safe_url)
  - All SQL parameterized
  - Audit logging (audit_event table)

Gaps:
  - Login endpoint: no rate limiting (brute-force risk)
  - No CSP / HSTS / X-Frame-Options headers
  - Docker runs as root
  - No request size limits
  - EPSS CSV downloaded over HTTP (no integrity check)
  - No structured logging (print() to stderr)
  - GitHub token cached via @lru_cache for process lifetime
  - API endpoints: no CORS configuration
  - No test execution in CI (only pip-audit)

### 1.7 Testing (MODERATE GAP)

37 test files covering: pipeline, core, storage, web routes, auth,
classify, merge, url_extractor, news, nvd envelope.

Missing coverage for:
  - notifications/dispatcher.py
  - bot/telegram.py
  - config/ module
  - net/auth.py (token resolution logic)
  - net/xsearch.py (X/Twitter auth flow)

CI runs pip-audit only — no test execution. ruff/mypy configured but
not enforced in CI.

### 1.8 CI/CD (SIGNIFICANT GAP)

Current:
  - pip-audit on push to main, PRs, weekly cron
  - Dependabot weekly PRs (max 5 prod, 3 dev)

Missing:
  - No pytest in CI
  - No ruff/mypy in CI
  - No Docker build/publish
  - No integration tests
  - No test against multiple Python versions
  - No release automation

### 1.9 Database

SQLite with dual migration:
  - schema.sql: idempotent CREATE TABLE IF NOT EXISTS
  - _migrate_columns(): ALTER TABLE via PRAGMA introspection

20+ tables. Works fine for single-server deployment.

PROBLEM for v0.12: SQLite cannot handle concurrent writes from
multiple workers. If we add async/parallel fetching, we need either:
  - WAL mode + busy_timeout (pragmatic for now)
  - PostgreSQL option (for future scaling)

---

## PART 2: OPENCTI ARCHITECTURE ANALYSIS (REFERENCE MODEL)

### 2.1 Key Patterns Worth Adopting

1. CONNECTOR-AS-CONTAINER: Each data source is a standalone Docker
   image with env-var config. Portable, independently versioned.

2. MINIMAL MANDATORY CONFIG: Just URL + token + ID + type + name.
   Everything else is connector-specific. Low barrier to entry.

3. HEALTH-CHECK GATING: All services use depends_on: condition:
   service_healthy. No race conditions between components.

4. AUTO-UPGRADE: docker-compose pull && up -d handles everything.
   Database migrations are automatic and transparent.

5. CONNECTOR TYPES TAXONOMY: External-import, Internal-enrichment,
   Import-file, Export-file, Stream. Clear separation of concerns.

6. XTM COMPOSER: Integration manager that auto-launches connector
   containers based on platform registrations.

### 2.2 What Horus Should Borrow

| OpenCTI Pattern          | Horus Adaptation                              |
|--------------------------|-----------------------------------------------|
| docker-compose.yml       | Create multi-service compose (horus + proxy)  |
| Connector type taxonomy  | cve_source / poc_source / enricher / news     |
| .env.sample              | Create .env.sample with all options           |
| Health endpoint          | Add /health endpoint to Flask app             |
| Per-connector auth       | Each source reads its own env vars            |
| UI-based connector mgmt  | Admin panel: enable/disable sources, set tokens|

### 2.3 What Horus Does NOT Need

- ElasticSearch (SQLite is fine for CVE-scale data)
- RabbitMQ (thread-based parallelism is sufficient)
- 3-worker scaling (single Horus instance handles CVE volume)
- Full STIX mapping (not a CTI sharing platform)

---

## PART 3: v0.11.2 PATCH PLAN

### Priority P0 — Security & Deployment Foundations

P0-1: Add tests to CI
  - Add pytest job to .github/workflows/security.yml
  - Run with coverage, fail under 70%
  - Files: .github/workflows/security.yml

P0-2: Docker Hardening
  - Add non-root user (horus:horus, UID 1000)
  - Add HEALTHCHECK instruction (curl http://localhost:8080/health)
  - Switch to multi-stage build (smaller image)
  - Add proper VOLUME for /app/state
  - Files: Dockerfile

P0-3: Login Rate Limiting
  - Add Flask-Limiter to auth blueprint
  - Default: 5 per minute on /login route
  - Files: horus/web/routes/auth.py, pyproject.toml

P0-4: Security Headers
  - Add CSP, HSTS, X-Frame-Options, X-Content-Type-Options
  - Implement in web/__init__.py as after_request hook
  - Files: horus/web/__init__.py

### Priority P1 — Configuration & Operational Fixes

P1-1: Create .env.sample
  - Document every env var with description and example
  - Mark required vs optional
  - Files: .env.sample (new)

P1-2: Source Toggle via Configuration
  - Sources read HORUS_SOURCES_ENABLED env var (comma-separated list)
  - Missing sources are gracefully disabled with a log warning
  - Files: horus/pipeline.py, horus/cli.py

P1-3: Add /health Endpoint
  - Returns JSON: {status:"ok",db:true,sources:{nvd:true,github:false,...}}
  - No auth required
  - Files: horus/web/routes/api.py (new /health route)

P1-4: Structured Logging
  - Replace print() calls with Python logging module
  - Add log format config via env (HORUS_LOG_LEVEL, HORUS_LOG_FORMAT)
  - Files: horus/__init__.py, all files using print()

P1-5: Fix EPSS CSV Integrity
  - Add SHA256 checksum verification for EPSS CSV downloads
  - Fail gracefully if checksum unavailable (log warn, not error)
  - Files: horus/enrichers/epss.py

### Priority P2 — Testing & Code Quality

P2-1: Add net/auth.py tests
  - Test token resolution priority (GITHUB_TOKEN > GH_TOKEN > gh auth)
  - Test caching behavior
  - Files: tests/net/test_auth.py

P2-2: Add config/ module tests
  - Test .env parsing: existing env wins, quotes stripped
  - Test source discovery: mock sources dir
  - Files: tests/config/test_env.py, tests/config/test_discovery.py

P2-3: CI Enhancement
  - Add ruff check to CI
  - Add mypy check to CI (core/storage only)
  - Files: .github/workflows/security.yml

P2-4: Request Size Limits
  - Configure MAX_CONTENT_LENGTH (e.g., 1MB)
  - Files: horus/web/__init__.py

---

## PART 4: v0.12 UPGRADE ROADMAP

### Theme: "Modular, Deployable, Configurable"

v0.12 transforms Horus from "developer runs it on their laptop" into
"anyone can deploy on any server with docker and configure data
sources without editing code."

### Phase 1: Docker Compose & Deployment (Week 1-2)

D1.1: docker-compose.yml
  services:
    horus:
      build: .
      ports: ["8080:8080"]
      volumes:
        - horus-state:/app/state
        - horus-reports:/app/reports
      env_file: [".env"]
      restart: unless-stopped
      healthcheck:
        test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
        interval: 30s
        timeout: 5s
        retries: 3

  volumes:
    horus-state:
    horus-reports:

D1.2: .env.sample (comprehensive)
  # === Core ===
  HORUS_SECRET_KEY=*** Leave empty = auto-generate
  HORUS_LOG_LEVEL=INFO

  # === Web ===
  HORUS_WEB_HOST=0.0.0.0
  HORUS_WEB_PORT=8080

  # === Sources (enable what you need) ===
  HORUS_SOURCES_ENABLED=nvd,gitlab,exploitdb
  # Available: nvd, x_twitter, github, gitlab, codeberg, exploitdb, news, resources

  # === GitHub Auth ===
  GITHUB_TOKEN=*** Optional: enables GitHub PoC search

  # === Codeberg Auth ===
  CODEBERG_TOKEN=*** Optional: enables Codeberg PoC search

  # === X/Twitter Auth ===
  # (document the Chrome auth flow or future API token flow)
  X_TOKEN=*** Optional: enables X/Twitter source

  # === Telegram Bot ===
  TELEGRAM_BOT_TOKEN=*** Optional: enables Telegram notifications
  TELEGRAM_BOT_USERNAME=     # Optional

D1.3: Deploy Script (scripts/deploy.sh)
  #!/bin/bash
  # curl ... | bash deployment
  set -e
  cp .env.sample .env
  echo "Edit .env to configure your data sources, then:"
  echo "  docker-compose up -d"
  docker-compose up -d
  docker-compose ps
  curl -s http://localhost:8080/health | python3 -m json.tool

### Phase 2: Source Configuration UI (Week 2-3)

D2.1: Admin Source Panel (/admin/sources)
  - List all available sources with status indicators
  - Toggle each source on/off (stored in DB or env)
  - Input fields for per-source credentials
  - "Test connection" button per source
  - Show last-run time and error messages

D2.2: Source Configuration Model
  - New table: source_config (source_name, enabled, credentials_json, last_success, last_error)
  - Sources read their config from DB at runtime
  - Pipeline respects enabled/disabled state

D2.3: Source Health Monitoring
  - Each source records success/failure in source_config table
  - /health endpoint aggregates source health
  - Admin dashboard shows green/yellow/red per source

### Phase 3: Plugin Extensibility (Week 3-4)

D3.1: Source Registry Class
  - Explicit registration (with metadata: name, type, description, auth_required)
  - Current auto-discovery stays as fallback
  - Type taxonomy: cve_source | poc_source | enricher | news | resource

D3.2: Custom Source Directory
  - HORUS_SOURCES_DIR env var for user-defined source plugins
  - Drop a .py file → discovered and registered
  - Templates directory for users to scaffold new sources

D3.3: Source Documentation
  - Each source file includes docstring with:
    """Source: MyCustomSource
    Type: poc_source
    Auth: MY_API_KEY env var
    Provides: [...]
    Consumes: [...]
    """

### Phase 4: CLI Configuration Tool (Week 4)

D4.1: Interactive Source Setup (horus setup)
  horus setup
  # Interactive prompt:
  # Enable NVD? [Y/n] → Y
  # Enable GitHub PoC search? [y/N] → y
  #   GitHub Token (ghp_xxx): →
  # Enable X/Twitter? [y/N] → n
  # Enable Telegram Bot? [y/N] → y
  #   Bot Token: →
  # ... generates .env file with selected sources enabled

D4.2: Source Verification (horus doctor)
  horus doctor
  # Checks:
  # - DB connection OK
  # - NVD API reachable
  # - GitHub token valid (if configured)
  # - SQLite WAL mode enabled
  # - Disk space > 100MB
  # - ...

### Phase 5: Polish & Release (Week 5)

D5.1: Docker Hub Publishing
  - Build and publish official image: ghcr.io/horus/horus:v0.12.0
  - Multi-arch: amd64 + arm64
  - GitHub Action: auto-publish on GitHub release

D5.2: Documentation
  - README: Quick Start (docker-compose up)
  - docs/deployment.md: Full deployment guide
  - docs/sources.md: Data source configuration
  - docs/custom-sources.md: Adding custom data sources

D5.3: Upgrade Path
  - Migration script: v0.11.x → v0.12 (DB schema compat, no data loss)
  - docker-compose handles everything else

---

## PART 5: RISK ASSESSMENT

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Docker Compose adds complexity | Medium | Low | Keep it simple: 1 service + .env |
| Source config UI adds dev time | High | High | Defer to late v0.12 if needed |
| Breaking existing deployments | Low | High | .env.sample is additive; existing setups keep working |
| Auth flow complexity for X/Chrome | Medium | Medium | Document clearly; add native API token later |
| SQLite concurrency with parallel sources | Medium | Medium | Enable WAL mode + busy_timeout in v0.12 |

---

## SUMMARY: Execution Order

IMMEDIATE (v0.11.2):
  1. P0-1: Tests in CI
  2. P0-2: Docker hardening (non-root, healthcheck, multi-stage)
  3. P0-3: Login rate limiting (Flask-Limiter)
  4. P0-4: Security headers
  5. P1-1: .env.sample
  6. P1-2: Source toggle via env
  7. P1-3: /health endpoint
  8. P1-4: Structured logging
  9. P1-5: EPSS CSV integrity

SHORT-TERM (v0.12 alpha):
  10. docker-compose.yml
  11. Deploy script
  12. horus setup (interactive config)
  13. Source health monitoring
  14. Admin source panel

MEDIUM-TERM (v0.12 beta):
  15. Source registry with metadata
  16. Custom source directory
  17. Docker Hub publishing
  18. Full documentation
