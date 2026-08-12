# Horus Plugin System — Design Spec

*Date: 2026-08-12*
*Branch: `refactor/plugin-system`*
*Status: approved design, pending implementation plan*

## Goal

Remove all "built-in" hardcoding of GitHub / X(Twitter) / GitLab / Codeberg /
Telegram (and the other sources/enrichers) so that every plugin — bundled or
user-authored — loads through **one** discovery mechanism defined by a single
scheme. Users can add, enable/disable, configure, and author new plugins from a
`horus plugin` CLI without touching Horus source.

## Decisions locked (from clarifying questions)

1. **Unified scope**: one scheme covers SOURCES + ENRICHERS + NOTIFICATIONS.
2. **Packaging**: each plugin is a *folder* containing a `plugin.toml` manifest
   + implementation module(s). Bundled under `horus/plugins/<type>/`, user
   plugins under external dir(s).
3. **Full refactor**: existing built-ins become real folder+manifest plugins so
   bundled == user plugins (dogfooding). No second code path.

---

## Section 1 — Plugin scheme (the contract)

### Directory layout
```
horus/plugins/
  sources/<name>/plugin.toml      # bundled
  enrichers/<name>/plugin.toml
  notifications/<name>/plugin.toml
```
User plugins live in any directory listed in `plugin_dirs` (config), default
`~/.config/horus/plugins`, overridable via `--plugins-dir` flag or
`HORUS_PLUGINS_DIR` env. Same folder layout inside.

### `plugin.toml` schema
```toml
[plugin]
name = "github"            # unique key used in config toggles
type = "source"           # source | enricher | notification
version = "1.0.0"
entrypoint = "main"       # module file (main.py) OR dotted path
enabled_by_default = true
# optional:
requires = ["net.http"]   # hints only, for docs

[schedule]
interval_seconds = 3600   # server poll cadence (sources)

[config]                  # user-tunable schema; surfaced by `horus plugin config`
max_results = { type = "int", default = 100, help = "Max repos per run" }
api_token_env = { type = "str", default = "GITHUB_TOKEN", help = "Env var holding token" }
```

### Interface contracts
- **source**: `main.run(ctx: SourceContext) -> dict`
  (unchanged from current `horus/sources/*.run`). Returns
  `{"cves": [...], "pocs": [...], optional "social_signals", optional "x_discovered_urls"}`.
- **enricher**: `main.enrich(ctx: EnricherContext) -> None`
  (unchanged). Mutates `ctx.cves` / `ctx.pocs` in place.
- **notification** (NEW contract):
  `main.notify(events: dict[str, list[dict]], ctx: NotificationContext) -> None`.
  `NotificationContext` (defined in `horus/core/notify_context.py`) carries
  `token`, `users`, `prefs`, and a `send(channel, message)` helper so a plugin
  does not hardcode Telegram. See Section 3.

Bundled and user plugins load **identically** through one `PluginManager`.

---

## Section 2 — PluginManager, config, and the `horus plugin` CLI

### `horus/plugin_manager.py` (new — single loader for all three kinds)
- Discovers from bundled `horus/plugins/<type>/` and each external dir in
  `plugin_dirs`.
- Reads each `plugin.toml` via `tomllib` (3.11+) with `tomli` fallback (3.10).
  Add `tomli` to `pyproject.toml` deps for the 3.10 floor.
- Validates: `type` matches parent dir; `entrypoint` module exists; module
  exports `run` (source) / `enrich` (enricher) / `notify` (notification).
- Merges enable state + per-plugin `config` from `horus.yaml`'s `plugins:` block
  over `enabled_by_default` / manifest `config` defaults.
- Exposes:
  - `manager.sources()` / `manager.enrichers()` / `manager.notifications()`
    → only **enabled** plugins, each wrapped as a `Plugin` whose `.run` / `.enrich`
    / `.notify` is bound to `(config, ctx)`.
  - `manager.due_sources(now)` → names whose interval has elapsed (manifest
    `schedule.interval_seconds` + config override).
  - `manager.broken` → list of `(name, error)` for plugins that failed to load
    (never aborts a run).
  - `manager.get(name)` → `Plugin | None` for CLI operations.

### `horus.yaml` changes
Old `sources_enabled:` / `poll_intervals:` replaced by:
```yaml
plugin_dirs:
  - ~/.config/horus/plugins
web:
  enabled: true
  host: 127.0.0.1
  port: 8080
  workers: 2
  allow_dev_fallback: true
plugins:
  github:
    enabled: true
    interval_seconds: 3600      # optional override of manifest schedule
    config:
      max_results: 200
  telegram:
    enabled: true
    config: {}
```
**Backward-compat shim**: if legacy `sources_enabled` / `poll_intervals` keys
exist, the manager reads them and emits a one-time `DeprecationWarning`. Removed
after the next minor release.

### `horus plugin` CLI (new subcommand in `cli.py`)
- `horus plugin list` — all discovered (bundled + external): type/version/enabled/path.
- `horus plugin enable|disable <name>` — flip state in `horus.yaml`'s `plugins:` block.
- `horus plugin config <name>` (show) / `horus plugin config <name> <key> <value>` (set)
  — read/write per-plugin `config`.
- `horus plugin add <path>` — install a plugin folder into an external `plugin_dirs` entry.
- `horus plugin remove <name>` — remove only from external dirs (never bundled).
- `horus plugin scaffold <type> <name>` — generate a starter folder (manifest +
  `main.py` stub implementing the correct interface). This is the
  "create new ones based on the schemes" deliverable.
- `horus plugin validate <name|path>` — manifest + entrypoint + export checks.

---

## Section 3 — Refactor of existing built-ins (dogfooding the scheme)

### Move to `horus/plugins/.../` (get `plugin.toml` + `main.py`)
- **Sources** → `horus/plugins/sources/<name>/`:
  `nvd`, `x_twitter`, `github`, `gitlab`, `codeberg`, `exploitdb`, `news`.
  Each `plugin.toml` declares `type="source"`, `entrypoint="main"`, and a
  `schedule.interval_seconds` copied from current `horus.yaml` defaults.
  The current `*_source.py`'s `run(ctx)` moves into `main.py` (thin re-export or
  direct move — signature unchanged).
- **Enrichers** → `horus/plugins/enrichers/<name>/`:
  `kev`, `epss`, `otx`, `darkweb`. Manifest `type="enricher"`, `entrypoint="main"`.
- **Notification** → `horus/plugins/notifications/telegram/` with
  `plugin.toml type="notification"` and `main.notify(events, ctx)`. Existing
  `dispatcher.py` logic becomes the telegram plugin body; the server's
  `register_notification_hook` calls `manager.notifications()` instead of
  importing `TelegramAPI` directly.

### Stays as a module (imported by pipeline/cli directly — NOT a plugin)
Verified at implementation time by tracing imports; only modules with no
`run`/`enrich` export AND imported by name elsewhere stay:
- `nvd_fetch.py` (used by `pipeline.py` phase 1c to fetch referenced CVEs)
- `news_linker.py` (`link_cves_to_news`, called in pipeline phase 6)
- `url_resolve.py`, `resource_intelligence.py`, `news.py` if they are helpers
- Old `horus/sources/` and `horus/enrichers/` packages removed once migrated
  (empty `__init__.py` deleted).

### NotificationContext (new, `horus/core/notify_context.py`)
```python
@dataclass
class NotificationContext:
    token: str | None
    users: list[UserRow]                 # id, username, chat_id
    prefs: dict[str, dict[str, bool]]
    send: Callable[[str, str], None]     # (channel/chat_id, message) -> None
```
The telegram plugin uses `ctx.send(chat_id, msg)` and reads `ctx.users` /
`ctx.prefs` instead of hitting the DB directly. Generalizes to Slack/email later.

### Config migration
`horus.yaml.example` rewritten to unified `plugin_dirs:` + `plugins:` form;
the legacy `telegram:` block folds into `plugins.telegram.config`.

---

## Section 4 — Discovery flow, error handling, testing

### Discovery order & precedence (`PluginManager`)
1. Scan bundled `horus/plugins/<type>/` then each external `plugin_dirs` entry.
2. **Name collision** (same `name` in bundled + external): external wins
   (override a bundled plugin), logged as `INFO`.
3. Each plugin validated independently; a broken plugin (bad manifest, missing
   export, import error) recorded in `manager.broken` with its error and
   **skipped** — never aborts the whole run. Reuses
   `test_discover_handles_import_errors` behavior.

### Server integration
- `server.py._register_notification_hook` iterates `manager.notifications()` and
  calls each `plugin.notify(events, ctx)`.
- Scheduler's `due_sources(now)` comes from `manager.due_sources(now)`
  (manifest `schedule.interval_seconds` + config override), replacing the
  hardcoded `poll_intervals` dict.
- `horus.yaml` legacy `sources_enabled` / `poll_intervals` parsed by a shim with
  a one-time `DeprecationWarning`.

### CLI integration
- `cli.main` builds a `PluginManager` from resolved config and passes
  `manager.sources()` / `enrichers()` into
  `run_pipeline(opts, sources=..., enrichers=...)`. `run_pipeline` already
  accepts these args; only its internal `discover_sources()` call path changes
  to "accept what's passed; if None, build from the manager".
- `horus plugin <subcommand>` routes to `plugin_manager` CLI helpers.

### Testing (preserve 80%+ coverage gate, all under `tests/`)
- `tests/config/test_discovery.py` → extended for `PluginManager`: bundled +
  external discovery, TOML parse, collision precedence, broken-plugin skip,
  enable/disable filtering.
- `tests/plugin_manager/test_load.py`: manifest schema validation, entrypoint
  resolution, `schedule.interval_seconds`.
- `tests/plugin_manager/test_cli.py`: `horus plugin list/enable/disable/config/
  scaffold/validate` against a temp `--plugins-dir` + temp `horus.yaml`.
- `tests/plugin_manager/test_scaffold.py`: `scaffold <type> <name>` produces a
  valid plugin that `validate` then passes.
- `tests/plugin_manager/test_notification_ctx.py`: a fake notification plugin
  receives `events` + `NotificationContext`; `ctx.send` invoked correctly.
- Migration regression: `tests/test_pipeline.py` updated so pipeline still finds
  github/telegram etc. via the manager; `test_discover_*` tests kept green.

### Docs
- `docs/architecture.md` plugin section rewritten.
- New `docs/plugins.md` (scheme reference + authoring a plugin from scaffold).
- `horus.yaml.example` unified.

---

## Out of scope (YAGNI)
- Pip-installable plugin packages (entry-point style) — folder+manifest only.
- Plugin sandboxing / isolation (plugins run in-process).
- A web UI for plugin management (CLI only for v1; web UI can follow later).
- Auto-update of bundled plugins.

## Risks
- **Import tracing**: some `horus/sources/*.py` are internal helpers, not
  `run`-exporting sources. Verify each by import graph at implementation time
  (Section 3) before deleting `horus/sources/`.
- **Config field renames**: `telegram.bot_token` → `plugins.telegram.config`
  path. The shim covers the transition; document in changelog.
- **Coverage gate**: migration is broad; keep `pytest` green and
  `--cov-fail-under=70` satisfied throughout.
