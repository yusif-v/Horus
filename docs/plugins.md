# Horus Plugins (v0.16)

Sources, enrichers, and notifications are all *plugins*: a folder with a
`plugin.toml` manifest and a `main.py` entrypoint. A single
`PluginManager` (`horus/plugin_manager.py`) loads every kind identically,
so authoring a source and authoring a notification are the same job with a
different entrypoint function.

- **Source** — discovers CVEs / PoCs. `main.run(ctx) -> dict`.
- **Enricher** — post-merge enrichment (EPSS, KEV, …). `main.enrich(ctx)`.
- **Notification** — end-of-run dispatch (Telegram, …). `main.notify(events, ctx)`.

A broken plugin — bad manifest, missing entrypoint, import error — is
recorded and skipped. It never aborts a run.

## Directory layout

Bundled plugins ship in the repo. External (user) plugins live under a
configurable root, `~/.config/horus/plugins` by default. Both layouts are
identical and load identically:

```
<plugins_root>/
├── sources/                  kind = "source"
│   └── <name>/
│       ├── plugin.toml
│       └── main.py
├── enrichers/                kind = "enricher"
│   └── <name>/
│       ├── plugin.toml
│       └── main.py
└── notifications/            kind = "notification"
    └── <name>/
        ├── plugin.toml
        └── main.py
```

- **Bundled:** `horus/plugins/<kind>/<name>/` — e.g. `horus/plugins/sources/nvd/`,
  `horus/plugins/enrichers/epss/`, `horus/plugins/notifications/telegram/`.
- **External:** `<plugin_dirs>/<kind>/<name>/` — the first entry of
  `plugin_dirs` in `horus.yaml` (default `~/.config/horus/plugins`), or the
  `--plugins-dir` flag.

The plugin `name` is the unique key used everywhere else: `plugins:` toggles
in horus.yaml and `horus plugin` commands. (The auto-generated
`--no-<name>` / `--skip-<name>` CLI flags exist for bundled plugins only.)
Keep it short, snake_case, and unique across all kinds.

## plugin.toml

```toml
[plugin]
name = "github"           # unique key used in config toggles
type = "source"           # source | enricher | notification
version = "1.0.0"
entrypoint = "main"       # module file (main.py)
enabled_by_default = true

[schedule]
interval_seconds = 3600   # server poll cadence

[config]                  # user-tunable schema (declarative)
max_results = { type = "int", default = 100 }
```

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `[plugin] name` | string | yes | Unique plugin key (config toggles, CLI). |
| `[plugin] type` | string | yes | `source`, `enricher`, or `notification`. Must match the kind directory. |
| `[plugin] version` | string | no | Semantic version, shown by `list`. Default `0.0.0`. |
| `[plugin] entrypoint` | string | no | Module file to load (no `.py`). Default `main`. |
| `[plugin] enabled_by_default` | bool | no | Whether the plugin runs unless overridden in `plugins:`. Default `true`. |
| `[schedule] interval_seconds` | int | no | Poll cadence used by the server scheduler. Default `3600`. |
| `[config]` | table | no | Declarative schema of user-tunable options, `key = { type, default }`. Runtime values are set per-plugin under `plugins:` in horus.yaml (via `horus plugin config <name> <key> <value>`). |

## Interface contracts

Every plugin's `main.py` exports exactly one contract function. Optional
module-level attributes (`NAME`, `KIND`, `DEFAULT_ENABLED`) are still read
for display / back-compat but are not required.

### Source — `main.run(ctx) -> dict`

`ctx` is a `SourceContext` (`horus/core/context.py`): `known_cve_ids`,
`known_poc_urls`, `max_results`, `min_cvss`, `last_run` (ISO-8601 or
`None`), and `provided` (inter-source handoff). Return:

```python
def run(ctx) -> dict:
    """Return {"cves": [...], "pocs": [...]}."""
    return {
        "cves": [],                    # required
        "pocs": [],                    # required
        # "social_signals": [...],     # optional
        # "x_discovered_urls": [...],  # optional
    }
```

`cves` and `pocs` are lists of dicts; the pipeline normalizes them into
`CVE` / `PoC` records. A PoC dict looks like:

```python
{
    "source": "github",           # plugin name (lowercase)
    "repo": "owner/repo",
    "url": "https://github.com/owner/repo",
    "description": "…",           # ≤300 chars
    "stars": 42,                  # int or None
    "repo_created_at": "…",       # ISO date, optional
}
```

### Enricher — `main.enrich(ctx) -> None`

`ctx` is an `EnricherContext` (`cves`, `pocs`). Mutate the lists **in
place**; the pipeline persists the result.

```python
def enrich(ctx) -> None:
    for cve in ctx.cves:
        cve.epss_score = _lookup(cve.id)   # mutates in place
```

### Notification — `main.notify(events, ctx)`

`events` is `dict[str, list[dict]]` keyed by notification category
(`critical_cve`, `kev_new`, `epss_jump`, `poc_new`, `watchlist_match`, …).
`ctx` is a `NotificationContext` carrying `token`, `users`, `prefs`, and a
`send(channel, message)` helper — call `send` instead of talking to a
transport directly.

```python
def notify(events, ctx):
    if not ctx.token:
        return
    for user_row in ctx.users:
        _uid, username, chat_id = user_row[0], user_row[1], user_row[2]
        for kind, items in events.items():
            if not items or not ctx.prefs.get(kind, False):
                continue
            for item in items:
                ctx.send(chat_id, f"{kind}: {item}")
```

## `horus plugin` CLI

The plugin manager is a subcommand — `horus plugin <action> [args]`, with
`--config` / `--plugins-dir` accepted before or after the action:

```
horus plugin <action> [name] [key [value]] [--config <horus.yaml>] [--plugins-dir <dir>]
```

| Action | Description | Example |
|--------|-------------|---------|
| `list` | All plugins by kind + version/display name + enabled state + path; `[broken]` entries too. | `horus plugin list` |
| `enable <name>` | Set `enabled: true` in the config `plugins:` block. | `horus plugin enable telegram --config horus.yaml` |
| `disable <name>` | Set `enabled: false`. | `horus plugin disable github --config horus.yaml` |
| `config <name>` | Show the plugin's `plugins.<name>.config` block from horus.yaml. | `horus plugin config nvd --config horus.yaml` |
| `config <name> <key> <value>` | Set a plugin config key under `plugins.<name>.config`. | `horus plugin config nvd max_results 50 --config horus.yaml` |
| `add <path>` | Copy a plugin folder into the external plugins dir (kind subdir inferred from its `plugin.toml`). | `horus plugin add ~/src/myext` |
| `remove <name>` | Delete an **external** plugin folder. Bundled plugins are never removed. | `horus plugin remove myext` |
| `scaffold <type> <name>` | Create `plugin.toml` + `main.py` stubs under the external dir. | `horus plugin scaffold source mysrc` |
| `validate <name|path>` | Check manifest + entrypoint import + required export. Prints `OK` or `INVALID:` with reasons. | `horus plugin validate mysrc` |

Notes:

- `enable`/`disable`/`config` write to the config file given by `--config`
  (YAML or JSON). Without it they warn and make no persistent change.
- `--plugins-dir` overrides the external plugin root (default
  `~/.config/horus/plugins`) for discovery and for `scaffold`/`add`/`remove`.
- `validate` accepts a plugin name (searched external first, then bundled)
  or a path to a plugin folder.
- `list` always reflects the full `PluginManager` view, including
  `[broken]` plugins that failed to load.

## Authoring a new source

Add a source to the **external** plugins dir so it doesn't touch the repo.

**1. Scaffold**

```bash
horus plugin scaffold source mysrc
# scaffolded source plugin -> ~/.config/horus/plugins/sources/mysrc
```

This writes `plugin.toml` (name `mysrc`, type `source`, version `0.1.0`,
`interval_seconds = 3600`) and a `main.py` stub:

```python
NAME = "mysrc"
KIND = "poc"
DEFAULT_ENABLED = True

def run(ctx):
    """Return {"cves": [], "pocs": []}."""
    return {'cves': [], 'pocs': []}
```

**2. Implement `run(ctx)`**

```python
import json
import urllib.request

NAME = "My PoC Source"
KIND = "poc"
DEFAULT_ENABLED = True

def run(ctx):
    """Return {"cves": [...], "pocs": [...]}."""
    url = "https://example.com/api/pocs"
    req = urllib.request.Request(url, headers={"User-Agent": "Horus"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        items = json.load(resp)

    pocs = [
        {
            "source": "mysrc",
            "repo": item["repo"],
            "url": item["url"],
            "description": item["description"][:300],
            "stars": item.get("stars"),
            "repo_created_at": item.get("created_at"),
        }
        for item in items
    ]
    return {"cves": [], "pocs": pocs}
```

**3. Validate**

```bash
horus plugin validate mysrc   # -> OK
```

**4. Enable it** — either in `horus.yaml`:

```yaml
plugins:
  mysrc:
    enabled: true
    interval_seconds: 3600
```

or via the CLI (same thing):

```bash
horus plugin enable mysrc --config horus.yaml
```

That's it. The next `horus --server` cycle polls `mysrc` on its interval and
the pipeline treats it like any bundled source. Remove it anytime with
`horus plugin remove mysrc`.

## Config reference

`horus.yaml` (mirror `horus.yaml.example`) uses the unified form:

```yaml
# External plugin folders (<kind>/<name>/ with plugin.toml + main.py).
plugin_dirs:
  - ~/.config/horus/plugins

# Per-plugin overrides keyed by plugin name (bundled AND external).
plugins:
  nvd:
    interval_seconds: 3600
  mysrc:
    enabled: true
    config:
      max_results: 100
```

Legacy `sources_enabled`, `poll_intervals`, and `telegram` keys are still
honored but deprecated (`DeprecationWarning`); they're folded into the
`plugins:` form and removed in the next minor version.
