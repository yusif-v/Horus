# Horus Architecture

## Plugin System

Horus uses a plugin-based architecture. **Adding a new source, enricher, or renderer
requires creating ONE file. No existing files are ever modified.**

### Adding a New Source

Create `horus/sources/<name>.py` with:

```python
NAME = "Human Readable Name"
DEFAULT_ENABLED = True

def run(known_cve_ids, known_poc_urls, args, **kwargs) -> dict:
    """Fetch new data. Returns {"cves": [CVE, ...], "pocs": [PoC, ...]}."""
    # ... fetch from your source ...
    return {"cves": [...], "pocs": [...]}
```

That's it. The plugin is auto-discovered. `--no-<name>` flag is auto-generated.

### Adding a New Enricher

Create `horus/enrichers/<name>.py` with:

```python
NAME = "Human Readable Name"
DEFAULT_ENABLED = True

def enrich(cves, pocs, args, **kwargs) -> None:
    """Enrich CVEs/PoCs in-place. No return value."""
    for cve in cves:
        cve.my_new_field = "value"
```

That's it. `--skip-<name>` flag is auto-generated.

### Conventions

| Thing | Interface | Returns |
|-------|-----------|---------|
| Source | `run(known_cve_ids, known_poc_urls, args, **kwargs)` | `{"cves": [CVE], "pocs": [PoC]}` |
| Enricher | `enrich(cves, pocs, args, **kwargs)` | `None` (in-place mutation) |
| PoC builder | `poc_from_<source>(raw: dict)` | `PoC` object |
| CVE builder | `cve_from_<source>(raw: dict)` | `CVE` object |

### CLI Flags (auto-generated)

| Flag | Example | Source |
|------|---------|--------|
| `--no-<source>` | `--no-exploitdb` | Defined in `sources/<name>.py` |
| `--skip-<enricher>` | `--skip-kev` | Defined in `enrichers/<name>.py` |
| `--sources a,b` | `--sources github,nvd` | Select specific sources |
| `--enrichers a,b` | `--enrichers epss` | Select specific enrichers |

### Current Plugins

| Source | Module | What it fetches |
|--------|--------|----------------|
| NVD | `sources/nvd.py` | New CVEs from NVD API |
| GitHub | `sources/github.py` | PoC repos from GitHub search |
| Exploit-DB | `sources/exploitdb.py` | Exploits for known CVEs |
| X/Twitter | `sources/x_twitter.py` | CVE mentions via Nitter RSS |

| Enricher | Module | What it adds |
|----------|--------|-------------|
| CISA KEV | `enrichers/kev.py` | Known-exploited flag |
| EPSS | `enrichers/epss.py` | Exploit probability score |

## Pipeline

```
1. Discover plugins (sources + enrichers)
2. Parse CLI args (--no-X, --skip-Y, --sources, --enrichers)
3. Run each source → collect CVEs + PoCs
4. Merge + deduplicate
5. Run each enricher → mutate CVEs in-place
6. Persist to SQLite
7. Render report + graph
```

## Why This Design

- **Open/closed principle**: extend without modifying
- **Each source is independent**: Exploit-DB doesn't know GitHub exists
- **Easy to test**: run a single source in isolation
- **Easy to disable**: `--no-X` flag auto-generated from module name
- **Merge is generic**: it accepts CVEs/PoCs from any source
