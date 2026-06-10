"""Plugin invocation contracts.

`SourceContext` and `EnricherContext` are the explicit, typed inputs
that the pipeline hands to every plugin. They replace the old pattern
of "pass the argparse Namespace and let each plugin reach into it"
which forced plugins to know about CLI flag names and forced the
server to forge a fake Namespace.

A source receives the context, returns a `dict` with the standard keys
(`cves`, `pocs`, optional `social_signals`, optional
`x_discovered_urls`). An enricher receives the context and mutates the
CVE/PoC lists in-place.

If a future source needs a tunable, add a typed field here — never
read attributes off `ctx.cli_args`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import CVE, PoC


@dataclass
class SourceContext:
    """Inputs to a `sources/*.run(ctx)` call.

    Fields are intentionally small and typed. Every source receives the
    same context object — sources that don't care about a field simply
    ignore it (e.g. exploit-db ignores `last_run`, github ignores
    `min_cvss`).
    """

    # Dedup state, mutated by the pipeline as it discovers new items.
    known_cve_ids: set[str] = field(default_factory=set)
    known_poc_urls: set[str] = field(default_factory=set)

    # Common tunables (CLI maps `--max-results`, `--min-cvss` here;
    # server maps from its YAML config).
    max_results: int | None = None
    min_cvss: float | None = None

    # Generic "when was the previous successful run of this source?"
    # ISO-8601 string in the storage layer's format, or None if never.
    # NVD uses it for adaptive lookback; other sources ignore it.
    last_run: str | None = None

    # Generic inter-source handoff: keys produced earlier in this cycle
    # by sources that declared `PROVIDES = [...]`. A consumer source
    # declares `CONSUMES = ["x_discovered_urls"]` and reads
    # `ctx.provided["x_discovered_urls"]`. No magic-string branching in
    # the pipeline.
    provided: dict[str, list[str]] = field(default_factory=dict)

    @property
    def x_discovered_urls(self) -> list[str]:
        """Back-compat shortcut for github source."""
        return self.provided.get("x_discovered_urls", [])


@dataclass
class EnricherContext:
    """Inputs to an `enrichers/*.enrich(ctx)` call.

    Enrichers mutate `cves` / `pocs` in place; the pipeline persists
    the result. There's currently no enricher-specific tunable, but
    when one appears (e.g. an EPSS cutoff), add it here rather than
    making the pipeline pass a CLI namespace through.
    """

    cves: list[CVE]
    pocs: list[PoC]
