"""Core domain model: CVE, PoC, AffectedProduct.

CVE and PoC are top-level entities. A PoC may reference zero or more CVEs
via `cve_refs`. The actual link (PoC ↔ CVE) is materialized at the merge
or persistence layer, not nested in either dataclass.
"""


from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AffectedProduct:
    vendor: str
    product: str
    versions: list[str] = field(default_factory=list)
    category: str = 'unknown'


@dataclass
class PoC:
    url: str
    source: str                  # "github" | "gitlab" | "exploit-db" | "twitter"
    stars: int | None = None
    age_days: int | None = None
    description: str | None = None
    cve_refs: list[str] = field(default_factory=list)


@dataclass
class CVE:
    id: str
    description: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    published_at: datetime | None = None
    attack_tags: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    affected: list[AffectedProduct] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    epss_score: float | None = None          # EPSS probability (0-1)
    kev: int = 0                             # CISA Known Exploited (0/1)
    exploitability_score: float | None = None  # computed composite
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
