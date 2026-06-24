"""Core domain model: CVE, PoC, AffectedProduct, Resource."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class AffectedProduct:
    vendor: str
    product: str
    versions: list[str] = field(default_factory=list)
    category: str = "unknown"


@dataclass
class PoC:
    url: str
    source: str  # "github" | "gitlab" | "exploit-db" | "twitter" | "pastebin" | "web"
    stars: int | None = None
    age_days: int | None = None  # Computed dynamically from repo_created_at at query time
    description: str | None = None
    cve_refs: list[str] = field(default_factory=list)
    repo_created_at: str | None = None  # ISO 8601 timestamp from source (e.g. GitHub created_at)
    exploit_type: str | None = None  # RCE, LPE, Inject, DoS, Bypass, PoC, Exploit


@dataclass
class CVE:
    id: str
    description: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    published_at: datetime | None = None
    attack_tags: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    affected: list[AffectedProduct] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    epss_score: float | None = None  # EPSS probability (0-1)
    kev: int = 0  # CISA Known Exploited (0/1)
    social_mentions: int = 0  # how many X posts mention this CVE
    poc_source_count: int = 0  # how many distinct signal sources have PoCs
    reputation_score: float = 0.0  # computed composite (0-10)
    confidence: str = "high"  # high=NVD, medium=NVD+signal, low=signal-only
    imminence_score: float = 0.0  # heuristic exploitability imminence (0-10)
    imminence_bucket: str = "unlikely"  # imminent | weeks | months | unlikely
    first_seen: datetime = field(default_factory=_utc_now)
    last_seen: datetime = field(default_factory=_utc_now)


@dataclass
class Resource:
    """A security intelligence resource discovered from social media or other sources.

    Broader than PoC — can be: exploit, tool, technique, advisory, bypass, disclosure, poc.
    """

    url: str
    resource_type: str  # poc / exploit / tool / technique / advisory / bypass / disclosure
    source: str  # x_twitter / github / gitlab / pastebin / web
    title: str | None = None
    description: str | None = None
    source_url: str | None = None  # original tweet/post URL
    source_author: str | None = None  # tweet author screen name
    engagement_score: int = 0  # likes + retweets*3 + replies
    tags: list[str] = field(default_factory=list)
    cve_refs: list[str] = field(default_factory=list)
    stars: int | None = None  # GitHub stars if applicable
    repo_created_at: str | None = None  # ISO 8601
    tweet_created_at: str | None = None  # ISO 8601 — when the original tweet/post was published
    first_seen: str | None = None
    last_seen: str | None = None
