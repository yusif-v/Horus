"""Notification category catalog + helpers.

Defines the canonical list of notification kinds users can subscribe to.
A user's effective preference for a kind is:

    enabled = notification_pref(user_id, kind).enabled
              if a row exists, else DEFAULT_PREFS[kind]

Categories should map 1:1 to events the eventual notification dispatcher
will emit (next session, alongside the bot listener).
"""

from __future__ import annotations

# kind → (label, description, default-enabled)
CATEGORIES: dict[str, tuple[str, str, bool]] = {
    "kev_new": (
        "New KEV addition",
        "CISA added a CVE you can be reached for to the Known Exploited Vulnerabilities catalog.",
        True,
    ),
    "kev_overdue": (
        "KEV overdue",
        "A KEV-listed CVE has passed its federal remediation deadline.",
        True,
    ),
    "kev_due_soon": (
        "KEV due soon",
        "A KEV-listed CVE deadline is within 30 days.",
        True,
    ),
    "epss_jump": (
        "EPSS jumped above 0.5",
        "A CVE's exploit-prediction score crossed 0.5 — imminent exploitation likely.",
        False,
    ),
    "critical_cve": (
        "New CVSS>=9 CVE with PoC",
        "Critical-severity CVE published and a public proof-of-concept already exists.",
        True,
    ),
    "watchlist_match": (
        "Watchlist match",
        "New CVE touches a vendor or product on your team's watchlist.",
        True,
    ),
    "poc_new": (
        "New PoC for tracked CVE",
        "A new public proof-of-concept showed up for a CVE already in the queue.",
        False,
    ),
}

DEFAULT_PREFS: dict[str, bool] = {k: v[2] for k, v in CATEGORIES.items()}


def effective_prefs(stored: dict[str, bool]) -> dict[str, bool]:
    """Merge stored prefs with defaults for any kind the user hasn't set."""
    return {k: stored.get(k, default) for k, default in DEFAULT_PREFS.items()}
