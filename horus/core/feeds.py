"""Security-news RSS feed registry shared by the news plugin and the web layer.

Kept in `horus.core` (not under `horus.plugins`) so that `core/news_linker.py`
and `web/routes/news.py` do not depend on a specific plugin package.

Feed keys are the `source` values stored on `news_article` rows. The
second tuple element is the default tier (lower = more important).
"""

FEEDS: dict[str, tuple[str, int]] = {
    "cisa": (
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        4,
    ),
    "hacker_news": (
        "https://feeds.feedburner.com/TheHackersNews",
        3,
    ),
    "bleepingcomputer": (
        "https://www.bleepingcomputer.com/feed/",
        3,
    ),
    "packet_storm": (
        "https://packetstormsecurity.com/feed.xml",
        2,
    ),
    "exploit_db": (
        "https://www.exploit-db.com/rss.xml",
        2,
    ),
    "nvd": (
        "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
        1,
    ),
}
