"""X/Twitter search — birdnode-compatible Python implementation.

Uses Chrome cookies (auth_token + ct0) to authenticate with X's internal
GraphQL API, exactly like birdnode does. No API keys, no Nitter, no browser.

How it works:
1. Extract auth_token + ct0 from Chrome's encrypted cookie DB (macOS keychain)
2. Dynamically discover X's current GraphQL query IDs from JS bundles
3. POST to SearchTimeline GraphQL endpoint with proper headers + cookies
4. Parse structured tweet responses

This is a faithful Python port of birdnode's core logic.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── Cookie extraction ───────────────────────────────────────────────────────

_CHROME_BASE = Path.home() / "Library/Application Support/Google/Chrome"
_PROFILES = ["Default", "Profile 1", "Profile 2", "Profile 3"]
_BEARER = (
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs"
    "%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)

# Known SearchTimeline query IDs (updated 2026-04, birdnode source)
_KNOWN_QUERY_IDS = [
    "R0u1RWRf748KzyGBXvOYRA",
    "M1jEez78PEfVfbQLvlWMvQ",
    "6AAys3t42mosm_yTI_QENg",
]

_SEARCH_FEATURES = {
    "rweb_video_screen_enabled": True,
    "profile_label_improvements_pcf_label_in_post_enabled": True,
    "responsive_web_profile_redirect_enabled": True,
    "rweb_tipjar_consumption_enabled": True,
    "verified_phone_label_enabled": False,
    "creator_subscriptions_tweet_preview_api_enabled": True,
    "responsive_web_graphql_timeline_navigation_enabled": True,
    "responsive_web_graphql_exclude_directive_enabled": True,
    "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
    "premium_content_api_read_enabled": False,
    "communities_web_enable_tweet_community_results_fetch": True,
    "c9s_tweet_anatomy_moderator_badge_enabled": True,
    "responsive_web_grok_analyze_button_fetch_trends_enabled": False,
    "responsive_web_grok_analyze_post_followups_enabled": False,
    "responsive_web_grok_annotations_enabled": False,
    "responsive_web_jetfuel_frame": True,
    "post_ctas_fetch_enabled": True,
    "responsive_web_grok_share_attachment_enabled": True,
    "responsive_web_edit_tweet_api_enabled": True,
    "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
    "view_counts_everywhere_api_enabled": True,
    "longform_notetweets_consumption_enabled": True,
    "responsive_web_twitter_article_tweet_consumption_enabled": True,
    "tweet_awards_web_tipping_enabled": False,
    "responsive_web_grok_show_grok_translated_post": False,
    "responsive_web_grok_analysis_button_from_backend": True,
    "creator_subscriptions_quote_tweet_preview_enabled": False,
    "freedom_of_speech_not_reach_fetch_enabled": True,
    "standardized_nudges_misinfo": True,
    "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": True,
    "rweb_video_timestamps_enabled": True,
    "longform_notetweets_rich_text_read_enabled": True,
    "longform_notetweets_inline_media_enabled": True,
    "responsive_web_enhance_cards_enabled": False,
}


class XAuthError(Exception):
    pass


class XSearchError(Exception):
    pass


def _get_encryption_key() -> bytes:
    """Get Chrome's safe storage key from macOS keychain."""
    attempts = [
        ["security", "find-generic-password", "-w", "-s", "Chrome Safe Storage", "-a", "Chrome"],
        ["security", "find-generic-password", "-w", "-s", "Chrome Safe Storage"],
        [
            "security",
            "find-generic-password",
            "-w",
            "-s",
            "Chromium Safe Storage",
            "-a",
            "Chromium",
        ],
    ]
    for cmd in attempts:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                password = result.stdout.strip().encode()
                return hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1003, dklen=16)
        except Exception:
            continue

    raise XAuthError(
        "Cannot read Chrome Safe Storage key from macOS Keychain. "
        "Try running from an interactive terminal, or set X_AUTH_TOKEN and X_CT0 env vars."
    )


def _decrypt_cookie(enc: bytes, key: bytes) -> str:
    """Decrypt Chrome v10/v11 cookie value (AES-128-CBC, IV=spaces).

    Chrome 127+ may prepend a 32-byte SHA256 domain hash before the
    actual cookie value. We detect this and strip it.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as e:
        raise XAuthError("Install cryptography: pip install cryptography") from e

    if enc[:3] not in (b"v10", b"v11"):
        return enc.decode("utf-8", errors="replace")

    iv = b" " * 16
    ct = enc[3:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    raw_bytes = dec.update(ct) + dec.finalize()

    # Strip PKCS7 padding
    pad = raw_bytes[-1]
    if isinstance(pad, int) and pad <= 16:
        raw_bytes = raw_bytes[:-pad]

    # Chrome 127+ may prepend a 32-byte SHA256 domain hash.
    # Detect: first 16 bytes are non-ASCII, bytes 32-40 are ASCII.
    if len(raw_bytes) > 32:

        def is_ascii(b):
            return 0x20 <= b <= 0x7E

        if not all(is_ascii(b) for b in raw_bytes[:16]) and all(
            is_ascii(b) for b in raw_bytes[32:40]
        ):
            raw_bytes = raw_bytes[32:]

    return raw_bytes.decode("utf-8", errors="replace").rstrip("\x00")


def _extract_x_cookies() -> dict:
    """Extract auth_token and ct0 from Chrome's cookie database."""
    key = _get_encryption_key()

    for profile in _PROFILES:
        db_path = _CHROME_BASE / profile / "Cookies"
        if not db_path.exists():
            continue

        # Copy to temp to avoid "database is locked" when Chrome is running
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)  # noqa: SIM115
        try:
            shutil.copy2(db_path, tmp.name)
            conn = sqlite3.connect(tmp.name)
            cursor = conn.execute(
                "SELECT name, encrypted_value FROM cookies "
                "WHERE host_key IN ('.x.com', 'x.com') "
                "AND name IN ('auth_token', 'ct0')"
            )
            cookies = {}
            for name, enc in cursor:
                if enc:
                    try:
                        val = _decrypt_cookie(enc, key)
                        if val:
                            cookies[name] = val
                    except Exception:
                        pass
            conn.close()

            if "auth_token" in cookies and "ct0" in cookies:
                return cookies
        finally:
            os.unlink(tmp.name)

    raise XAuthError(
        "auth_token/ct0 not found. Log into x.com in Chrome first, "
        "or set X_AUTH_TOKEN and X_CT0 environment variables."
    )


def get_x_cookies() -> dict:
    """Get X auth cookies from cache, Chrome, or environment."""
    # Allow env var override
    auth_token = os.environ.get("X_AUTH_TOKEN")
    ct0 = os.environ.get("X_CT0")
    if auth_token and ct0:
        return {"auth_token": auth_token, "ct0": ct0}

    # Check cache file (~/.horus_x_cookies.json)
    cache_path = Path.home() / ".horus_x_cookies.json"
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text())
            if data.get("auth_token") and data.get("ct0"):
                return data
        except Exception:
            pass

    # Extract from Chrome
    cookies = _extract_x_cookies()

    # Cache for future runs
    try:
        cache_path.write_text(json.dumps(cookies))
        os.chmod(cache_path, 0o600)  # user-only read
    except Exception:
        pass

    return cookies


# ── Query ID discovery ──────────────────────────────────────────────────────


def _discover_query_ids(ct0: str, auth_token: str) -> dict:
    """Dynamically discover X's current GraphQL query IDs from JS bundles."""
    cache = {}
    page_headers = {
        "cookie": f"auth_token={auth_token}; ct0={ct0}",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
    }

    try:
        req = urllib.request.Request("https://x.com/home", headers=page_headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")

        # Find JS bundle URLs
        bundle_urls = list(
            dict.fromkeys(
                re.findall(
                    r"https://abs\.twimg\.com/responsive-web/client-web(?:-legacy)?/[\w._-]+\.js",
                    html,
                )
            )
        )

        targets = {"SearchTimeline", "UserByScreenName", "Viewer", "CreateTweet", "TweetDetail"}
        js_headers = {
            "user-agent": "Mozilla/5.0 Chrome/132.0.0.0 Safari/537.36",
            "accept": "*/*",
        }

        for url in bundle_urls:
            if all(t in cache for t in targets):
                break
            try:
                req = urllib.request.Request(url, headers=js_headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    js = resp.read().decode("utf-8", errors="replace")

                # Pattern: queryId:"...",operationName:"..."
                for m in re.finditer(
                    r'queryId\s*:\s*["\']([^"\']+)["\'][^}]{0,200}operationName\s*:\s*["\']([^"\']+)["\']',
                    js,
                ):
                    qid, op = m.group(1), m.group(2)
                    if op in targets and op not in cache:
                        cache[op] = qid

                # Pattern: operationName:"...",queryId:"..."
                for m in re.finditer(
                    r'operationName\s*:\s*["\']([^"\']+)["\'][^}]{0,200}queryId\s*:\s*["\']([^"\']+)["\']',
                    js,
                ):
                    op, qid = m.group(1), m.group(2)
                    if op in targets and op not in cache:
                        cache[op] = qid
            except Exception:
                continue
    except Exception:
        pass

    return cache


# ── Tweet parsing ───────────────────────────────────────────────────────────


def _map_tweet(result: dict) -> dict | None:
    """Parse a tweet result from GraphQL response into a clean dict."""
    if not result:
        return None

    tweet = result.get("tweet") or result
    legacy = tweet.get("legacy")
    if not legacy:
        return None

    user_wrapper = tweet.get("core", {}).get("user_results", {}).get("result")
    if not user_wrapper:
        return None

    user = user_wrapper.get("user") or user_wrapper
    user_legacy = user.get("legacy", {})
    user_core = user.get("core", {})

    screen_name = user_legacy.get("screen_name") or user_core.get("screen_name")
    name = user_legacy.get("name") or user_core.get("name") or screen_name

    if not screen_name:
        return None

    tweet_id = legacy.get("id_str") or tweet.get("rest_id")
    views = tweet.get("views", {})
    views_count = int(views.get("count", 0)) if views.get("count") else 0

    return {
        "id": tweet_id,
        "text": legacy.get("full_text", ""),
        "createdAt": legacy.get("created_at", ""),
        "likes": legacy.get("favorite_count", 0),
        "retweets": legacy.get("retweet_count", 0),
        "replies": legacy.get("reply_count", 0),
        "quotes": legacy.get("quote_count", 0),
        "views": views_count,
        "author": name,
        "screenName": screen_name,
        "userId": user.get("rest_id", ""),
        "description": user_legacy.get("description", ""),
        "followersCount": user_legacy.get("followers_count", 0),
        "url": f"https://x.com/{screen_name}/status/{tweet_id}",
        "inReplyToId": legacy.get("in_reply_to_status_id_str"),
        "inReplyToScreenName": legacy.get("in_reply_to_screen_name"),
    }


def _parse_search_response(data: dict) -> tuple[list[dict], str | None]:
    """Parse SearchTimeline GraphQL response. Returns (tweets, next_cursor)."""
    instructions = (
        data.get("data", {})
        .get("search_by_raw_query", {})
        .get("search_timeline", {})
        .get("timeline", {})
        .get("instructions", [])
    )

    tweets = []
    next_cursor = None

    for instruction in instructions:
        if instruction.get("type") == "TimelineAddEntries" or "entries" in instruction:
            for entry in instruction.get("entries", []):
                tweet_result = (
                    entry.get("content", {})
                    .get("itemContent", {})
                    .get("tweet_results", {})
                    .get("result")
                )
                if tweet_result:
                    mapped = _map_tweet(tweet_result)
                    if mapped:
                        tweets.append(mapped)

                # Look for cursor
                content = entry.get("content", {})
                if (
                    content.get("entryType") == "TimelineTimelineCursor"
                    and content.get("cursorType") == "Bottom"
                ):
                    next_cursor = content.get("value")
                elif entry.get("entryId", "").startswith("cursor-bottom-"):
                    next_cursor = content.get("value") or content.get("itemContent", {}).get(
                        "value"
                    )

        if instruction.get("type") == "TimelineReplaceEntry":
            entry = instruction.get("entry", {})
            content = entry.get("content", {})
            if (
                content.get("entryType") == "TimelineTimelineCursor"
                and content.get("cursorType") == "Bottom"
            ):
                next_cursor = content.get("value")

    return tweets, next_cursor


# ── Main search class ──────────────────────────────────────────────────────


class XSearch:
    """X/Twitter search using Chrome cookie authentication.

    Drop-in replacement for birdnode's search functionality.
    Uses the same GraphQL API with dynamically discovered query IDs.

    Usage:
        xs = XSearch()
        tweets = xs.search("CVE-2026", max_results=20)
    """

    def __init__(self):
        self._cookies = get_x_cookies()
        self._auth_token = self._cookies["auth_token"]
        self._ct0 = self._cookies["ct0"]
        self._query_ids = list(_KNOWN_QUERY_IDS)
        self._dynamic_discovered = False

    def _build_headers(self) -> dict:
        return {
            "authorization": f"Bearer {_BEARER}",
            "x-csrf-token": self._ct0,
            "content-type": "application/json",
            "x-twitter-auth-type": "OAuth2Session",
            "x-twitter-active-user": "yes",
            "cookie": f"auth_token={self._auth_token}; ct0={self._ct0}",
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "accept-language": "en-US,en;q=0.9",
            "referer": "https://x.com/",
            "origin": "https://x.com",
        }

    def _perform_search(
        self, query: str, query_id: str, cursor: str | None, product: str
    ) -> tuple[list[dict], str | None]:
        """Execute a single SearchTimeline GraphQL request."""
        variables = {
            "rawQuery": query,
            "count": 20,
            "querySource": "typed_query",
            "product": product,
        }
        if cursor:
            variables["cursor"] = cursor

        body = json.dumps(
            {
                "variables": variables,
                "features": _SEARCH_FEATURES,
                "queryId": query_id,
            }
        ).encode()

        url = f"https://x.com/i/api/graphql/{query_id}/SearchTimeline"
        req = urllib.request.Request(url, data=body, headers=self._build_headers(), method="POST")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body_text = ""
            with contextlib.suppress(Exception):
                body_text = e.read()[:200].decode("utf-8", errors="replace")
            raise XSearchError(f"HTTP {e.code}: {body_text}") from e

        if data.get("errors"):
            raise XSearchError(data["errors"][0].get("message", "Unknown GraphQL error"))

        return _parse_search_response(data)

    def search(self, query: str, max_results: int = 20, product: str = "Latest") -> list[dict]:
        """Search X for tweets matching a query.

        Args:
            query: Search query string
            max_results: Maximum number of tweets to return
            product: "Latest" or "Top"

        Returns:
            List of tweet dicts with keys:
                id, text, createdAt, likes, retweets, replies, quotes,
                views, author, screenName, userId, description,
                followersCount, url, inReplyToId, inReplyToScreenName
        """
        all_tweets = []
        cursor = None
        page = 0
        max_pages = 10

        while len(all_tweets) < max_results and page < max_pages:
            page += 1
            result = None
            last_error = None

            # Try each query ID
            for query_id in self._query_ids:
                try:
                    result = self._perform_search(query, query_id, cursor, product)
                    break
                except XSearchError as e:
                    last_error = e
                    err_msg = str(e)
                    if "400" in err_msg or "404" in err_msg:
                        continue  # Try next query ID
                    raise

            # If all known IDs failed, try dynamic discovery
            if result is None and not self._dynamic_discovered:
                print(
                    "  [INFO] Known query IDs failed, discovering from JS bundles...",
                    file=sys.stderr,
                )
                discovered = _discover_query_ids(self._ct0, self._auth_token)
                self._dynamic_discovered = True
                if "SearchTimeline" in discovered:
                    new_id = discovered["SearchTimeline"]
                    if new_id not in self._query_ids:
                        self._query_ids.insert(0, new_id)
                        try:
                            result = self._perform_search(query, new_id, cursor, product)
                        except XSearchError as e:
                            last_error = e

            if result is None:
                if last_error:
                    print(f"  [WARN] Search failed: {last_error}", file=sys.stderr)
                break

            tweets, next_cursor = result
            if not tweets:
                break

            # Deduplicate
            existing_ids = {t["id"] for t in all_tweets}
            new_tweets = [t for t in tweets if t["id"] not in existing_ids]
            if not new_tweets and page > 1:
                break

            all_tweets.extend(new_tweets)

            if not next_cursor:
                break
            cursor = next_cursor

            # Rate-limit friendly delay
            time.sleep(0.6)

        return all_tweets[:max_results]

    def check(self) -> dict:
        """Verify credentials are valid."""
        try:
            self.search("test", max_results=1)
            return {
                "status": "ok",
                "auth_token": f"...{self._auth_token[-8:]}",
                "ct0": f"...{self._ct0[-8:]}",
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
