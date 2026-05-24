"""X/Twitter PoC source via birdnode CLI."""

import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from ..core.filters import extract_cves


def fetch_twitter_pocs(
    known_poc_urls: set[str],
    max_results: int | None = None,
) -> list[dict]:
    """Search X/Twitter for CVE mentions via birdnode CLI.

    Each tweet mentioning a CVE is treated as a PoC reference.
    Mutates `known_poc_urls` to include every tweet URL we report this run.

    Returns list of PoC-style dicts with keys: url, source, description,
    cves, stars, age_days.
    """
    results: list[dict] = []
    seen_urls: set[str] = set()
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=48)

    birdnode_path = shutil.which('birdnode')
    if birdnode_path is None:
        print('  [WARN] birdnode not found in PATH — skipping Twitter source',
              file=sys.stderr)
        return []

    queries = ['CVE-2026', 'CVE-2025', 'CVE PoC']
    for query in queries:
        cmd = [birdnode_path, 'search', query, '-n', '20', '--json']
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            print(f'  [WARN] birdnode failed for "{query}": {e}', file=sys.stderr)
            continue

        if proc.returncode != 0:
            print(
                f'  [WARN] birdnode non-zero ({proc.returncode}) for '
                f'"{query}": {proc.stderr.strip()[:200]}',
                file=sys.stderr,
            )
            continue

        # Skip non-JSON lines before the '[' bracket.
        stdout = proc.stdout
        bracket_idx = stdout.find('[')
        if bracket_idx == -1:
            continue
        json_str = stdout[bracket_idx:]

        try:
            tweets = json.loads(json_str)
        except json.JSONDecodeError:
            continue

        if not isinstance(tweets, list):
            tweets = [tweets] if isinstance(tweets, dict) else []

        for tweet in tweets:
            raw_id = tweet.get('id')
            if raw_id is None:
                continue
            tweet_id = str(raw_id)
            text = tweet.get('text', '') or ''
            tweet_url = tweet.get('url', '')
            if not tweet_url:
                author_name = tweet.get('screenName') or tweet.get('author') or ''
                tweet_url = f'https://x.com/{author_name}/status/{tweet_id}' if author_name else ''

            if tweet_url in seen_urls or tweet_url in known_poc_urls:
                continue

            # Filter to last 48h.
            created_at_raw = tweet.get('createdAt')
            published_at = _parse_twitter_date(created_at_raw) if created_at_raw else None
            if published_at is not None:
                if published_at.tzinfo is None:
                    published_at = published_at.replace(tzinfo=timezone.utc)
                if published_at < cutoff:
                    continue

            # If we can't parse the date, include it (don't lose data).

            cves_in_tweet = extract_cves(text)
            if not cves_in_tweet:
                continue

            seen_urls.add(tweet_url)
            known_poc_urls.add(tweet_url)

            likes = tweet.get('likes', 0) or 0
            retweets = tweet.get('retweets', 0) or 0
            replies = tweet.get('replies', 0) or 0
            stars = likes + retweets * 2 + replies * 3

            age_days = None
            if published_at is not None:
                age_days = (datetime.now(tz=timezone.utc) - published_at).days

            results.append({
                'url': tweet_url,
                'source': 'twitter',
                'description': text[:300],
                'cves': cves_in_tweet,
                'stars': stars,
                'age_days': age_days or 0,
                'tweet_meta': {
                    'author': tweet.get('author') or tweet.get('screenName') or 'unknown',
                    'screen_name': tweet.get('screenName') or '',
                    'followers': tweet.get('followersCount'),
                    'likes': likes,
                    'retweets': retweets,
                    'replies': replies,
                    'views': tweet.get('views', 0) or 0,
                    'tweet_id': tweet_id,
                },
            })

    # Deduplicate by tweet URL keeping highest engagement.
    deduped = list({r['url']: r for r in results}.values())
    deduped.sort(key=lambda x: x.get('stars', 0), reverse=True)

    if max_results is not None:
        deduped = deduped[:max_results]
    return deduped


def _parse_twitter_date(raw: str) -> datetime | None:
    """Parse Twitter's 'Sat May 23 23:04:31 +0000 2026' format."""
    if not raw:
        return None
    try:
        return datetime.strptime(raw, '%a %b %d %H:%M:%S %z %Y')
    except ValueError:
        return None
