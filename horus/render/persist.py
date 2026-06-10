"""Write rendered reports to disk under reports/YYYY/MM/."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..config import REPORTS_DIR


def save_report(content: str, fmt: str = "md", when: datetime | None = None) -> Path:
    """Write a report under reports/YYYY/MM/YYYY-MM-DD.{md|txt}.

    Same-day reruns overwrite. Returns the file path.
    """
    now = when or datetime.now()
    ext = "md" if fmt == "md" else "txt"
    folder = REPORTS_DIR / f"{now.year:04d}" / f"{now.month:02d}"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{now.strftime('%Y-%m-%d')}.{ext}"
    path.write_text(content)
    return path
