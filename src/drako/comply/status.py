"""`drako comply status` dashboard logic."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ARTICLES = (9, 11, 12, 14)


@dataclass
class ArticleStatus:
    article: int
    last_generated: datetime | None
    scan_age_days: int | None
    state: str  # "up-to-date" | "STALE — regenerate" | "NOT GENERATED"


def _newest_artifact(output_dir: Path, article: int) -> datetime | None:
    candidates = list(output_dir.glob(f"article_{article}_*.docx")) + list(
        output_dir.glob(f"article_{article}_*.pdf")
    )
    if not candidates:
        return None
    newest = max(c.stat().st_mtime for c in candidates)
    return datetime.fromtimestamp(newest)


def _scan_mtime(directory: Path) -> datetime | None:
    cache = directory / ".drako" / ".last_scan.json"
    if not cache.exists():
        return None
    return datetime.fromtimestamp(cache.stat().st_mtime)


def collect(directory: str | Path = ".", output_dir: str | Path = "comply-output") -> list[ArticleStatus]:
    directory = Path(directory)
    output_dir = directory / output_dir if not Path(output_dir).is_absolute() else Path(output_dir)
    scan_mtime = _scan_mtime(directory)
    rows: list[ArticleStatus] = []
    for article in ARTICLES:
        last = _newest_artifact(output_dir, article) if output_dir.exists() else None
        if last is None:
            rows.append(ArticleStatus(article, None, None, "NOT GENERATED"))
            continue
        age = (datetime.now() - last).days if last else None
        state = "STALE — regenerate" if scan_mtime and scan_mtime > last else "up-to-date"
        rows.append(ArticleStatus(article, last, age, state))
    return rows


def render(rows: list[ArticleStatus]) -> str:
    lines = [
        "Article     Last Generated      Scan Age    Status",
        "────────    ──────────────      ─────────   ─────────",
    ]
    for r in rows:
        last = r.last_generated.strftime("%Y-%m-%d %H:%M") if r.last_generated else "—"
        age = f"{r.scan_age_days} days" if r.scan_age_days is not None else "—"
        lines.append(f"Art. {r.article:<3} {last:<19} {age:<11} {r.state}")
    return "\n".join(lines) + "\n"
