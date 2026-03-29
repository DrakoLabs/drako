#!/usr/bin/env python3
"""Master threat-intel sync — daily cron entry point.

Fetches from all configured feeds, applies quality gates, deduplicates
against previously seen advisories, validates output, and writes
DRAKO-ABSS YAML files to the staging directory.

Usage:
    python sync_all.py                     # Full sync (all feeds)
    python sync_all.py --dry-run           # Preview without writing
    python sync_all.py --source otx        # Single feed
    python sync_all.py --source abusech    # Single feed
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Ensure sibling modules are importable when running as a script.
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from sync_otx import fetch_ai_pulses, map_otx_to_abss  # noqa: E402
from sync_abusech import fetch_ai_targeted_urls  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("threat-intel-sync")

OUTPUT_DIR = SCRIPT_DIR / "output"
CONFIG_PATH = SCRIPT_DIR / "config.yaml"
STATE_PATH = SCRIPT_DIR / "state.json"

# Fields required for every advisory written to disk.
REQUIRED_FIELDS = ("id", "title", "severity", "source", "ioc", "metadata")


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config() -> dict[str, Any]:
    """Load configuration from config.yaml next to this script."""
    if not CONFIG_PATH.is_file():
        logger.warning("Config file not found at %s — using defaults", CONFIG_PATH)
        return {}
    with CONFIG_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ---------------------------------------------------------------------------
# State management (deduplication across runs)
# ---------------------------------------------------------------------------

def load_state() -> dict[str, Any]:
    """Load persisted state (seen IDs) from disk."""
    if not STATE_PATH.is_file():
        return {"seen_ids": []}
    try:
        with STATE_PATH.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Corrupted state file, resetting: %s", exc)
        return {"seen_ids": []}


def save_state(state: dict[str, Any]) -> None:
    """Persist state to disk."""
    with STATE_PATH.open("w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    logger.debug("State saved with %d seen IDs", len(state.get("seen_ids", [])))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_advisory(advisory: dict[str, Any]) -> bool:
    """Validate that an advisory has all required fields before writing."""
    for field in REQUIRED_FIELDS:
        if not advisory.get(field):
            logger.warning(
                "Advisory %s failed validation: missing or empty field '%s'",
                advisory.get("id", "<no-id>"), field,
            )
            return False
    return True


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def write_advisory(advisory: dict[str, Any], *, output_dir: Path) -> Path:
    """Write a single advisory as YAML to the output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)

    filename = advisory["id"].lower().replace(":", "-") + ".yaml"
    path = output_dir / filename

    advisory["_generated_by"] = "threat-intel-sync"
    advisory["_schema_version"] = "1.0"

    path.write_text(
        yaml.dump(advisory, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# Existing-ID loader (reads the output staging dir)
# ---------------------------------------------------------------------------

def load_existing_ids(output_dir: Path) -> set[str]:
    """Load IDs of all existing advisories in the output directory."""
    ids: set[str] = set()
    if not output_dir.is_dir():
        return ids
    for fpath in output_dir.glob("*.yaml"):
        try:
            data = yaml.safe_load(fpath.read_text(encoding="utf-8"))
            if data and isinstance(data, dict) and "id" in data:
                ids.add(data["id"])
        except Exception as exc:
            logger.warning("Could not read existing advisory %s: %s", fpath.name, exc)
    return ids


# ---------------------------------------------------------------------------
# Core sync
# ---------------------------------------------------------------------------

async def sync(
    *,
    source: str = "all",
    dry_run: bool = False,
) -> int:
    """Run the full sync pipeline. Returns the count of new advisories written."""
    config = load_config()
    state = load_state()
    seen_ids = set(state.get("seen_ids", []))

    existing_ids = load_existing_ids(OUTPUT_DIR)
    all_known_ids = seen_ids | existing_ids
    logger.info("Known advisories: %d (state) + %d (on-disk)", len(seen_ids), len(existing_ids))

    new_advisories: list[dict[str, Any]] = []
    rejected = {"quality": 0, "duplicate": 0, "invalid": 0}

    # --- OTX ---
    if source in ("all", "otx"):
        logger.info("Fetching AlienVault OTX pulses...")
        try:
            otx_cfg = config.get("otx", {})
            pulses = await fetch_ai_pulses(
                base_url=otx_cfg.get("base_url", "https://otx.alienvault.com/api/v1"),
                keywords=otx_cfg.get("search_keywords"),
                max_per_keyword=otx_cfg.get("max_pulses_per_keyword", 20),
                limit=otx_cfg.get("max_total_pulses", 50),
                timeout=float(otx_cfg.get("timeout_seconds", 15)),
            )
            logger.info("OTX returned %d pulses", len(pulses))

            qg = otx_cfg.get("quality_gate", {})
            ai_tags_list = otx_cfg.get("ai_tags")
            ai_tags = set(ai_tags_list) if ai_tags_list else None

            for pulse in pulses:
                advisory = map_otx_to_abss(
                    pulse,
                    min_subscribers=qg.get("min_subscriber_count", 10),
                    min_indicators=qg.get("min_indicator_count", 1),
                    ai_tags=ai_tags,
                )
                if advisory is None:
                    rejected["quality"] += 1
                    continue
                if advisory["id"] in all_known_ids:
                    rejected["duplicate"] += 1
                    continue
                if not validate_advisory(advisory):
                    rejected["invalid"] += 1
                    continue
                new_advisories.append(advisory)
                all_known_ids.add(advisory["id"])
        except Exception:
            logger.exception("OTX sync failed — continuing with other feeds")

    # --- abuse.ch ---
    if source in ("all", "abusech"):
        logger.info("Fetching abuse.ch URLhaus...")
        try:
            ac_cfg = config.get("abusech", {})
            domains_list = ac_cfg.get("ai_infrastructure_domains")
            ai_domains = frozenset(domains_list) if domains_list else None

            abuse_advisories = await fetch_ai_targeted_urls(
                urlhaus_api=ac_cfg.get("urlhaus_api", "https://urlhaus-api.abuse.ch/v1"),
                ai_domains=ai_domains,
                limit=ac_cfg.get("max_recent_urls", 100),
                timeout=float(ac_cfg.get("timeout_seconds", 15)),
            )
            logger.info("URLhaus returned %d AI-targeted advisories", len(abuse_advisories))

            for advisory in abuse_advisories:
                if advisory["id"] in all_known_ids:
                    rejected["duplicate"] += 1
                    continue
                if not validate_advisory(advisory):
                    rejected["invalid"] += 1
                    continue
                new_advisories.append(advisory)
                all_known_ids.add(advisory["id"])
        except Exception:
            logger.exception("abuse.ch sync failed — continuing")

    # --- Apply per-run cap ---
    max_per_run = config.get("output", {}).get("max_advisories_per_run", 50)
    if len(new_advisories) > max_per_run:
        logger.warning(
            "Capping output from %d to %d advisories",
            len(new_advisories), max_per_run,
        )
        new_advisories = new_advisories[:max_per_run]

    # --- Write ---
    written: list[str] = []
    if dry_run:
        for adv in new_advisories:
            logger.info("[DRY RUN] Would write: %s — %s", adv["id"], adv["title"][:60])
        written = [a["id"] for a in new_advisories]
    else:
        for advisory in new_advisories:
            path = write_advisory(advisory, output_dir=OUTPUT_DIR)
            written.append(path.name)
            logger.info("+ %s: %s", advisory["id"], advisory["title"][:60])

    # --- Update state ---
    if not dry_run:
        state["seen_ids"] = sorted(all_known_ids)
        state["last_run"] = str(asyncio.get_event_loop().time())
        save_state(state)

    # --- Summary ---
    logger.info("--- Sync Summary ---")
    logger.info("New advisories written: %d", len(written))
    logger.info("Rejected (quality gate): %d", rejected["quality"])
    logger.info("Rejected (duplicate):    %d", rejected["duplicate"])
    logger.info("Rejected (invalid):      %d", rejected["invalid"])
    logger.info("Total known:             %d", len(all_known_ids))

    # Write GitHub Actions step summary if available
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        try:
            with open(summary_file, "a", encoding="utf-8") as fh:
                fh.write("## Threat Intel Sync\n")
                fh.write(f"- New advisories: **{len(written)}**\n")
                fh.write(f"- Rejected (quality): {rejected['quality']}\n")
                fh.write(f"- Rejected (duplicate): {rejected['duplicate']}\n")
                fh.write(f"- Total corpus: {len(all_known_ids)}\n")
        except OSError as exc:
            logger.warning("Could not write GitHub step summary: %s", exc)

    return len(written)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sync AI/LLM threat intelligence from public feeds.",
    )
    parser.add_argument(
        "--source",
        choices=["all", "otx", "abusech"],
        default="all",
        help="Which feed(s) to sync (default: all)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be fetched without writing to disk",
    )
    return parser


def main() -> int:
    """Entry point for CLI and GitHub Actions."""
    parser = _build_parser()
    args = parser.parse_args()

    try:
        count = asyncio.run(sync(source=args.source, dry_run=args.dry_run))
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception:
        logger.exception("Unrecoverable error during sync")
        return 1

    logger.info("Done. %d new advisories.", count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
