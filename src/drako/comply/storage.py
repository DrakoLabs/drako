"""Persist questionnaire answers in `.drako/comply.yaml`.

We pick YAML over JSON so users can hand-edit between runs without paying
the JSON quoting tax. Loads return an empty dict when no file exists so
the questionnaire only prompts for missing fields on subsequent runs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

COMPLY_FILE = Path(".drako") / "comply.yaml"


def _resolve(directory: str | Path) -> Path:
    return Path(directory) / COMPLY_FILE


def load(directory: str | Path = ".") -> dict[str, Any]:
    path = _resolve(directory)
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        return {}
    return raw


def save(answers: dict[str, Any], directory: str | Path = ".") -> Path:
    path = _resolve(directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(answers, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    return path
