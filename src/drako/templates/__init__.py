"""Policy template registry and inheritance utilities.

Templates are industry-specific .drako.yaml presets that users can
extend via ``extends: fintech`` in their own config. The SDK resolves
inheritance client-side before pushing the resolved config to the backend.
"""

from __future__ import annotations

import copy
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from drako.exceptions import ConfigError

_TEMPLATE_DIR = Path(__file__).parent


def list_templates() -> list[dict[str, str]]:
    """Return metadata for all available templates."""
    templates = []
    for f in sorted(_TEMPLATE_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            name = f.stem
            description = ""
            # Extract description from comment header
            lines = f.read_text(encoding="utf-8").split("\n")
            for line in lines:
                if line.startswith("# Drako Policy Template:"):
                    description = line.split(":", 1)[1].strip()
                    break
                if line.startswith("# ") and not description and "Drako" not in line:
                    description = line[2:].strip()
            templates.append({
                "name": name,
                "governance_level": data.get("governance_level", "custom"),
                "description": description,
            })
        except (yaml.YAMLError, OSError):
            continue
    return templates


def load_template(name: str) -> dict[str, Any]:
    """Load a template by name, returning its config as a dict.

    Raises ConfigError if the template is not found.
    """
    template_path = _TEMPLATE_DIR / f"{name}.yaml"
    if not template_path.exists():
        available = [f.stem for f in _TEMPLATE_DIR.glob("*.yaml")]
        raise ConfigError(
            f"Unknown template: '{name}'. "
            f"Available templates: {', '.join(available) or 'none'}"
        )

    try:
        data = yaml.safe_load(template_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in template '{name}': {exc}") from exc

    return data


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override into base. Override values take precedence.

    For dicts: recursively merge.
    For everything else: override replaces base.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result
