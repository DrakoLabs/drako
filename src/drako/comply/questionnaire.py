"""Interactive questionnaire for `drako comply init`.

The 30 questions are split into six groups of five and cover the slice of
the EU AI Act that scan/BOM cannot infer (purpose, users, training data,
oversight, limitations, compliance context). Each `Question` knows its
key, prompt, group, and optional choice list. The `run` helper drives the
flow with Click prompts and only asks about fields that are missing from
the existing answers dict — re-runs are cheap.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import click


@dataclass
class Question:
    key: str
    prompt: str
    group: str
    choices: list[str] | None = None
    multi: bool = False  # if True, value is a list (comma-separated input)
    default: str | None = None


QUESTIONS: list[Question] = [
    # System identity
    Question("system_name", "System name", "System identity"),
    Question("system_version", "System version", "System identity"),
    Question("deployment_environment", "Deployment environment (e.g. production, staging)", "System identity"),
    Question("deployment_regions", "Deployment regions (comma-separated)", "System identity", multi=True),
    Question("provider_entity", "Provider/operator legal entity name", "System identity"),
    # Purpose and users
    Question("system_purpose", "Intended purpose of the system", "Purpose and users"),
    Question("intended_users", "Categories of affected users", "Purpose and users"),
    Question(
        "domain",
        "Application domain",
        "Purpose and users",
        choices=[
            "health", "finance", "hr", "legal", "education",
            "critical_infrastructure", "other",
        ],
    ),
    Question("high_risk_rationale", "High-risk classification rationale", "Purpose and users"),
    Question("deployment_timeline", "Deployment timeline", "Purpose and users"),
    # Data and training
    Question("training_data_sources", "Training data sources (comma-separated)", "Data and training", multi=True),
    Question("data_provenance", "Data provenance summary", "Data and training"),
    Question("data_retention_policy", "Data retention policy", "Data and training"),
    Question("pii_categories", "PII categories processed (comma-separated)", "Data and training", multi=True),
    Question("data_subject_rights", "Data subject rights mechanism", "Data and training"),
    # Oversight and governance
    Question("oversight_responsible_name", "Name of human oversight responsible", "Oversight and governance"),
    Question("oversight_responsible_role", "Their role / title", "Oversight and governance"),
    Question("escalation_path", "Escalation path for incidents", "Oversight and governance"),
    Question("incident_response_procedure", "Incident response procedure", "Oversight and governance"),
    Question("update_cadence", "Update / retraining cadence", "Oversight and governance"),
    # Limitations and risks
    Question("known_limitations", "Known limitations (comma-separated)", "Limitations and risks", multi=True),
    Question("known_failure_modes", "Known failure modes (comma-separated)", "Limitations and risks", multi=True),
    Question("residual_risks", "Residual risks (comma-separated)", "Limitations and risks", multi=True),
    Question("out_of_scope_use_cases", "Out-of-scope use cases (comma-separated)", "Limitations and risks", multi=True),
    Question("user_notification_mechanism", "User notification mechanism", "Limitations and risks"),
    # Compliance context
    Question("other_regulations", "Other applicable regulations (comma-separated)", "Compliance context", multi=True),
    Question("existing_certifications", "Existing certifications (e.g. SOC2, ISO)", "Compliance context", multi=True),
    Question("third_party_audits", "Third-party audits done", "Compliance context"),
    Question("legal_counsel_involvement", "Legal counsel involvement", "Compliance context"),
    Question("signature_authority", "Signature authority for this document", "Compliance context"),
]


def _parse_multi(raw: str) -> list[str]:
    return [piece.strip() for piece in raw.split(",") if piece.strip()]


def _ask(question: Question, prompter) -> Any:
    if question.choices:
        return prompter(
            f"[{question.group}] {question.prompt}",
            type=click.Choice(question.choices),
            default=question.default,
        )
    raw = prompter(f"[{question.group}] {question.prompt}", default=question.default or "")
    if question.multi:
        return _parse_multi(raw)
    return raw


def run(
    existing: dict[str, Any] | None = None,
    *,
    only: Iterable[str] | None = None,
    prompter=click.prompt,
) -> dict[str, Any]:
    """Run the questionnaire, returning the merged answers dict.

    Only fields missing from `existing` are prompted. `only` (when given)
    restricts prompting to a subset of question keys — useful for tests.
    `prompter` is injectable so unit tests can drive non-interactively.
    """
    answers: dict[str, Any] = dict(existing or {})
    keys = set(only) if only is not None else None
    for question in QUESTIONS:
        if keys is not None and question.key not in keys:
            continue
        if question.key in answers and answers[question.key] not in (None, "", []):
            continue
        answers[question.key] = _ask(question, prompter)
    return answers


def question_keys() -> list[str]:
    return [q.key for q in QUESTIONS]
