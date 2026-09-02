"""Shared fail-closed validation for runtime secrets."""

from __future__ import annotations

from typing import Any, Optional


MIN_SECRET_LENGTH = 32
PLACEHOLDER_FRAGMENTS = (
    "change_me",
    "changeme",
    "default_fallback",
    "replace_me",
    "your_secret",
    "your_token",
)


def secret_validation_error(value: Any) -> Optional[str]:
    """Return a stable error identifier, or ``None`` for an acceptable secret."""
    secret = str(value or "").strip()
    lowered = secret.lower()
    if not secret:
        return "missing"
    if len(secret) < MIN_SECRET_LENGTH:
        return "too_short"
    if any(fragment in lowered for fragment in PLACEHOLDER_FRAGMENTS):
        return "placeholder"
    if len(set(secret)) < 8:
        return "insufficient_character_diversity"
    return None


def strong_secret_or_none(value: Any) -> Optional[str]:
    """Return the normalized secret only when it satisfies the shared policy."""
    secret = str(value or "").strip()
    return secret if secret_validation_error(secret) is None else None
