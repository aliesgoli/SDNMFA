"""Password hashing and verification for the v2 thesis implementation.

New credentials use memory-hard scrypt with a unique random salt.  The
database login layer keeps read compatibility with the legacy PostgreSQL
bcrypt representation and upgrades it after a successful login.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Optional


SCHEME = "sdnmfa_scrypt_v1"
N = 2**14
R = 8
P = 1
SALT_BYTES = 16
KEY_BYTES = 32
MAX_MEMORY = 64 * 1024 * 1024


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def hash_password(password: str, *, salt: Optional[bytes] = None) -> str:
    """Return a self-describing scrypt password hash."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    chosen_salt = bytes(salt) if salt is not None else secrets.token_bytes(SALT_BYTES)
    if len(chosen_salt) != SALT_BYTES:
        raise ValueError("Password salt must be 16 bytes")
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=chosen_salt,
        n=N,
        r=R,
        p=P,
        dklen=KEY_BYTES,
        maxmem=MAX_MEMORY,
    )
    return "$".join(
        (SCHEME, str(N), str(R), str(P), _b64encode(chosen_salt), _b64encode(derived))
    )


def verify_password(encoded: str, candidate: str) -> bool:
    """Verify a candidate without leaking parsing failures."""
    try:
        scheme, n_text, r_text, p_text, salt_text, expected_text = encoded.split("$")
        if scheme != SCHEME:
            return False
        n_value, r_value, p_value = int(n_text), int(r_text), int(p_text)
        if (n_value, r_value, p_value) != (N, R, P):
            return False
        salt = _b64decode(salt_text)
        expected = _b64decode(expected_text)
        if len(salt) != SALT_BYTES or len(expected) != KEY_BYTES:
            return False
        observed = hashlib.scrypt(
            str(candidate).encode("utf-8"),
            salt=salt,
            n=n_value,
            r=r_value,
            p=p_value,
            dklen=len(expected),
            maxmem=MAX_MEMORY,
        )
        return hmac.compare_digest(observed, expected)
    except (TypeError, ValueError, UnicodeError):
        return False


def password_policy_error(password: str) -> Optional[str]:
    """Return a human-readable policy error for ordinary account creation."""
    if len(password or "") < 12:
        return "Password must contain at least 12 characters"
    categories = (
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char.isdigit() for char in password),
        any(not char.isalnum() for char in password),
    )
    if sum(categories) < 3:
        return "Password must use at least three character categories"
    return None
