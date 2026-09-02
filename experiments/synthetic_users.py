"""Deterministic, isolated user cohort for reproducible experiments."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional

from config.runtime_security import strong_secret_or_none
from security.password_service import SCHEME as PASSWORD_SCHEME
from security.password_service import hash_password
from security.simulated_biometric_v2 import encrypt_template, reference_vector


DEFAULT_COHORT = "thesis-v2-500"
DEFAULT_USER_COUNT = 500
USERNAME_PREFIXES = (
    "aurora", "cedar", "delta", "ember", "falcon", "garden", "harbor",
    "iris", "juniper", "keystone", "lotus", "maple", "nebula", "onyx",
    "pioneer", "quartz", "river", "saffron", "tulip", "umbra", "violet",
    "willow", "xenon", "yucca", "zephyr",
)
PASSWORD_CLASSES = (
    "weak_numeric",
    "weak_dictionary",
    "medium_mixed",
    "strong_composed",
    "high_entropy",
)
COMMON_NUMERIC_PASSWORDS = (
    "12345678", "11111111", "00000000", "87654321", "22222222",
    "12341234", "11223344", "12121212", "99999999", "55555555",
)


@dataclass(frozen=True)
class ExperimentUser:
    ordinal: int
    username: str
    full_name: str
    email: str
    password: str
    password_class: str
    cohort: str


def _master_secret() -> bytes:
    value = strong_secret_or_none(os.getenv("EXPERIMENT_MASTER_SECRET"))
    if value is None:
        raise RuntimeError(
            "EXPERIMENT_MASTER_SECRET must be a non-placeholder secret of at least 32 characters"
        )
    return value.encode("utf-8")


def _digest(label: str, ordinal: int) -> str:
    return hmac.new(
        _master_secret(),
        ("%s|%s" % (label, int(ordinal))).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _password_for(ordinal: int, password_class: str) -> str:
    digest = _digest("password|" + password_class, ordinal)
    if password_class == "weak_numeric":
        return COMMON_NUMERIC_PASSWORDS[ordinal % len(COMMON_NUMERIC_PASSWORDS)]
    if password_class == "weak_dictionary":
        words = ("welcome", "sunshine", "network", "student", "security")
        return words[ordinal % len(words)] + str(ordinal % 100)
    if password_class == "medium_mixed":
        return "Lab%s%s" % (digest[:6], ordinal % 97)
    if password_class == "strong_composed":
        return "V2!%s-%s-Az" % (digest[:12], digest[12:18].upper())
    return "H9!%s_%s#%s" % (digest[:14], digest[14:28].upper(), digest[28:38])


def build_user_profiles(
    count: int = DEFAULT_USER_COUNT, *, cohort: str = DEFAULT_COHORT
) -> List[ExperimentUser]:
    if not 1 <= int(count) <= 5000:
        raise ValueError("Experiment user count must be between 1 and 5000")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", cohort or ""):
        raise ValueError("Invalid cohort identifier")
    users: List[ExperimentUser] = []
    for ordinal in range(int(count)):
        prefix = USERNAME_PREFIXES[ordinal % len(USERNAME_PREFIXES)]
        suffix = _digest("username", ordinal)[:5]
        username = "expv2_%s_%03d_%s" % (prefix, ordinal, suffix)
        password_class = PASSWORD_CLASSES[ordinal % len(PASSWORD_CLASSES)]
        users.append(
            ExperimentUser(
                ordinal=ordinal,
                username=username,
                full_name="Synthetic Participant %03d" % (ordinal + 1),
                email="%s@invalid.example" % username,
                password=_password_for(ordinal, password_class),
                password_class=password_class,
                cohort=cohort,
            )
        )
    return users


def user_for_task(task_id: str, users: Iterable[ExperimentUser]) -> ExperimentUser:
    pool = list(users)
    if not pool:
        raise ValueError("Experiment user pool is empty")
    index = int(hashlib.sha256(str(task_id).encode("utf-8")).hexdigest()[:16], 16)
    return pool[index % len(pool)]


def provision_experiment_users(
    *,
    count: int = DEFAULT_USER_COUNT,
    cohort: str = DEFAULT_COHORT,
    replace_cohort: bool = False,
) -> dict:
    """Provision only the scoped synthetic cohort; ordinary accounts are untouched."""
    from database.db_config import get_db_connection, release_db_connection

    profiles = build_user_profiles(count, cohort=cohort)
    conn = get_db_connection()
    if conn is None:
        raise RuntimeError("Database connection is unavailable")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM users
                WHERE is_active=TRUE
                  AND is_experiment_user=FALSE
                """
            )
            operator_count = int(cur.fetchone()[0] or 0)
            if operator_count < 1:
                raise RuntimeError(
                    "At least one active non-experiment account is required"
                )
            if replace_cohort:
                cur.execute(
                    """
                    DELETE FROM users
                    WHERE is_experiment_user=TRUE
                      AND experiment_cohort=%s
                      AND username LIKE 'expv2_%%'
                    """,
                    (cohort,),
                )
            for profile in profiles:
                template = encrypt_template(
                    profile.username, reference_vector(profile.username)
                )
                cur.execute(
                    """
                    INSERT INTO users (
                        username, full_name, email, password_hash, password_scheme,
                        role, otp_enabled, biometric_template, biometric_mode,
                        biometric_threshold, is_active, is_experiment_user,
                        experiment_cohort, password_class
                    ) VALUES (
                        %s, %s, %s, %s, %s, 'user', TRUE, %s,
                        'software_simulated_v2', 0.92, TRUE, TRUE, %s, %s
                    )
                    ON CONFLICT (username) DO UPDATE SET
                        full_name=EXCLUDED.full_name,
                        email=EXCLUDED.email,
                        password_hash=EXCLUDED.password_hash,
                        password_scheme=EXCLUDED.password_scheme,
                        otp_enabled=TRUE,
                        biometric_template=EXCLUDED.biometric_template,
                        biometric_mode=EXCLUDED.biometric_mode,
                        biometric_threshold=EXCLUDED.biometric_threshold,
                        experiment_cohort=EXCLUDED.experiment_cohort,
                        password_class=EXCLUDED.password_class,
                        failed_attempts=0,
                        locked_until=NULL,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE users.is_experiment_user=TRUE
                    """,
                    (
                        profile.username,
                        profile.full_name,
                        profile.email,
                        hash_password(profile.password),
                        PASSWORD_SCHEME,
                        template,
                        cohort,
                        profile.password_class,
                    ),
                )
            cur.execute(
                """
                SELECT password_class, COUNT(*)
                FROM users
                WHERE is_experiment_user=TRUE AND experiment_cohort=%s
                GROUP BY password_class ORDER BY password_class
                """,
                (cohort,),
            )
            distribution = {name: int(total) for name, total in cur.fetchall()}
        conn.commit()
        return {
            "cohort": cohort,
            "user_count": len(profiles),
            "password_class_distribution": distribution,
            "ordinary_accounts_modified": 0,
            "eligible_operator_accounts": operator_count,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        release_db_connection(conn)
