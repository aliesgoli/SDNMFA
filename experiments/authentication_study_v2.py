"""Execute the controlled authentication-attack matrix on synthetic users."""

from __future__ import annotations

import json
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:  # preflight reports the missing dependency
    psutil = None

from config.experiment_protocol import POLICY_SELECTION, POLICY_SPECS
from experiments.authentication_protocol import (
    AUTH_PRESENTATION_BUDGETS,
    AuthenticationObservationPlan,
    build_authentication_plan,
    expected_policy_outcome,
)
from experiments.synthetic_users import ExperimentUser
from otp.otp_service import generate_otp, store_otp, validate_otp
from security.mfa_manager import authenticate_user
from security.password_service import verify_password
from security.simulated_biometric_v2 import score_probe, simulated_probe


POLICY_KEYS = {mode: key for key, mode in POLICY_SELECTION.items()}
COMMON_NUMERIC = (
    "12345678", "11111111", "00000000", "87654321", "22222222",
    "12341234", "11223344", "12121212", "99999999", "55555555",
)
COMMON_WORDS = ("welcome", "sunshine", "network", "student", "security")


def _connection():
    from database.db_config import get_db_connection

    conn = get_db_connection()
    if conn is None:
        raise RuntimeError("Database connection is unavailable")
    return conn


def _release(conn) -> None:
    from database.db_config import release_db_connection

    release_db_connection(conn)


def _dictionary_candidates(limit: int) -> List[str]:
    candidates = list(COMMON_NUMERIC)
    for suffix in range(100):
        for word in COMMON_WORDS:
            candidates.append(word + str(suffix))
    # Medium/strong fixtures are deliberately absent from this bounded list.
    return candidates[: int(limit)]


def _audit_password(
    profile: ExperimentUser,
    stored_hash: str,
    plan: AuthenticationObservationPlan,
) -> Tuple[bool, int]:
    variant = plan.attack_variant
    if variant == "credential_stuffing_audit":
        exposure_percent = {"low": 10, "medium": 30, "high": 60}[plan.intensity]
        exposed = (profile.ordinal * 37 + plan.repetition * 11) % 100 < exposure_percent
        candidates = [profile.password] if exposed else ["synthetic-pair-not-present"]
    elif variant == "password_spray_audit":
        candidates = _dictionary_candidates(plan.guess_budget)[: plan.guess_budget]
    else:
        candidates = _dictionary_candidates(plan.guess_budget)
    for index, candidate in enumerate(candidates, start=1):
        if verify_password(stored_hash, candidate):
            return True, index
    return False, len(candidates)


def _stored_user_material(username: str) -> Tuple[str, str, Optional[float]]:
    conn = _connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT password_hash, biometric_template, biometric_threshold
                FROM users
                WHERE username=%s AND is_experiment_user=TRUE AND is_active=TRUE
                """,
                (username,),
            )
            row = cur.fetchone()
        if not row:
            raise RuntimeError("Synthetic experiment user is missing: %s" % username)
        return str(row[0]), str(row[1]), row[2]
    finally:
        _release(conn)


def _expire_attempt(username: str, attempt_id: str, age_seconds: int) -> None:
    conn = _connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE otp_sessions
                SET expires_at=CURRENT_TIMESTAMP - (%s * INTERVAL '1 second'),
                    invalidated_reason='controlled_expiry'
                WHERE username=%s AND attempt_id=%s
                """,
                (int(age_seconds), username, attempt_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _release(conn)


def _persist_observation(
    *, study_id: str, profile: ExperimentUser,
    plan: AuthenticationObservationPlan, run_id: str,
    actual_success: bool, expected_success: bool, latency_ms: float,
    supplied: Dict[str, Any], resource_metrics: Dict[str, Any],
    biometric_score: Optional[float], biometric_threshold: Optional[float],
    message: str,
) -> None:
    conn = _connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO authentication_experiment_logs (
                    campaign_id, study_id, run_id, username, scenario,
                    attack_family, attack_variant, intensity_level, mfa_mode,
                    repetition, supplied_factors, authentication_succeeded,
                    expected_success, biometric_score, biometric_threshold,
                    is_valid, latency_ms, resource_metrics, message
                ) VALUES (
                    NULL, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s::jsonb, %s, %s, %s, %s, %s, %s, %s::jsonb, %s
                )
                ON CONFLICT (
                    study_id, username, attack_family, attack_variant, scenario,
                    intensity_level, mfa_mode, repetition
                ) WHERE study_id IS NOT NULL DO UPDATE SET
                    run_id=EXCLUDED.run_id,
                    supplied_factors=EXCLUDED.supplied_factors,
                    authentication_succeeded=EXCLUDED.authentication_succeeded,
                    expected_success=EXCLUDED.expected_success,
                    biometric_score=EXCLUDED.biometric_score,
                    biometric_threshold=EXCLUDED.biometric_threshold,
                    is_valid=EXCLUDED.is_valid,
                    latency_ms=EXCLUDED.latency_ms,
                    resource_metrics=EXCLUDED.resource_metrics,
                    message=EXCLUDED.message,
                    created_at=CURRENT_TIMESTAMP
                """,
                (
                    study_id, run_id, profile.username, plan.attack_variant,
                    plan.attack_family, plan.attack_variant, plan.intensity,
                    plan.policy, plan.repetition,
                    json.dumps(supplied, sort_keys=True), bool(actual_success),
                    bool(expected_success), biometric_score, biometric_threshold,
                    True, float(latency_ms),
                    json.dumps(resource_metrics, sort_keys=True), str(message),
                ),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _release(conn)


def reset_experiment_user_state(username: str) -> None:
    """Reset transient verifier state before an independent paired block.

    Password lockout counters and outstanding OTP sessions are stateful by
    design.  Clearing only those transient fields for a synthetic experiment
    account prevents one planned cell from changing the starting conditions
    of the next cell.  Passwords, enrollments, and ordinary accounts are not
    modified.
    """
    conn = _connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET failed_attempts=0, locked_until=NULL, last_failed_login=NULL
                WHERE username=%s AND is_experiment_user=TRUE
                """,
                (username,),
            )
            if cur.rowcount != 1:
                raise RuntimeError("Synthetic experiment user is missing: %s" % username)
            cur.execute(
                """
                UPDATE otp_sessions
                SET used=TRUE,
                    invalidated_reason=COALESCE(invalidated_reason, 'block_reset')
                WHERE username=%s AND used=FALSE
                """,
                (username,),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _release(conn)


def execute_authentication_observation(
    *,
    profile: ExperimentUser,
    plan: AuthenticationObservationPlan,
    users: List[ExperimentUser],
    run_id: Optional[str] = None,
    reset_state: bool = False,
) -> Dict[str, Any]:
    """Exercise the real verifier once and return a privacy-safe observation."""
    if reset_state:
        reset_experiment_user_state(profile.username)
    stored_password, stored_template, threshold = _stored_user_material(
        profile.username
    )
    password_hit = False
    guesses_made = 0
    if plan.factor_state["password"] == "bounded_audit":
        password_hit, guesses_made = _audit_password(
            profile, stored_password, plan
        )

    observation_run_id = str(uuid.UUID(run_id or plan.observation_id))
    attempt_id = str(uuid.uuid4())
    factor_state = dict(plan.factor_state)
    if factor_state["password"] == "bounded_audit":
        factor_state["password"] = "audit_hit" if password_hit else "invalid"
    supplied_password = (
        profile.password
        if factor_state["password"] in {"valid", "audit_hit"}
        else "invalid-synthetic-password"
    )

    otp_code: Optional[str] = None
    otp_guesses_executed = 0
    expiry_age_seconds = 0
    if "otp" in POLICY_SPECS[plan.policy]["factor_keys"]:
        otp_state = factor_state["otp"]
        if otp_state != "missing":
            generated = generate_otp()
            staged_attempt = (
                str(uuid.uuid4()) if otp_state == "cross_attempt" else attempt_id
            )
            stored, store_message = store_otp(
                profile.username,
                generated,
                run_id=observation_run_id,
                attempt_id=staged_attempt,
            )
            if not stored:
                raise RuntimeError(store_message)
            otp_code = generated
            if otp_state == "invalid":
                otp_code = "000000" if generated != "000000" else "999999"
                target_guesses = {"low": 1, "medium": 3, "high": 5}[
                    plan.intensity
                ]
                for _ in range(target_guesses - 1):
                    validate_otp(
                        profile.username, otp_code, attempt_id=attempt_id
                    )
                    otp_guesses_executed += 1
            elif otp_state == "expired":
                expiry_age_seconds = {
                    "low": 1, "medium": 30, "high": 120
                }[plan.intensity]
                _expire_attempt(
                    profile.username, attempt_id, expiry_age_seconds
                )
            elif otp_state == "replay":
                consumed, _ = validate_otp(
                    profile.username, generated, attempt_id=attempt_id
                )
                if not consumed:
                    raise RuntimeError("Could not stage controlled OTP replay")

    biometric_data: Optional[str] = None
    biometric_score: Optional[float] = None
    biometric_probes_evaluated = 0
    if "biometric" in POLICY_SPECS[plan.policy]["factor_keys"]:
        bio_state = factor_state["biometric"]
        if bio_state in {"valid", "replay"}:
            biometric_data = simulated_probe(
                profile.username,
                probe_index=plan.repetition if bio_state == "valid" else 0,
                genuine=True,
            )
        elif bio_state == "impostor":
            candidates: List[Tuple[float, str]] = []
            for offset in range(
                1, AUTH_PRESENTATION_BUDGETS[plan.intensity] + 1
            ):
                other = users[(profile.ordinal + offset) % len(users)]
                candidate = simulated_probe(
                    profile.username,
                    probe_index=(plan.repetition * 10) + offset,
                    genuine=False,
                    impostor_username=other.username,
                )
                candidates.append(
                    (
                        score_probe(
                            profile.username, stored_template, candidate
                        ),
                        candidate,
                    )
                )
            biometric_score, biometric_data = max(
                candidates, key=lambda item: item[0]
            )
            biometric_probes_evaluated = len(candidates)
        elif bio_state == "corrupt":
            biometric_data = "simv2:corrupted-probe"
        if biometric_data and bio_state != "corrupt" and biometric_score is None:
            biometric_score = score_probe(
                profile.username, stored_template, biometric_data
            )

    expected = expected_policy_outcome(plan.policy, factor_state)
    process = psutil.Process() if psutil is not None else None
    rss_before = process.memory_info().rss if process else 0
    cpu_before = process.cpu_times() if process else None
    started = time.perf_counter()
    success, message = authenticate_user(
        username=profile.username,
        password=supplied_password,
        otp_code=otp_code,
        biometric_data=biometric_data,
        policy_key=POLICY_KEYS[plan.policy],
        run_id=observation_run_id,
        attempt_id=attempt_id,
    )
    latency_ms = (time.perf_counter() - started) * 1000.0
    rss_after = process.memory_info().rss if process else 0
    cpu_after = process.cpu_times() if process else None
    cpu_seconds = 0.0
    if cpu_before is not None and cpu_after is not None:
        cpu_seconds = max(
            0.0,
            (cpu_after.user + cpu_after.system)
            - (cpu_before.user + cpu_before.system),
        )
    resources = {
        "process_label": "mfa_verifier",
        "cpu_seconds": round(cpu_seconds, 6),
        "rss_before_bytes": int(rss_before),
        "rss_after_bytes": int(rss_after),
        "rss_delta_bytes": int(rss_after - rss_before),
        "password_guess_budget": int(plan.guess_budget),
        "password_guesses_executed": int(guesses_made),
        "password_audit_hit": bool(password_hit),
        "presentation_attempt_budget": int(
            AUTH_PRESENTATION_BUDGETS[plan.intensity]
        ),
        "biometric_probes_evaluated": int(biometric_probes_evaluated),
        "otp_expiry_age_seconds": int(expiry_age_seconds),
        "otp_guesses_executed": int(
            otp_guesses_executed
            + (
                1
                if factor_state.get("otp") == "invalid"
                and "otp" in POLICY_SPECS[plan.policy]["factor_keys"]
                else 0
            )
        ),
    }
    return {
        "run_id": observation_run_id,
        "attempt_id": attempt_id,
        "success": bool(success),
        "expected_success": bool(expected),
        "is_valid": True,
        "outcome_matches_expected": bool(success) == bool(expected),
        "latency_ms": latency_ms,
        "factor_state": factor_state,
        "required_factors": list(POLICY_SPECS[plan.policy]["factor_keys"]),
        "resource_metrics": resources,
        "biometric_score": biometric_score,
        "biometric_threshold": float(threshold or 0.92),
        "message": str(message),
        "secrets_persisted": False,
    }


def run_authentication_study(
    *, study_id: str, base_seed: int, repetitions: int,
    users: List[ExperimentUser], progress_every: int = 25,
) -> Dict[str, Any]:
    """Run 14 attacks x 3 intensities x 4 policies x repetitions."""
    uuid.UUID(str(study_id))
    plans = build_authentication_plan(
        base_seed=base_seed, repetitions=repetitions, user_count=len(users)
    )
    grouped: Dict[str, List[AuthenticationObservationPlan]] = defaultdict(list)
    for plan in plans:
        grouped[plan.block_id].append(plan)
    process = psutil.Process() if psutil is not None else None
    total = 0
    valid = 0
    protocol_outcome_mismatches = 0
    residual_biometric_replay_accepts = 0
    for block_number, block_plans in enumerate(grouped.values(), start=1):
        profile = users[block_plans[0].user_ordinal]
        stored_password, stored_template, threshold = _stored_user_material(
            profile.username
        )
        password_hit = False
        guesses_made = 0
        if block_plans[0].factor_state["password"] == "bounded_audit":
            password_hit, guesses_made = _audit_password(
                profile, stored_password, block_plans[0]
            )
        for plan in sorted(block_plans, key=lambda item: item.policy_position):
            run_id = str(uuid.UUID(plan.observation_id))
            attempt_id = str(uuid.uuid4())
            factor_state = dict(plan.factor_state)
            if factor_state["password"] == "bounded_audit":
                factor_state["password"] = "audit_hit" if password_hit else "invalid"
            supplied_password = (
                profile.password
                if factor_state["password"] in {"valid", "audit_hit"}
                else "invalid-synthetic-password"
            )

            otp_code: Optional[str] = None
            otp_guesses_executed = 0
            expiry_age_seconds = 0
            if "otp" in POLICY_SPECS[plan.policy]["factor_keys"]:
                otp_state = factor_state["otp"]
                if otp_state != "missing":
                    generated = generate_otp()
                    staged_attempt = (
                        str(uuid.uuid4()) if otp_state == "cross_attempt" else attempt_id
                    )
                    stored, store_message = store_otp(
                        profile.username, generated, run_id=run_id,
                        attempt_id=staged_attempt,
                    )
                    if not stored:
                        raise RuntimeError(store_message)
                    otp_code = generated
                    if otp_state == "invalid":
                        otp_code = "000000" if generated != "000000" else "999999"
                        target_guesses = {"low": 1, "medium": 3, "high": 5}[
                            plan.intensity
                        ]
                        for _ in range(target_guesses - 1):
                            validate_otp(
                                profile.username, otp_code, attempt_id=attempt_id
                            )
                            otp_guesses_executed += 1
                    elif otp_state == "expired":
                        expiry_age_seconds = {
                            "low": 1, "medium": 30, "high": 120
                        }[plan.intensity]
                        _expire_attempt(
                            profile.username, attempt_id, expiry_age_seconds
                        )
                    elif otp_state == "replay":
                        consumed, _ = validate_otp(
                            profile.username, generated, attempt_id=attempt_id
                        )
                        if not consumed:
                            raise RuntimeError("Could not stage controlled OTP replay")

            biometric_data: Optional[str] = None
            biometric_score: Optional[float] = None
            biometric_probes_evaluated = 0
            if "biometric" in POLICY_SPECS[plan.policy]["factor_keys"]:
                bio_state = factor_state["biometric"]
                if bio_state in {"valid", "replay"}:
                    biometric_data = simulated_probe(
                        profile.username,
                        probe_index=plan.repetition if bio_state == "valid" else 0,
                        genuine=True,
                    )
                elif bio_state == "impostor":
                    # A stronger presentation tier receives a larger bounded
                    # candidate budget. The actual verifier is then exercised
                    # with the highest-scoring candidate, never with a
                    # fabricated acceptance outcome.
                    candidates: List[Tuple[float, str]] = []
                    for offset in range(
                        1, AUTH_PRESENTATION_BUDGETS[plan.intensity] + 1
                    ):
                        other = users[(profile.ordinal + offset) % len(users)]
                        candidate = simulated_probe(
                            profile.username,
                            probe_index=(plan.repetition * 10) + offset,
                            genuine=False,
                            impostor_username=other.username,
                        )
                        candidates.append(
                            (
                                score_probe(
                                    profile.username, stored_template, candidate
                                ),
                                candidate,
                            )
                        )
                    biometric_score, biometric_data = max(
                        candidates, key=lambda item: item[0]
                    )
                    biometric_probes_evaluated = len(candidates)
                elif bio_state == "corrupt":
                    biometric_data = "simv2:corrupted-probe"
                if (
                    biometric_data
                    and bio_state != "corrupt"
                    and biometric_score is None
                ):
                    biometric_score = score_probe(
                        profile.username, stored_template, biometric_data
                    )

            expected = expected_policy_outcome(plan.policy, factor_state)
            rss_before = process.memory_info().rss if process else 0
            cpu_before = process.cpu_times() if process else None
            started = time.perf_counter()
            success, message = authenticate_user(
                username=profile.username,
                password=supplied_password,
                otp_code=otp_code,
                biometric_data=biometric_data,
                policy_key=POLICY_KEYS[plan.policy],
                run_id=run_id,
                attempt_id=attempt_id,
            )
            latency_ms = (time.perf_counter() - started) * 1000.0
            rss_after = process.memory_info().rss if process else 0
            cpu_after = process.cpu_times() if process else None
            cpu_seconds = 0.0
            if cpu_before is not None and cpu_after is not None:
                cpu_seconds = max(
                    0.0,
                    (cpu_after.user + cpu_after.system)
                    - (cpu_before.user + cpu_before.system),
                )
            resources = {
                "process_label": "mfa_verifier",
                "cpu_seconds": round(cpu_seconds, 6),
                "rss_before_bytes": int(rss_before),
                "rss_after_bytes": int(rss_after),
                "rss_delta_bytes": int(rss_after - rss_before),
                "password_guess_budget": int(plan.guess_budget),
                "password_guesses_executed": int(guesses_made),
                "password_audit_hit": bool(password_hit),
                "presentation_attempt_budget": int(
                    AUTH_PRESENTATION_BUDGETS[plan.intensity]
                ),
                "biometric_probes_evaluated": int(
                    biometric_probes_evaluated
                ),
                "otp_expiry_age_seconds": int(expiry_age_seconds),
                "otp_guesses_executed": int(
                    otp_guesses_executed
                    + (1 if factor_state.get("otp") == "invalid" and "otp" in POLICY_SPECS[plan.policy]["factor_keys"] else 0)
                ),
            }
            supplied = {
                "factor_state": factor_state,
                "required_factors": list(POLICY_SPECS[plan.policy]["factor_keys"]),
                "secrets_persisted": False,
                "scope": "synthetic_local_lab_only",
            }
            _persist_observation(
                study_id=study_id, profile=profile, plan=plan, run_id=run_id,
                actual_success=bool(success), expected_success=bool(expected),
                latency_ms=latency_ms, supplied=supplied,
                resource_metrics=resources, biometric_score=biometric_score,
                biometric_threshold=float(threshold or 0.92), message=str(message),
            )
            total += 1
            valid += 1
            if bool(success) != bool(expected):
                protocol_outcome_mismatches += 1
            if (
                plan.attack_variant == "biometric_replay_without_liveness"
                and success
                and "biometric" in POLICY_SPECS[plan.policy]["factor_keys"]
            ):
                residual_biometric_replay_accepts += 1
        if progress_every and block_number % int(progress_every) == 0:
            print(
                "Authentication study: %s/%s isolated blocks completed"
                % (block_number, len(grouped))
            )
    return {
        "study_id": study_id,
        "planned_observations": len(plans),
        "completed_observations": total,
        "valid_observations": valid,
        "protocol_outcome_mismatches": protocol_outcome_mismatches,
        "isolated_user_blocks": len(grouped),
        "residual_biometric_replay_accepts": residual_biometric_replay_accepts,
    }
