"""Measured factor-availability study using the real MFA verifier."""

from __future__ import annotations

import json
import time
import uuid
from collections import Counter
from typing import Any, Dict, List, Optional

try:
    import psutil
except ImportError:  # preflight rejects the environment before a campaign
    psutil = None

from config.experiment_protocol import (
    AUTH_SCENARIO_ORDER,
    AUTH_SCENARIO_SPECS,
    POLICY_ORDER,
    POLICY_SELECTION,
    POLICY_SPECS,
)


def run_factor_availability_study(
    *,
    campaign_id: str,
    username: str,
    password: str,
    biometric_sample: str,
    repetitions: int,
) -> Dict[str, Any]:
    """Exercise real verifier paths with controlled factor availability.

    Valid secrets are held only in process memory. Database evidence records
    factor names and outcomes, never passwords, OTP values, or biometric input.
    """
    from database.db_config import get_db_connection, release_db_connection
    from otp.otp_service import generate_otp, store_otp
    from security.mfa_manager import authenticate_user

    policy_keys = {mode: key for key, mode in POLICY_SELECTION.items()}
    if psutil is None:
        raise RuntimeError("psutil is required for authentication resource measurement")
    process = psutil.Process()
    observations: List[Dict[str, Any]] = []
    for repetition in range(1, int(repetitions) + 1):
        for scenario in AUTH_SCENARIO_ORDER:
            available = set(AUTH_SCENARIO_SPECS[scenario]["available_factors"])
            for mode in POLICY_ORDER:
                required = set(POLICY_SPECS[mode]["factor_keys"])
                run_id = str(uuid.uuid4())
                attempt_id = str(uuid.uuid4())
                otp_code: Optional[str] = None
                if "otp" in required and "otp" in available:
                    otp_code = generate_otp()
                    stored, message = store_otp(
                        username,
                        otp_code,
                        run_id=run_id,
                        attempt_id=attempt_id,
                    )
                    if not stored:
                        raise RuntimeError("Could not stage OTP factor: %s" % message)
                biometric = (
                    biometric_sample
                    if "biometric" in required and "biometric" in available
                    else None
                )
                cpu_before = process.cpu_times()
                rss_before = process.memory_info().rss
                started = time.perf_counter()
                success, message = authenticate_user(
                    username=username,
                    password=password,
                    otp_code=otp_code,
                    biometric_data=biometric,
                    policy_key=policy_keys[mode],
                    run_id=run_id,
                    attempt_id=attempt_id,
                )
                latency_ms = (time.perf_counter() - started) * 1000.0
                cpu_after = process.cpu_times()
                rss_after = process.memory_info().rss
                cpu_seconds = max(
                    0.0,
                    (cpu_after.user + cpu_after.system)
                    - (cpu_before.user + cpu_before.system),
                )
                wall_seconds = max(latency_ms / 1000.0, 0.000001)
                resource_metrics = {
                    "process_pid": int(process.pid),
                    "process_label": "mfa_verifier",
                    "cpu_seconds": round(cpu_seconds, 6),
                    "cpu_percent_equivalent": round(
                        100.0 * cpu_seconds / wall_seconds,
                        3,
                    ),
                    "rss_before_bytes": int(rss_before),
                    "rss_after_bytes": int(rss_after),
                    "rss_delta_bytes": int(rss_after - rss_before),
                }
                supplied = sorted(required & available)
                expected_success = required.issubset(available)
                if bool(success) != expected_success:
                    raise RuntimeError(
                        "MFA verifier did not conform to the declared factor-availability control "
                        "for %s / %s" % (scenario, mode)
                    )
                observation = {
                    "run_id": run_id,
                    "scenario": scenario,
                    "mfa_mode": mode,
                    "repetition": repetition,
                    "required_factors": sorted(required),
                    "supplied_factors": supplied,
                    "authentication_succeeded": bool(success),
                    "latency_ms": round(latency_ms, 3),
                    "resource_metrics": resource_metrics,
                    "message": str(message),
                }
                conn = get_db_connection()
                if conn is None:
                    raise RuntimeError("Database connection is unavailable")
                try:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO authentication_experiment_logs (
                                campaign_id, run_id, username, scenario, mfa_mode,
                                repetition, supplied_factors, authentication_succeeded,
                                latency_ms, resource_metrics, message
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb, %s)
                            ON CONFLICT (campaign_id, scenario, mfa_mode, repetition)
                            DO UPDATE SET
                                run_id = EXCLUDED.run_id,
                                supplied_factors = EXCLUDED.supplied_factors,
                                authentication_succeeded = EXCLUDED.authentication_succeeded,
                                latency_ms = EXCLUDED.latency_ms,
                                resource_metrics = EXCLUDED.resource_metrics,
                                message = EXCLUDED.message,
                                created_at = CURRENT_TIMESTAMP
                            """,
                            (
                                campaign_id,
                                run_id,
                                username,
                                scenario,
                                mode,
                                repetition,
                                json.dumps(
                                    {
                                        "required": sorted(required),
                                        "supplied": supplied,
                                        "simulation": "software_factor_availability",
                                    },
                                    sort_keys=True,
                                ),
                                bool(success),
                                latency_ms,
                                json.dumps(resource_metrics, sort_keys=True),
                                str(message),
                            ),
                        )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                finally:
                    release_db_connection(conn)
                observations.append(observation)

    successes = Counter(
        (row["scenario"], row["mfa_mode"])
        for row in observations
        if row["authentication_succeeded"]
    )
    return {
        "observation_count": len(observations),
        "repetitions": repetitions,
        "success_cells": {
            "%s|%s" % key: value for key, value in sorted(successes.items())
        },
    }
