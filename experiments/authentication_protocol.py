"""Controlled authentication-attack protocol for the thesis study.

The protocol measures verifier outcomes; it never captures real credentials,
sends phishing content, or targets a service outside the local laboratory.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, List

from config.experiment_protocol import INTENSITY_ORDER, POLICY_ORDER, POLICY_SPECS


AUTH_ATTACK_ORDER = [
    "legitimate_control",
    "phishing_password_disclosed",
    "phishing_password_otp_disclosed",
    "credential_all_factors_disclosed",
    "bounded_dictionary_audit",
    "password_spray_audit",
    "credential_stuffing_audit",
    "otp_invalid_guess",
    "otp_expired",
    "otp_replay",
    "otp_cross_attempt",
    "biometric_impostor",
    "biometric_replay_without_liveness",
    "biometric_probe_corruption",
]

AUTH_ATTACK_SPECS: Dict[str, Dict[str, Any]] = {
    "legitimate_control": {
        "family": "control",
        "label": "Legitimate authentication",
        "password": "valid", "otp": "valid", "biometric": "valid",
    },
    "phishing_password_disclosed": {
        "family": "phishing_consequence",
        "label": "Password disclosed by a controlled phishing consequence",
        "password": "valid", "otp": "missing", "biometric": "missing",
    },
    "phishing_password_otp_disclosed": {
        "family": "phishing_consequence",
        "label": "Password and current OTP disclosed",
        "password": "valid", "otp": "valid", "biometric": "missing",
    },
    "credential_all_factors_disclosed": {
        "family": "credential_compromise",
        "label": "All implemented factors disclosed",
        "password": "valid", "otp": "valid", "biometric": "valid",
    },
    "bounded_dictionary_audit": {
        "family": "password_resistance",
        "label": "Bounded dictionary audit against synthetic credentials",
        # Non-target factors are valid so this row isolates the password
        # verifier. Partial-factor compromise is measured separately below.
        "password": "bounded_audit", "otp": "valid", "biometric": "valid",
    },
    "password_spray_audit": {
        "family": "password_resistance",
        "label": "Bounded password-spray audit against synthetic accounts",
        "password": "bounded_audit", "otp": "valid", "biometric": "valid",
    },
    "credential_stuffing_audit": {
        "family": "password_resistance",
        "label": "Bounded credential-stuffing audit using synthetic pairs",
        "password": "bounded_audit", "otp": "valid", "biometric": "valid",
    },
    "otp_invalid_guess": {
        "family": "otp_resistance",
        "label": "Invalid OTP guess",
        "password": "valid", "otp": "invalid", "biometric": "valid",
    },
    "otp_expired": {
        "family": "otp_resistance",
        "label": "Expired OTP",
        "password": "valid", "otp": "expired", "biometric": "valid",
    },
    "otp_replay": {
        "family": "otp_resistance",
        "label": "Previously consumed OTP replay",
        "password": "valid", "otp": "replay", "biometric": "valid",
    },
    "otp_cross_attempt": {
        "family": "otp_resistance",
        "label": "OTP submitted in a different authentication attempt",
        "password": "valid", "otp": "cross_attempt", "biometric": "valid",
    },
    "biometric_impostor": {
        "family": "biometric_resistance",
        "label": "Impostor feature-vector probe",
        "password": "valid", "otp": "valid", "biometric": "impostor",
    },
    "biometric_replay_without_liveness": {
        "family": "biometric_resistance",
        "label": "Captured simulated feature replay (no liveness control)",
        "password": "valid", "otp": "valid", "biometric": "replay",
    },
    "biometric_probe_corruption": {
        "family": "biometric_resistance",
        "label": "Malformed or corrupted simulated feature probe",
        "password": "valid", "otp": "valid", "biometric": "corrupt",
    },
}

AUTH_GUESS_BUDGETS = {"low": 5, "medium": 25, "high": 100}
AUTH_PRESENTATION_BUDGETS = {"low": 1, "medium": 3, "high": 5}


@dataclass(frozen=True)
class AuthenticationObservationPlan:
    block_id: str
    observation_id: str
    attack_variant: str
    attack_family: str
    intensity: str
    repetition: int
    policy: str
    policy_position: int
    user_ordinal: int
    expected_success: bool
    factor_state: Dict[str, str]
    guess_budget: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def expected_policy_outcome(policy: str, factor_state: Dict[str, str]) -> bool:
    valid_states = {
        "password": {"valid", "audit_hit"},
        "otp": {"valid"},
        # Replay is intentionally accepted by the matcher because this
        # software simulation does not claim liveness detection.
        "biometric": {"valid", "replay"},
    }
    return all(
        factor_state.get(factor, "missing") in valid_states[factor]
        for factor in POLICY_SPECS[policy]["factor_keys"]
    )


def build_authentication_plan(
    *, base_seed: int, repetitions: int = 5, user_count: int = 500
) -> List[AuthenticationObservationPlan]:
    if not 1 <= int(repetitions) <= 30:
        raise ValueError("Repetitions must be between 1 and 30")
    block_count = len(AUTH_ATTACK_ORDER) * len(INTENSITY_ORDER) * int(repetitions)
    if int(user_count) < block_count:
        raise ValueError(
            "At least %s experiment users are required so attack blocks remain isolated"
            % block_count
        )
    plans: List[AuthenticationObservationPlan] = []
    ordinal = 0
    for repetition in range(1, int(repetitions) + 1):
        for attack_variant in AUTH_ATTACK_ORDER:
            spec = AUTH_ATTACK_SPECS[attack_variant]
            for intensity in INTENSITY_ORDER:
                block_key = "%s|%s|%s|%s" % (
                    int(base_seed), attack_variant, intensity, repetition
                )
                block_id = str(uuid.uuid5(uuid.NAMESPACE_URL, block_key))
                seed = int.from_bytes(
                    hashlib.sha256(block_key.encode("utf-8")).digest()[:8], "big"
                )
                rng = random.Random(seed)
                policy_order = list(POLICY_ORDER)
                rng.shuffle(policy_order)
                factor_state = {
                    "password": str(spec["password"]),
                    "otp": str(spec["otp"]),
                    "biometric": str(spec["biometric"]),
                }
                for position, policy in enumerate(policy_order, start=1):
                    observation_key = "%s|%s|%s" % (block_id, policy, position)
                    plans.append(
                        AuthenticationObservationPlan(
                            block_id=block_id,
                            observation_id=str(
                                uuid.uuid5(uuid.NAMESPACE_URL, observation_key)
                            ),
                            attack_variant=attack_variant,
                            attack_family=str(spec["family"]),
                            intensity=intensity,
                            repetition=repetition,
                            policy=policy,
                            policy_position=position,
                            user_ordinal=ordinal,
                            expected_success=expected_policy_outcome(
                                policy, factor_state
                            ),
                            factor_state=dict(factor_state),
                            guess_budget=AUTH_GUESS_BUDGETS[intensity],
                        )
                    )
                ordinal += 1
    return plans
