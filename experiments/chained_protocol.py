"""Deterministic end-to-end authentication-to-network experiment design."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, List

from config.experiment_protocol import DEFAULT_REPETITIONS
from experiments.authentication_protocol import (
    AUTH_ATTACK_SPECS,
    AUTH_GUESS_BUDGETS,
    AuthenticationObservationPlan,
    expected_policy_outcome,
)
from experiments.campaign import build_thesis_suite


CHAIN_PROTOCOL_ID = "sdnmfa-chain-v2"
CHAIN_AUTH_ATTACK_ORDER = (
    "phishing_password_disclosed",
    "phishing_password_otp_disclosed",
    "credential_all_factors_disclosed",
    "bounded_dictionary_audit",
    "otp_invalid_guess",
    "otp_replay",
    "biometric_impostor",
    "biometric_replay_without_liveness",
)


@dataclass(frozen=True)
class ChainedTask:
    chain_id: str
    block_id: str
    base_task_id: str
    auth_plan: AuthenticationObservationPlan
    topology_id: str
    binding_profile: str
    network_scenario: str
    intensity: str
    repetition: int
    policy: str
    user_ordinal: int
    network_parameters: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["protocol_id"] = CHAIN_PROTOCOL_ID
        return payload


def _stable_ordinal(material: str, user_count: int) -> int:
    digest = hashlib.sha256(material.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % int(user_count)


def build_chained_plan(
    *,
    topology_id: str,
    base_seed: int,
    repetitions: int = DEFAULT_REPETITIONS,
    user_count: int = 500,
) -> List[ChainedTask]:
    """Cross eight representative entry attacks with the network matrix.

    Authentication and network attack intensity share the same declared tier.
    This produces 11,520 planned chains per topology at five repetitions.
    """
    if int(user_count) < 1:
        raise ValueError("At least one synthetic experiment user is required")
    suite = build_thesis_suite(
        topology_id=topology_id,
        base_seed=int(base_seed),
        repetitions=int(repetitions),
    )
    tasks: List[ChainedTask] = []
    for manifest in suite:
        for network_task in manifest.tasks:
            for attack_variant in CHAIN_AUTH_ATTACK_ORDER:
                spec = AUTH_ATTACK_SPECS[attack_variant]
                block_material = "%s|%s|%s|%s|%s|%s" % (
                    CHAIN_PROTOCOL_ID,
                    int(base_seed),
                    topology_id,
                    network_task.scenario,
                    network_task.intensity,
                    network_task.repetition,
                )
                paired_material = "%s|%s" % (block_material, attack_variant)
                block_id = str(uuid.uuid5(uuid.NAMESPACE_URL, paired_material))
                chain_material = "%s|%s|%s" % (
                    paired_material,
                    network_task.binding_profile,
                    network_task.policy,
                )
                chain_id = str(uuid.uuid5(uuid.NAMESPACE_URL, chain_material))
                factor_state = {
                    key: str(spec[key])
                    for key in ("password", "otp", "biometric")
                }
                auth_plan = AuthenticationObservationPlan(
                    block_id=block_id,
                    observation_id=chain_id,
                    attack_variant=attack_variant,
                    attack_family=str(spec["family"]),
                    intensity=network_task.intensity,
                    repetition=network_task.repetition,
                    policy=network_task.policy,
                    policy_position=network_task.policy_position,
                    user_ordinal=_stable_ordinal(paired_material, user_count),
                    expected_success=expected_policy_outcome(
                        network_task.policy, factor_state
                    ),
                    factor_state=factor_state,
                    guess_budget=AUTH_GUESS_BUDGETS[network_task.intensity],
                )
                tasks.append(
                    ChainedTask(
                        chain_id=chain_id,
                        block_id=block_id,
                        base_task_id=network_task.task_id,
                        auth_plan=auth_plan,
                        topology_id=topology_id,
                        binding_profile=network_task.binding_profile,
                        network_scenario=network_task.scenario,
                        intensity=network_task.intensity,
                        repetition=network_task.repetition,
                        policy=network_task.policy,
                        user_ordinal=auth_plan.user_ordinal,
                        network_parameters=dict(network_task.parameters),
                    )
                )
    return tasks


def expected_chained_runs_per_topology(repetitions: int) -> int:
    return 8 * 4 * 4 * 6 * 3 * int(repetitions)
