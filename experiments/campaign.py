"""Deterministic, paired experiment campaign generation.

Randomness is limited to declared input ranges. A sampled input is reused for
all four policies, while policy order is shuffled within each block. This is a
randomized complete-block design: policy comparisons are not confounded by a
different traffic draw.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import sys
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root_text = str(PROJECT_ROOT)
while project_root_text in sys.path:
    sys.path.remove(project_root_text)
sys.path.insert(0, project_root_text)

from config.experiment_protocol import (
    AUTHORIZATION_TTL_SECONDS,
    AVAILABILITY_DEGRADATION_MARGIN,
    BINDING_ORDER,
    BINDING_SPECS,
    CONTROL_PROBE_COUNT,
    DEFAULT_BINDING_PROFILE,
    DEFAULT_REPETITIONS,
    FLOOD_INTENSITY_RANGES,
    IMPLEMENTATION_REVISION,
    INTENSITY_ORDER,
    MAX_RATE_ACHIEVEMENT_PERCENT,
    MIN_CONTROL_AVAILABILITY,
    MIN_RATE_ACHIEVEMENT_PERCENT,
    POLICY_ORDER,
    PROTOCOL_ID,
    PROTOCOL_SCHEMA_VERSION,
    PROTECTED_HOST,
    PROTECTED_PORT,
    REFERENCE_LINK_CAPACITY_MBPS,
    SCENARIO_SPECS,
    DISPLAY_SCENARIO_ORDER,
    intensity_ranges,
    offered_load_ratio,
    protocol_parameter_errors,
)
from config.topology_profiles import DEFAULT_TOPOLOGY, TOPOLOGY_PROFILES


@dataclass(frozen=True)
class CampaignTask:
    campaign_id: str
    task_id: str
    sample_id: str
    scenario: str
    intensity: str
    repetition: int
    policy: str
    policy_position: int
    binding_profile: str
    topology_id: str
    parameters: Dict[str, Any]


@dataclass
class CampaignManifest:
    schema_version: int
    protocol_id: str
    campaign_id: str
    created_at_utc: str
    seed: int
    scenario: str
    topology_id: str
    binding_profile: str
    repetitions: int
    design: str
    protocol_parameters: Dict[str, Any]
    tasks: List[CampaignTask]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["manifest_sha256"] = manifest_digest(payload)
        return payload

    def write_json(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        temporary.replace(path)
        return path


def manifest_digest(payload: Dict[str, Any]) -> str:
    digest_payload = dict(payload)
    digest_payload.pop("manifest_sha256", None)
    # Creation time is provenance rather than an experimental-design input.
    # Excluding it lets an interrupted campaign be resumed with the same
    # protocol, seed, topology, scenario, and repetition count.
    digest_payload.pop("created_at_utc", None)
    encoded = json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _bounded_int(rng: random.Random, bounds: Iterable[Any]) -> int:
    lower, upper = [int(value) for value in bounds]
    return rng.randint(lower, upper)


def _sample_parameters(scenario: str, intensity: str, rng: random.Random) -> Dict[str, Any]:
    spec = SCENARIO_SPECS[scenario]
    ranges = intensity_ranges(scenario, intensity)
    duration = _bounded_int(rng, ranges["duration_seconds"])
    source_count = int(spec["source_count"])
    if spec["parameter_family"] == "access":
        rate = _bounded_int(rng, ranges["rate_pps"])
        request_lower, request_upper = [int(value) for value in ranges["request_count"]]
        feasible_upper = min(request_upper, duration * rate)
        request_count = rng.randint(request_lower, max(request_lower, feasible_upper))
        return {
            "target_host": PROTECTED_HOST,
            "target_port": PROTECTED_PORT,
            "duration_seconds": duration,
            "rate_pps": rate,
            "request_count": request_count,
            "worker_count": source_count,
            "source_count": source_count,
            "payload_size_bytes": None,
            "offered_load_ratio": None,
        }

    payload = _bounded_int(rng, ranges["payload_size_bytes"])
    lower_ratio, upper_ratio = [float(value) for value in ranges["offered_load_ratio"]]
    sampled_ratio = rng.uniform(lower_ratio, upper_ratio)
    bits_per_packet = (payload + 28) * 8
    packets_per_second_scale = (
        REFERENCE_LINK_CAPACITY_MBPS * 1_000_000.0 / bits_per_packet
    )
    minimum_rate = max(1, int(math.ceil(lower_ratio * packets_per_second_scale)))
    maximum_rate = max(minimum_rate, int(math.floor(upper_ratio * packets_per_second_scale)))
    sampled_rate = int(round(sampled_ratio * packets_per_second_scale))
    rate = min(maximum_rate, max(minimum_rate, sampled_rate))
    actual_ratio = offered_load_ratio(rate, payload)
    return {
        "target_host": PROTECTED_HOST,
        "target_port": PROTECTED_PORT,
        "duration_seconds": duration,
        "rate_pps": rate,
        "request_count": None,
        "worker_count": source_count,
        "source_count": source_count,
        "payload_size_bytes": payload,
        "offered_load_ratio": round(actual_ratio, 6),
    }


def build_campaign(
    scenario: str,
    *,
    seed: int,
    repetitions: int = DEFAULT_REPETITIONS,
    topology_id: str = DEFAULT_TOPOLOGY,
    binding_profile: str = DEFAULT_BINDING_PROFILE,
    created_at_utc: Optional[str] = None,
) -> CampaignManifest:
    if scenario not in SCENARIO_SPECS:
        raise ValueError("Unknown scenario: %s" % scenario)
    if topology_id not in TOPOLOGY_PROFILES:
        raise ValueError("Unknown topology: %s" % topology_id)
    if binding_profile not in BINDING_SPECS:
        raise ValueError("Unknown binding profile: %s" % binding_profile)
    if not 1 <= int(repetitions) <= 30:
        raise ValueError("Repetitions must be between 1 and 30")
    if not isinstance(seed, int) or isinstance(seed, bool) or not 0 <= seed <= 2**63 - 1:
        raise ValueError("Seed must be an integer between 0 and 2^63-1")

    campaign_key = "%s|%s|%s|%s|%s|%s|%s" % (
        PROTOCOL_ID,
        IMPLEMENTATION_REVISION,
        scenario,
        seed,
        repetitions,
        topology_id,
        binding_profile,
    )
    campaign_id = str(uuid.uuid5(uuid.NAMESPACE_URL, campaign_key))
    rng = random.Random(seed)
    tasks: List[CampaignTask] = []
    for repetition in range(1, int(repetitions) + 1):
        for intensity in INTENSITY_ORDER:
            parameters = _sample_parameters(scenario, intensity, rng)
            errors = protocol_parameter_errors(
                scenario,
                duration_seconds=parameters["duration_seconds"],
                rate_pps=parameters["rate_pps"],
                worker_count=parameters["worker_count"],
                payload_size_bytes=parameters["payload_size_bytes"],
                target_host=parameters["target_host"],
                target_port=parameters["target_port"],
                intensity_level=intensity,
                request_count=parameters["request_count"],
                source_count=parameters["source_count"],
            )
            if errors:
                raise RuntimeError("Generated parameters violate protocol: %s" % ", ".join(errors))
            # The sample identifier is deliberately independent of the binding
            # campaign.  All 16 policy-by-binding observations in the same
            # topology/scenario/intensity/repetition block therefore share the
            # same sampled traffic and pairing key.
            sample_key = "%s|%s|%s|%s|%s|%s|%s" % (
                PROTOCOL_ID,
                IMPLEMENTATION_REVISION,
                seed,
                topology_id,
                scenario,
                repetition,
                intensity,
            )
            sample_id = str(uuid.uuid5(uuid.NAMESPACE_URL, sample_key))
            policy_order = list(POLICY_ORDER)
            rng.shuffle(policy_order)
            for position, policy in enumerate(policy_order, start=1):
                # Task UUIDs remain unique after sample IDs are paired across
                # bindings by including the data-plane profile explicitly.
                task_key = "%s|%s|%s|%s" % (
                    sample_id, binding_profile, policy, position
                )
                tasks.append(
                    CampaignTask(
                        campaign_id=campaign_id,
                        task_id=str(uuid.uuid5(uuid.NAMESPACE_URL, task_key)),
                        sample_id=sample_id,
                        scenario=scenario,
                        intensity=intensity,
                        repetition=repetition,
                        policy=policy,
                        policy_position=position,
                        binding_profile=binding_profile,
                        topology_id=topology_id,
                        parameters=dict(parameters),
                    )
                )

    manifest = CampaignManifest(
        schema_version=PROTOCOL_SCHEMA_VERSION,
        protocol_id=PROTOCOL_ID,
        campaign_id=campaign_id,
        created_at_utc=created_at_utc or datetime.now(timezone.utc).isoformat(),
        seed=seed,
        scenario=scenario,
        topology_id=topology_id,
        binding_profile=binding_profile,
        repetitions=int(repetitions),
        design="randomized_complete_block_paired_inputs",
        protocol_parameters={
            "implementation_revision": IMPLEMENTATION_REVISION,
            "protected_target": "%s:%s" % (PROTECTED_HOST, PROTECTED_PORT),
            "reference_link_capacity_mbps": REFERENCE_LINK_CAPACITY_MBPS,
            "authorization_ttl_seconds": AUTHORIZATION_TTL_SECONDS,
            "policy_order": list(POLICY_ORDER),
            "common_binding_profile": binding_profile,
            "declared_intensity_ranges": {
                intensity: intensity_ranges(scenario, intensity)
                for intensity in INTENSITY_ORDER
            },
            "control_probe_count": CONTROL_PROBE_COUNT,
            "minimum_control_availability": MIN_CONTROL_AVAILABILITY,
            "availability_degradation_margin": AVAILABILITY_DEGRADATION_MARGIN,
            "accepted_rate_achievement_percent": [
                MIN_RATE_ACHIEVEMENT_PERCENT,
                MAX_RATE_ACHIEVEMENT_PERCENT,
            ],
        },
        tasks=tasks,
    )
    validation_errors = validate_campaign(manifest)
    if validation_errors:
        raise RuntimeError("Invalid generated campaign: %s" % ", ".join(validation_errors))
    return manifest


def _derived_campaign_seed(
    base_seed: int, topology_id: str, binding_profile: str, scenario: str
) -> int:
    """Derive a reproducible seed paired across all four bindings.

    ``binding_profile`` remains in the signature to make the pairing decision
    explicit, but it is intentionally excluded from the seed material.
    """
    if binding_profile not in BINDING_SPECS:
        raise ValueError("Unknown binding profile: %s" % binding_profile)
    material = "%s|%s|%s|%s" % (
        PROTOCOL_ID,
        int(base_seed),
        topology_id,
        scenario,
    )
    return int.from_bytes(hashlib.sha256(material.encode("utf-8")).digest()[:8], "big") & (
        2**63 - 1
    )


def build_thesis_suite(
    *,
    topology_id: str,
    base_seed: int,
    repetitions: int = DEFAULT_REPETITIONS,
    created_at_utc: Optional[str] = None,
) -> List[CampaignManifest]:
    """Build the complete 4-binding by 6-scenario suite for one topology.

    Each campaign remains a randomized complete-block comparison of the four
    MFA policies.  Crossing campaigns adds the binding dimension without
    conflating a network identity check with an authentication factor.
    """
    if topology_id not in TOPOLOGY_PROFILES:
        raise ValueError("Unknown topology: %s" % topology_id)
    if not isinstance(base_seed, int) or isinstance(base_seed, bool):
        raise ValueError("Base seed must be an integer")
    manifests: List[CampaignManifest] = []
    for binding_profile in BINDING_ORDER:
        for scenario in DISPLAY_SCENARIO_ORDER:
            manifests.append(
                build_campaign(
                    scenario,
                    seed=_derived_campaign_seed(
                        base_seed, topology_id, binding_profile, scenario
                    ),
                    repetitions=repetitions,
                    topology_id=topology_id,
                    binding_profile=binding_profile,
                    created_at_utc=created_at_utc,
                )
            )
    return manifests


def validate_campaign(manifest: CampaignManifest) -> List[str]:
    errors: List[str] = []
    if not manifest.protocol_parameters:
        errors.append("missing_protocol_parameters")
    expected_task_count = manifest.repetitions * len(INTENSITY_ORDER) * len(POLICY_ORDER)
    if len(manifest.tasks) != expected_task_count:
        errors.append("unexpected_task_count")
    task_ids = [task.task_id for task in manifest.tasks]
    if len(task_ids) != len(set(task_ids)):
        errors.append("duplicate_task_id")
    blocks: Dict[str, List[CampaignTask]] = {}
    for task in manifest.tasks:
        blocks.setdefault(task.sample_id, []).append(task)
    for tasks in blocks.values():
        if sorted(task.policy for task in tasks) != sorted(POLICY_ORDER):
            errors.append("incomplete_policy_block")
        parameter_signatures = {
            json.dumps(task.parameters, sort_keys=True, separators=(",", ":")) for task in tasks
        }
        if len(parameter_signatures) != 1:
            errors.append("unpaired_parameters")
        if sorted(task.policy_position for task in tasks) != list(range(1, len(POLICY_ORDER) + 1)):
            errors.append("invalid_policy_positions")
    return sorted(set(errors))
