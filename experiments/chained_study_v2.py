"""Execute the end-to-end authentication, authorization, and network study."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.experiment_protocol import POLICY_SPECS
from controller.mfa_controller import MFAController, _authorize_user, _ryu_request
from experiments.authentication_protocol import AuthenticationObservationPlan
from experiments.authentication_study_v2 import execute_authentication_observation
from experiments.chained_protocol import (
    ChainedTask,
    build_chained_plan,
    expected_chained_runs_per_topology,
)
from experiments.chained_storage import ChainedStore
from experiments.metrics import PacketCapture, ResourceSampler
from experiments.synthetic_users import ExperimentUser


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AVAILABILITY_SCENARIOS = {"dos_udp_flood", "ddos_udp_flood"}


def _legitimate_control_plan(task: ChainedTask, run_id: str) -> AuthenticationObservationPlan:
    return AuthenticationObservationPlan(
        block_id=task.block_id,
        observation_id=run_id,
        attack_variant="legitimate_control",
        attack_family="control",
        intensity=task.intensity,
        repetition=task.repetition,
        policy=task.policy,
        policy_position=task.auth_plan.policy_position,
        user_ordinal=task.user_ordinal,
        expected_success=True,
        factor_state={"password": "valid", "otp": "valid", "biometric": "valid"},
        guess_budget=task.auth_plan.guess_budget,
    )


def _chain_outcome(network_security_outcome: str) -> str:
    if network_security_outcome == "attack_success":
        return "attack_succeeded_end_to_end"
    if network_security_outcome == "availability_degraded":
        return "service_degraded"
    if network_security_outcome in {"attack_blocked", "availability_preserved"}:
        return "contained_after_admission"
    return "not_evaluable"


def _execute_network_stage(
    *,
    controller: MFAController,
    task: ChainedTask,
    profile: ExperimentUser,
    authentication: Dict[str, Any],
    authorization: Dict[str, Any],
    controller_pid: int,
    capture_pcap: bool,
) -> Dict[str, Any]:
    pcap: Optional[PacketCapture] = None
    pcap_evidence: Dict[str, Any] = {"enabled": False}
    if capture_pcap:
        pcap_path = (
            PROJECT_ROOT / "evidence" / "pcap" / "chained"
            / task.topology_id / (task.chain_id + ".pcap")
        )
        from controller.mfa_controller import _load_mininet_ctx

        mn = _load_mininet_ctx()
        pcap = PacketCapture(
            int(mn["h2"]["pid"]),
            pcap_path,
            str(task.network_parameters["target_host"]),
            int(task.network_parameters["target_port"]),
        ).start()

    sampler = ResourceSampler(
        interval_seconds=0.2,
        pid=controller_pid,
        process_label="ryu_controller",
    ).start()
    result = None
    try:
        parameters = task.network_parameters
        result = controller.execute_attack(
            username=profile.username,
            attack_type=task.network_scenario,
            target_host=str(parameters["target_host"]),
            target_port=int(parameters["target_port"]),
            duration_s=int(parameters["duration_seconds"]),
            rate_pps=int(parameters["rate_pps"]),
            threads=int(parameters["worker_count"]),
            payload_size_bytes=parameters.get("payload_size_bytes"),
            mfa_mode=task.policy,
            run_id=str(authentication["run_id"]),
            attempt_id=str(authentication["attempt_id"]),
            authorization_context=authorization,
            task_id=task.chain_id,
            sample_id=task.block_id,
            repetition=task.repetition,
            intensity_level=task.intensity,
            binding_profile=task.binding_profile,
            topology_id=task.topology_id,
            request_count=parameters.get("request_count"),
            source_count=parameters.get("source_count"),
        )
    finally:
        resource_metrics = sampler.stop()
        if pcap is not None:
            pcap_evidence = pcap.stop()
    if result is None:
        raise RuntimeError("Network scenario returned no result")
    serialized = controller._safe_json(result)
    metrics = serialized.get("metrics") if isinstance(serialized, dict) else {}
    if not isinstance(metrics, dict):
        metrics = {}
    return {
        "result": serialized,
        "metrics": metrics,
        "resource_metrics": resource_metrics,
        "pcap_evidence": pcap_evidence,
    }


def run_chained_study(
    *,
    study_id: str,
    topology_id: str,
    base_seed: int,
    repetitions: int,
    users: List[ExperimentUser],
    mn: Dict[str, Any],
    capture_pcap: bool = False,
    cooldown_seconds: float = 0.2,
    progress_every: int = 25,
) -> Dict[str, Any]:
    """Run or resume the 11,520-cell chained matrix for one topology."""
    uuid.UUID(str(study_id))
    if str(mn.get("topology_id") or "") != topology_id:
        raise RuntimeError("The active Mininet topology does not match the chain plan")
    tasks = build_chained_plan(
        topology_id=topology_id,
        base_seed=base_seed,
        repetitions=repetitions,
        user_count=len(users),
    )
    expected = expected_chained_runs_per_topology(repetitions)
    if len(tasks) != expected:
        raise RuntimeError("The chained plan has an unexpected task count")

    store = ChainedStore()
    completed = store.completed_ids(study_id, topology_id)
    controller = MFAController()
    completed_now = 0
    skipped = 0
    technical_errors = 0
    blocked_at_authentication = 0
    admitted_to_network = 0

    for index, task in enumerate(tasks, start=1):
        if task.chain_id in completed:
            skipped += 1
            continue
        reset_ok, reset_payload = _ryu_request("/sdnmfa/reset", "POST", {})
        if not reset_ok:
            raise RuntimeError("Controller state reset failed: %s" % reset_payload)
        status_ok, status_payload = _ryu_request("/sdnmfa/status", "GET")
        try:
            controller_pid = int(status_payload.get("controller_pid"))
        except (TypeError, ValueError):
            controller_pid = 0
        if not status_ok or controller_pid <= 0:
            raise RuntimeError("Controller process identity is unavailable")

        profile = users[task.user_ordinal]
        authentication = execute_authentication_observation(
            profile=profile,
            plan=task.auth_plan,
            users=users,
            run_id=task.chain_id,
            reset_state=True,
        )
        network_stage_status = "not_admitted"
        network_result: Dict[str, Any] = {
            "reason": "authentication_denied",
            "security_outcome": "blocked_at_authentication",
        }
        network_resources: Dict[str, Any] = {}
        pcap_evidence: Dict[str, Any] = {"enabled": False}
        chain_outcome = "blocked_at_authentication"
        execution_status = "completed"
        is_valid = True

        try:
            authorization_auth = authentication
            if not authentication["success"] and task.network_scenario in AVAILABILITY_SCENARIOS:
                control_run_id = str(
                    uuid.uuid5(uuid.UUID(task.chain_id), "availability-control")
                )
                control_plan = _legitimate_control_plan(task, control_run_id)
                authorization_auth = execute_authentication_observation(
                    profile=profile,
                    plan=control_plan,
                    users=users,
                    run_id=control_run_id,
                    reset_state=True,
                )
                if not authorization_auth["success"]:
                    raise RuntimeError("Legitimate availability control could not authenticate")
                network_stage_status = "external_threat_controlled"

            should_execute_network = bool(authentication["success"]) or (
                task.network_scenario in AVAILABILITY_SCENARIOS
            )
            if should_execute_network:
                authorization = _authorize_user(
                    mn,
                    task.policy,
                    task.binding_profile,
                    run_id=authorization_auth["run_id"],
                    attempt_id=authorization_auth["attempt_id"],
                )
                stage = _execute_network_stage(
                    controller=controller,
                    task=task,
                    profile=profile,
                    authentication=authorization_auth,
                    authorization=authorization,
                    controller_pid=controller_pid,
                    capture_pcap=capture_pcap,
                )
                network_result = stage["result"]
                network_resources = stage["resource_metrics"]
                pcap_evidence = stage["pcap_evidence"]
                metrics = stage["metrics"]
                if network_stage_status != "external_threat_controlled":
                    network_stage_status = "completed"
                if not metrics.get("is_valid"):
                    network_stage_status = "technical_error"
                    chain_outcome = "not_evaluable"
                    execution_status = "technical_error"
                    is_valid = False
                    technical_errors += 1
                else:
                    chain_outcome = _chain_outcome(
                        str(metrics.get("security_outcome") or "")
                    )
                admitted_to_network += 1
            else:
                blocked_at_authentication += 1
        except Exception as exc:
            network_stage_status = "technical_error"
            network_result = {"error": str(exc), "security_outcome": "not_evaluable"}
            chain_outcome = "not_evaluable"
            execution_status = "technical_error"
            is_valid = False
            technical_errors += 1
        finally:
            _ryu_request(
                "/sdnmfa/revoke", "POST", {"src_ip": str(mn["h1"]["ip"])}
            )

        store.save(
            study_id=study_id,
            task=task,
            username=profile.username,
            authentication=authentication,
            network_stage_status=network_stage_status,
            network_result=network_result,
            resource_metrics=network_resources,
            pcap_evidence=pcap_evidence,
            chain_outcome=chain_outcome,
            execution_status=execution_status,
            is_valid=is_valid,
        )
        completed_now += 1
        if progress_every and completed_now % int(progress_every) == 0:
            print(
                "Chained study: %s/%s processed in this run (%s resumed)"
                % (completed_now, expected - skipped, skipped)
            )
        if cooldown_seconds > 0 and index < len(tasks):
            time.sleep(min(10.0, float(cooldown_seconds)))

    progress = store.progress(study_id, topology_id, expected)
    progress.update(
        {
            "study_id": study_id,
            "topology_id": topology_id,
            "completed_now": completed_now,
            "skipped": skipped,
            "technical_errors_this_run": technical_errors,
            "blocked_at_authentication_this_run": blocked_at_authentication,
            "network_stages_this_run": admitted_to_network,
        }
    )
    return progress
