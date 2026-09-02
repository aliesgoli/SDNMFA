#!/usr/bin/env python3
"""Generate an article-ready Persian report from measured v2 observations."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import statistics
import sys
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
while str(PROJECT_ROOT) in sys.path:
    sys.path.remove(str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT))
os.environ.setdefault("MPLCONFIGDIR", "/tmp/sdnmfa_matplotlib_v2")

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import PercentFormatter

from config.experiment_protocol import (
    BINDING_ORDER,
    DISPLAY_SCENARIO_ORDER,
    INTENSITY_ORDER,
    POLICY_ORDER,
    POLICY_SPECS,
)
from experiments.authentication_protocol import (
    AUTH_ATTACK_ORDER,
    AUTH_ATTACK_SPECS,
    expected_policy_outcome,
)
from experiments.study import THESIS_TOPOLOGIES
from experiments.chained_protocol import expected_chained_runs_per_topology


POLICY_LABELS = {
    "password_only": "Password",
    "password_otp": "Password + OTP",
    "password_biometric": "Password + Biometric",
    "password_otp_biometric": "Full MFA",
}
BINDING_LABELS = {
    "ip_only": "IP",
    "ip_mac": "IP + MAC",
    "ip_port": "IP + Port",
    "ip_mac_port": "IP + MAC + Port",
}
SCENARIO_LABELS = {
    "unauthorized_access": "Unauthorized",
    "ip_spoofing": "IP spoof",
    "ip_mac_spoofing": "IP+MAC spoof",
    "arp_mitm": "ARP/MITM",
    "dos_udp_flood": "DoS",
    "ddos_udp_flood": "DDoS",
}
INTENSITY_LABELS = {"low": "Low", "medium": "Medium", "high": "High"}
COLORS = {
    "password_only": "#C73645",
    "password_otp": "#E69F00",
    "password_biometric": "#009E73",
    "password_otp_biometric": "#2F5597",
}
POLICY_LINESTYLES = {
    "password_only": "-",
    "password_otp": "--",
    "password_biometric": "-.",
    "password_otp_biometric": ":",
}
POLICY_MARKERS = {
    "password_only": "o",
    "password_otp": "s",
    "password_biometric": "^",
    "password_otp_biometric": "D",
}
REPORT_QUERY_TIMEOUT_MS = 600_000


def _metric(row: Dict[str, Any], key: str, default: Any = None) -> Any:
    observed = row.get("observed_result") or {}
    if isinstance(observed, str):
        try:
            observed = json.loads(observed)
        except Exception:
            observed = {}
    metrics = observed.get("metrics") if isinstance(observed, dict) else {}
    return metrics.get(key, default) if isinstance(metrics, dict) else default


def _mean(values: Iterable[float]) -> Optional[float]:
    data = [float(value) for value in values if value is not None and math.isfinite(float(value))]
    return statistics.fmean(data) if data else None


def _std(values: Iterable[float]) -> Optional[float]:
    data = [float(value) for value in values if value is not None and math.isfinite(float(value))]
    return statistics.stdev(data) if len(data) > 1 else (0.0 if data else None)


def _wilson(successes: int, total: int) -> Tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0
    z = 1.96
    p = successes / total
    denominator = 1.0 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def _exact_mcnemar(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from discordant paired outcomes."""
    discordant = int(b) + int(c)
    if discordant <= 0:
        return 1.0
    tail = sum(
        math.comb(discordant, value)
        for value in range(0, min(int(b), int(c)) + 1)
    ) / (2.0 ** discordant)
    return min(1.0, 2.0 * tail)


def _holm_adjust(p_values: Sequence[float]) -> List[float]:
    indexed = sorted(enumerate(float(value) for value in p_values), key=lambda item: item[1])
    adjusted = [1.0] * len(indexed)
    running = 0.0
    count = len(indexed)
    for rank, (original_index, value) in enumerate(indexed):
        running = max(running, min(1.0, (count - rank) * value))
        adjusted[original_index] = running
    return adjusted


def _load_real(study_id: str) -> Dict[str, Any]:
    from database.db_config import get_db_connection, release_db_connection

    conn = get_db_connection()
    if conn is None:
        raise RuntimeError("Database connection is unavailable")
    try:
        with conn.cursor() as cur:
            # The pooled 30-second limit is suitable for interactive requests,
            # but a complete study report must read and order every measured run.
            cur.execute(
                "SELECT set_config('statement_timeout', %s, true)",
                (str(REPORT_QUERY_TIMEOUT_MS),),
            )
            cur.execute(
                """
                SELECT study_id, protocol_id, implementation_revision, base_seed,
                       repetitions, expected_topologies, design_config, status,
                       created_at, completed_at
                FROM thesis_studies WHERE study_id=%s
                """,
                (study_id,),
            )
            study_row = cur.fetchone()
            if not study_row:
                raise RuntimeError("Study was not found: %s" % study_id)
            study = {
                "study_id": str(study_row[0]), "protocol_id": study_row[1],
                "implementation_revision": study_row[2], "base_seed": int(study_row[3]),
                "repetitions": int(study_row[4]), "expected_topologies": study_row[5],
                "design_config": study_row[6], "status": study_row[7],
                "created_at": study_row[8], "completed_at": study_row[9],
                "data_status": "MEASURED",
            }
            cur.execute(
                """
                SELECT r.task_id, r.campaign_id, r.sample_id, r.run_id,
                       r.experiment_username, r.scenario, r.intensity_level,
                       r.repetition, r.policy_position, r.mfa_mode,
                       r.binding_profile, r.topology_id, r.sampled_parameters,
                       r.observed_result, r.resource_metrics, r.pcap_evidence,
                       r.execution_status, r.is_valid, r.started_at, r.completed_at
                FROM experiment_runs r
                JOIN experiment_campaigns c ON c.campaign_id=r.campaign_id
                WHERE c.study_id=%s ORDER BY r.topology_id, r.scenario,
                    r.binding_profile, r.repetition, r.intensity_level, r.policy_position
                """,
                (study_id,),
            )
            names = [item.name for item in cur.description]
            network = [dict(zip(names, row)) for row in cur.fetchall()]
            cur.execute(
                """
                SELECT run_id, username, scenario, attack_family, attack_variant,
                       intensity_level, mfa_mode, repetition, supplied_factors,
                       authentication_succeeded, expected_success, biometric_score,
                       biometric_threshold, is_valid, latency_ms, resource_metrics,
                       message, created_at
                FROM authentication_experiment_logs
                WHERE study_id=%s
                ORDER BY attack_family, attack_variant, intensity_level,
                    repetition, mfa_mode
                """,
                (study_id,),
            )
            auth_names = [item.name for item in cur.description]
            authentication = [dict(zip(auth_names, row)) for row in cur.fetchall()]
            cur.execute(
                """
                SELECT chain_id, block_id, base_task_id, run_id,
                       experiment_username, auth_attack_variant,
                       intensity_level, mfa_mode, binding_profile,
                       network_scenario, topology_id, repetition,
                       sampled_parameters, factor_state,
                       authentication_succeeded,
                       expected_authentication_success,
                       authentication_latency_ms, authentication_metrics,
                       network_stage_status, network_result, resource_metrics,
                       pcap_evidence, chain_outcome, execution_status,
                       is_valid, started_at, completed_at
                FROM chained_experiment_runs
                WHERE study_id=%s
                ORDER BY topology_id, network_scenario, auth_attack_variant,
                    intensity_level, repetition, binding_profile, mfa_mode
                """,
                (study_id,),
            )
            chain_names = [item.name for item in cur.description]
            chained = [dict(zip(chain_names, row)) for row in cur.fetchall()]
        return {
            "study": study,
            "network": network,
            "authentication": authentication,
            "chained": chained,
        }
    finally:
        release_db_connection(conn)


def _demo_data() -> Dict[str, Any]:
    """Deterministic illustrative data used only for layout verification."""
    rng = random.Random(20260822)
    network: List[Dict[str, Any]] = []
    access = DISPLAY_SCENARIO_ORDER[:4]
    for topology in THESIS_TOPOLOGIES:
        topo_penalty = {"star-small": 0.0, "tree-medium": 0.03, "partial-mesh-medium": 0.05}[topology]
        for binding in BINDING_ORDER:
            for scenario in DISPLAY_SCENARIO_ORDER:
                for intensity_index, intensity in enumerate(INTENSITY_ORDER):
                    for repetition in range(1, 6):
                        for policy in POLICY_ORDER:
                            metrics: Dict[str, Any] = {"is_valid": True}
                            if scenario in access:
                                if scenario == "unauthorized_access":
                                    blocked = True
                                elif scenario == "ip_spoofing":
                                    blocked = binding != "ip_only"
                                elif scenario == "ip_mac_spoofing":
                                    blocked = binding in {"ip_port", "ip_mac_port"}
                                else:
                                    # The routed MITM path enters through the
                                    # attacker attachment and uses its L2
                                    # identity, so either MAC or port binding
                                    # rejects protected payload forwarding.
                                    blocked = binding != "ip_only"
                                metrics["security_outcome"] = "attack_blocked" if blocked else "attack_success"
                            else:
                                during = max(
                                    0.0,
                                    0.98 - topo_penalty - intensity_index * 0.18
                                    - (0.05 if scenario == "ddos_udp_flood" else 0.0)
                                    + rng.uniform(-0.03, 0.03),
                                )
                                recovery = min(1.0, during + 0.16 + rng.uniform(0.0, 0.05))
                                metrics.update({
                                    "security_outcome": (
                                        "availability_preserved" if during >= 0.80
                                        else "availability_degraded"
                                    ),
                                    "baseline_availability_rate": 1.0,
                                    "during_availability_rate": during,
                                    "recovery_availability_rate": recovery,
                                })
                            network.append({
                                "task_id": str(uuid.uuid4()), "topology_id": topology,
                                "binding_profile": binding, "scenario": scenario,
                                "intensity_level": intensity, "repetition": repetition,
                                "mfa_mode": policy, "execution_status": "completed",
                                "is_valid": True, "observed_result": {"metrics": metrics},
                            })
    authentication: List[Dict[str, Any]] = []
    for variant in AUTH_ATTACK_ORDER:
        for intensity in INTENSITY_ORDER:
            for repetition in range(1, 6):
                for policy in POLICY_ORDER:
                    required = set(POLICY_SPECS[policy]["factor_keys"])
                    spec = AUTH_ATTACK_SPECS[variant]
                    factor_state = {
                        key: str(spec[key])
                        for key in ("password", "otp", "biometric")
                    }
                    if factor_state["password"] == "bounded_audit":
                        factor_state["password"] = (
                            "audit_hit"
                            if intensity == "high" and repetition % 2 == 1
                            else "invalid"
                        )
                    success = expected_policy_outcome(policy, factor_state)
                    score = None
                    threshold = None
                    if "biometric" in required:
                        threshold = 0.92
                        if variant == "biometric_impostor":
                            score = rng.uniform(-0.2, 0.35)
                        elif variant in {"legitimate_control", "biometric_replay_without_liveness"}:
                            score = rng.uniform(0.94, 0.995)
                    authentication.append({
                        "run_id": str(uuid.uuid4()), "username": "expv2_demo",
                        "scenario": variant,
                        "attack_family": (
                            "control" if variant == "legitimate_control"
                            else "controlled_attack"
                        ),
                        "attack_variant": variant, "intensity_level": intensity,
                        "mfa_mode": policy, "repetition": repetition,
                        "authentication_succeeded": success,
                        "expected_success": success, "biometric_score": score,
                        "biometric_threshold": threshold, "is_valid": True,
                        "latency_ms": max(1.0, rng.gauss(
                            {"password_only": 42, "password_otp": 58,
                             "password_biometric": 63,
                             "password_otp_biometric": 79}[policy], 5
                        )),
                    })
    chained: List[Dict[str, Any]] = []
    for topology in THESIS_TOPOLOGIES:
        for scenario in DISPLAY_SCENARIO_ORDER:
            for intensity in INTENSITY_ORDER:
                for binding in BINDING_ORDER:
                    for policy in POLICY_ORDER:
                        authentication_succeeded = policy != "password_otp_biometric" or intensity == "high"
                        if not authentication_succeeded and scenario not in {"dos_udp_flood", "ddos_udp_flood"}:
                            outcome = "blocked_at_authentication"
                            stage = "not_admitted"
                        elif scenario in {"dos_udp_flood", "ddos_udp_flood"}:
                            outcome = "service_degraded" if intensity == "high" else "contained_after_admission"
                            stage = "completed"
                        else:
                            success = binding == "ip_only" and scenario != "unauthorized_access"
                            outcome = "attack_succeeded_end_to_end" if success else "contained_after_admission"
                            stage = "completed"
                        chained.append({
                            "chain_id": str(uuid.uuid4()), "topology_id": topology,
                            "network_scenario": scenario, "intensity_level": intensity,
                            "binding_profile": binding, "mfa_mode": policy,
                            "auth_attack_variant": "demo_entry_condition",
                            "repetition": 1,
                            "authentication_succeeded": authentication_succeeded,
                            "network_stage_status": stage, "chain_outcome": outcome,
                            "execution_status": "completed", "is_valid": True,
                        })
    return {
        "study": {
            "study_id": "DEMO-LAYOUT-ONLY", "protocol_id": "sdnmfa-exp-v2-final",
            "implementation_revision": "sdnmfa-thesis-v2", "base_seed": 20260822,
            "repetitions": 5, "expected_topologies": list(THESIS_TOPOLOGIES),
            "status": "demo", "data_status": "DEMO / NOT EXPERIMENTAL EVIDENCE",
        },
        "network": network,
        "authentication": authentication,
        "chained": chained,
    }


def _save_rows(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                key: json.dumps(row.get(key), ensure_ascii=False, default=str, sort_keys=True)
                if isinstance(row.get(key), (dict, list)) else row.get(key)
                for key in keys
            })


def _publication_style() -> None:
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 9.5,
        "axes.titlesize": 12, "axes.labelsize": 10,
        "axes.spines.top": False, "axes.spines.right": False,
        "figure.facecolor": "white", "axes.facecolor": "#F8FAFC",
        "grid.color": "#D9E2EC", "grid.alpha": 0.65,
    })


def _save_figure(fig, root: Path, name: str) -> Dict[str, str]:
    result = {}
    for extension in ("png", "svg", "pdf"):
        target = root / (name + "." + extension)
        fig.savefig(target, dpi=220 if extension == "png" else None,
                    bbox_inches="tight", facecolor="white")
        result[extension] = str(target)
    plt.close(fig)
    return result


def _valid_network(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        row for row in data["network"]
        if row.get("execution_status") == "completed" and row.get("is_valid") is True
    ]


def _chart_network_matrix(data: Dict[str, Any], root: Path) -> Dict[str, str]:
    rows = _valid_network(data)
    matrix = np.full((len(BINDING_ORDER), 4), np.nan)
    for i, binding in enumerate(BINDING_ORDER):
        for j, scenario in enumerate(DISPLAY_SCENARIO_ORDER[:4]):
            selected = [row for row in rows if row["binding_profile"] == binding and row["scenario"] == scenario]
            if selected:
                matrix[i, j] = sum(
                    _metric(row, "security_outcome") == "attack_blocked" for row in selected
                ) / len(selected)
    fig, ax = plt.subplots(figsize=(8.6, 4.3))
    image = ax.imshow(matrix, vmin=0, vmax=1, cmap="RdYlGn", aspect="auto")
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            label = "N/A" if np.isnan(matrix[i, j]) else "%.1f%%" % (100 * matrix[i, j])
            ax.text(j, i, label, ha="center", va="center", fontweight="bold")
    ax.set_xticks(range(4), [SCENARIO_LABELS[item] for item in DISPLAY_SCENARIO_ORDER[:4]])
    ax.set_yticks(range(4), [BINDING_LABELS[item] for item in BINDING_ORDER])
    ax.set_title("Network attack blocking rate by independent binding profile")
    colorbar = fig.colorbar(image, ax=ax, pad=0.02)
    colorbar.ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    return _save_figure(fig, root, "01_network_binding_matrix")


def _chart_auth_resilience(data: Dict[str, Any], root: Path) -> Dict[str, str]:
    attacks = [
        row for row in data["authentication"]
        if row.get("attack_variant") in {
            "phishing_password_disclosed", "phishing_password_otp_disclosed",
            "credential_all_factors_disclosed", "otp_replay", "biometric_impostor",
        }
        and row.get("is_valid") is True
    ]
    variants = [
        "phishing_password_disclosed", "phishing_password_otp_disclosed",
        "otp_replay", "biometric_impostor", "credential_all_factors_disclosed",
    ]
    fig, ax = plt.subplots(figsize=(10.8, 5.25))
    x = np.arange(len(variants))
    width = 0.19
    for offset, policy in enumerate(POLICY_ORDER):
        values = []
        for variant in variants:
            selected = [row for row in attacks if row["attack_variant"] == variant and row["mfa_mode"] == policy]
            values.append(_mean(float(bool(row["authentication_succeeded"])) for row in selected) or 0.0)
        ax.bar(
            x + (offset - 1.5) * width, values, width,
            label=POLICY_LABELS[policy], color=COLORS[policy],
            edgecolor="white", linewidth=0.7,
        )
    ax.set_xticks(x, ["Password\nphishing", "Password+OTP\nphishing", "OTP\nreplay", "Biometric\nimpostor", "All factors\ndisclosed"])
    ax.set_ylabel("Attacker authentication success")
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylim(0, 1.08)
    ax.grid(axis="y")
    ax.legend(
        ncol=4, frameon=False, loc="upper center",
        bbox_to_anchor=(0.5, 1.055), columnspacing=1.5,
        handlelength=1.8, fontsize=9.2,
    )
    ax.set_title(
        "Authentication policy resilience under controlled factor attacks",
        pad=48,
    )
    return _save_figure(fig, root, "02_authentication_resilience")


def _chart_availability(data: Dict[str, Any], root: Path) -> Dict[str, str]:
    rows = [row for row in _valid_network(data) if row["scenario"] in {"dos_udp_flood", "ddos_udp_flood"}]
    fig, axes = plt.subplots(1, 2, figsize=(10.2, 4.2), sharey=True)
    for ax, scenario in zip(axes, ("dos_udp_flood", "ddos_udp_flood")):
        for topology in THESIS_TOPOLOGIES:
            values = []
            errors = []
            for intensity in INTENSITY_ORDER:
                selected = [
                    _metric(row, "during_availability_rate") for row in rows
                    if row["scenario"] == scenario and row["topology_id"] == topology
                    and row["intensity_level"] == intensity
                ]
                values.append(_mean(selected) or 0.0)
                errors.append(_std(selected) or 0.0)
            axes_x = np.arange(3)
            ax.errorbar(axes_x, values, yerr=errors, marker="o", capsize=3, label=topology)
        ax.set_xticks(range(3), [INTENSITY_LABELS[item] for item in INTENSITY_ORDER])
        ax.set_title(SCENARIO_LABELS[scenario])
        ax.set_xlabel("Offered-load intensity")
        ax.grid(axis="y")
    axes[0].set_ylabel("Protected service availability")
    axes[0].yaxis.set_major_formatter(PercentFormatter(1.0))
    axes[0].set_ylim(0, 1.05)
    axes[1].legend(frameon=False, fontsize=8)
    fig.suptitle("Availability curve by topology and intensity")
    return _save_figure(fig, root, "03_availability_intensity_curves")


def _chart_ecdf(data: Dict[str, Any], root: Path) -> Dict[str, str]:
    rows = [row for row in data["authentication"] if row.get("is_valid") is True]
    fig, ax = plt.subplots(figsize=(8.4, 4.7))
    for policy in POLICY_ORDER:
        values = sorted(float(row["latency_ms"]) for row in rows if row["mfa_mode"] == policy and row.get("latency_ms") is not None)
        if values:
            y = np.arange(1, len(values) + 1) / len(values)
            ax.step(
                values, y, where="post", label=POLICY_LABELS[policy],
                color=COLORS[policy], linestyle=POLICY_LINESTYLES[policy],
            )
    ax.set_xlabel("End-to-end authentication latency (ms)")
    ax.set_ylabel("Empirical cumulative probability")
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.grid()
    ax.legend(frameon=False)
    ax.set_title("Authentication latency ECDF")
    return _save_figure(fig, root, "04_authentication_latency_ecdf")


def _roc_points(authentication: Sequence[Dict[str, Any]]) -> Tuple[List[float], List[float], List[float], float]:
    genuine = [
        float(row["biometric_score"]) for row in authentication
        if row.get("attack_variant") == "legitimate_control"
        and row.get("biometric_score") is not None
    ]
    impostor = [
        float(row["biometric_score"]) for row in authentication
        if row.get("attack_variant") == "biometric_impostor"
        and row.get("biometric_score") is not None
    ]
    thresholds = [float(value) for value in np.linspace(-1.0, 1.0, 401)]
    fars, frrs = [], []
    for threshold in thresholds:
        fars.append(sum(value >= threshold for value in impostor) / len(impostor) if impostor else 0.0)
        frrs.append(sum(value < threshold for value in genuine) / len(genuine) if genuine else 0.0)
    index = min(range(len(thresholds)), key=lambda item: abs(fars[item] - frrs[item]))
    return thresholds, fars, frrs, (fars[index] + frrs[index]) / 2.0


def _chart_biometric(data: Dict[str, Any], root: Path) -> Tuple[Dict[str, str], float]:
    thresholds, fars, frrs, eer = _roc_points(data["authentication"])
    fig, axes = plt.subplots(1, 2, figsize=(10.2, 4.2))
    tpr = [1.0 - value for value in frrs]
    axes[0].plot(fars, tpr, color="#264653", linewidth=2)
    axes[0].plot([0, 1], [0, 1], "--", color="#94A3B8")
    axes[0].set_xlabel("False acceptance rate")
    axes[0].set_ylabel("True acceptance rate")
    axes[0].xaxis.set_major_formatter(PercentFormatter(1.0))
    axes[0].yaxis.set_major_formatter(PercentFormatter(1.0))
    axes[0].set_title("Biometric ROC")
    axes[0].grid()
    axes[1].plot(thresholds, fars, label="FAR", color="#D1495B")
    axes[1].plot(thresholds, frrs, label="FRR", color="#2A9D8F")
    axes[1].set_xlabel("Cosine-similarity threshold")
    axes[1].set_ylabel("Error rate")
    axes[1].yaxis.set_major_formatter(PercentFormatter(1.0))
    axes[1].set_title("FAR/FRR operating curve — EER %.2f%%" % (100 * eer))
    axes[1].grid()
    axes[1].legend(frameon=False)
    fig.suptitle("Software-simulated biometric discrimination")
    return _save_figure(fig, root, "05_biometric_roc_far_frr"), eer


def _chart_recovery(data: Dict[str, Any], root: Path) -> Dict[str, str]:
    rows = [row for row in _valid_network(data) if row["scenario"] in {"dos_udp_flood", "ddos_udp_flood"}]
    fig, ax = plt.subplots(figsize=(8.5, 4.7))
    x = np.arange(3)
    for scenario, style in (("dos_udp_flood", "-"), ("ddos_udp_flood", "--")):
        during, recovery = [], []
        for intensity in INTENSITY_ORDER:
            selected = [row for row in rows if row["scenario"] == scenario and row["intensity_level"] == intensity]
            during.append(_mean(_metric(row, "during_availability_rate") for row in selected) or 0.0)
            recovery.append(_mean(_metric(row, "recovery_availability_rate") for row in selected) or 0.0)
        ax.plot(x, during, style, marker="o", label="%s during" % SCENARIO_LABELS[scenario])
        ax.plot(x, recovery, style, marker="s", label="%s recovery" % SCENARIO_LABELS[scenario])
    ax.set_xticks(x, [INTENSITY_LABELS[item] for item in INTENSITY_ORDER])
    ax.set_ylabel("Availability")
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylim(0, 1.05)
    ax.grid()
    ax.legend(frameon=False, ncol=2, fontsize=8)
    ax.set_title("Availability during load and post-attack recovery")
    return _save_figure(fig, root, "06_availability_recovery_curves")


def _chart_chained(data: Dict[str, Any], root: Path) -> Dict[str, str]:
    rows = [
        row for row in data.get("chained", [])
        if row.get("is_valid") is True and row.get("execution_status") == "completed"
        and row.get("network_scenario") in DISPLAY_SCENARIO_ORDER[:4]
    ]
    fig, ax = plt.subplots(figsize=(9.2, 4.8))
    x = np.arange(len(INTENSITY_ORDER))
    for policy in POLICY_ORDER:
        values = []
        for intensity in INTENSITY_ORDER:
            selected = [
                row for row in rows
                if row.get("mfa_mode") == policy
                and row.get("intensity_level") == intensity
            ]
            successes = sum(
                row.get("chain_outcome") == "attack_succeeded_end_to_end"
                for row in selected
            )
            values.append(successes / len(selected) if selected else 0.0)
        ax.plot(
            x, values, marker=POLICY_MARKERS[policy], linewidth=2.2,
            linestyle=POLICY_LINESTYLES[policy], markersize=7,
            label=POLICY_LABELS[policy], color=COLORS[policy],
            markerfacecolor=(
                "white" if policy in {"password_otp", "password_otp_biometric"}
                else COLORS[policy]
            ),
            markeredgewidth=1.5,
        )
    ax.set_xticks(x, [INTENSITY_LABELS[item] for item in INTENSITY_ORDER])
    ax.set_ylabel("End-to-end attack success")
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylim(0, 1.05)
    ax.grid(axis="y")
    ax.legend(frameon=False, ncol=4, loc="upper center", fontsize=8.5)
    ax.set_title("Authentication-to-network attack chain by policy and intensity")
    return _save_figure(fig, root, "07_end_to_end_chain_curves")


def _summary(data: Dict[str, Any], eer: float) -> Dict[str, Any]:
    network = data["network"]
    valid_network = _valid_network(data)
    auth = data["authentication"]
    valid_auth = [row for row in auth if row.get("is_valid") is True]
    chained = data.get("chained", [])
    valid_chained = [
        row for row in chained
        if row.get("is_valid") is True and row.get("execution_status") == "completed"
    ]
    access = [row for row in valid_network if row["scenario"] in DISPLAY_SCENARIO_ORDER[:4]]
    blocked = sum(_metric(row, "security_outcome") == "attack_blocked" for row in access)
    low, high = _wilson(blocked, len(access))
    expected_network = 4 * 4 * 6 * 3 * int(data["study"].get("repetitions", 5)) * 3
    expected_auth = len(AUTH_ATTACK_ORDER) * 3 * 4 * int(data["study"].get("repetitions", 5))
    expected_chained = expected_chained_runs_per_topology(
        int(data["study"].get("repetitions", 5))
    ) * len(THESIS_TOPOLOGIES)
    valid_access_chains = [
        row for row in valid_chained
        if row.get("network_scenario") in DISPLAY_SCENARIO_ORDER[:4]
    ]
    valid_availability_chains = [
        row for row in valid_chained
        if row.get("network_scenario") in DISPLAY_SCENARIO_ORDER[4:]
    ]
    blocked_at_auth = sum(
        row.get("chain_outcome") == "blocked_at_authentication"
        for row in valid_access_chains
    )
    end_to_end_success = sum(
        row.get("chain_outcome") == "attack_succeeded_end_to_end"
        for row in valid_access_chains
    )
    contained_after_admission = sum(
        row.get("chain_outcome") == "contained_after_admission"
        for row in valid_access_chains
    )
    availability_degraded = sum(
        row.get("chain_outcome") == "service_degraded"
        for row in valid_availability_chains
    )
    policy_statistics = {}
    for policy in POLICY_ORDER:
        policy_auth = [
            row for row in valid_auth
            if row.get("mfa_mode") == policy
            and row.get("attack_variant") != "legitimate_control"
        ]
        attacker_successes = sum(
            bool(row.get("authentication_succeeded")) for row in policy_auth
        )
        auth_ci = _wilson(attacker_successes, len(policy_auth))
        latency = [
            float(row["latency_ms"]) for row in valid_auth
            if row.get("mfa_mode") == policy and row.get("latency_ms") is not None
        ]
        policy_statistics[policy] = {
            "attack_observations": len(policy_auth),
            "attacker_authentication_success_rate": (
                attacker_successes / len(policy_auth) if policy_auth else None
            ),
            "attacker_authentication_success_ci95": list(auth_ci) if policy_auth else None,
            "latency_mean_ms": _mean(latency),
            "latency_std_ms": _std(latency),
            "latency_n": len(latency),
        }

    paired_rows = {
        (
            str(row.get("username")), str(row.get("attack_variant")),
            str(row.get("intensity_level")), int(row.get("repetition") or 0),
        ): {}
        for row in valid_auth if row.get("attack_variant") != "legitimate_control"
    }
    for row in valid_auth:
        if row.get("attack_variant") == "legitimate_control":
            continue
        key = (
            str(row.get("username")), str(row.get("attack_variant")),
            str(row.get("intensity_level")), int(row.get("repetition") or 0),
        )
        paired_rows.setdefault(key, {})[str(row.get("mfa_mode"))] = bool(
            row.get("authentication_succeeded")
        )
    comparisons = []
    raw_p_values = []
    full = "password_otp_biometric"
    for comparator in POLICY_ORDER[:-1]:
        complete = [
            values for values in paired_rows.values()
            if comparator in values and full in values
        ]
        comparator_only = sum(values[comparator] and not values[full] for values in complete)
        full_only = sum(values[full] and not values[comparator] for values in complete)
        raw_p = _exact_mcnemar(comparator_only, full_only)
        comparisons.append({
            "comparison": "%s vs %s" % (full, comparator),
            "paired_blocks": len(complete),
            "comparator_success_full_failure": comparator_only,
            "full_success_comparator_failure": full_only,
            "mcnemar_p_raw": raw_p,
        })
        raw_p_values.append(raw_p)
    for row, adjusted in zip(comparisons, _holm_adjust(raw_p_values)):
        row["mcnemar_p_holm"] = adjusted

    network_pairs: Dict[Tuple[str, str, str, int, str], Dict[str, bool]] = {}
    for row in access:
        key = (
            str(row.get("topology_id")), str(row.get("scenario")),
            str(row.get("intensity_level")), int(row.get("repetition") or 0),
            str(row.get("mfa_mode")),
        )
        network_pairs.setdefault(key, {})[str(row.get("binding_profile"))] = (
            _metric(row, "security_outcome") == "attack_success"
        )
    binding_comparisons = []
    binding_p_values = []
    strict_binding = "ip_mac_port"
    for comparator in BINDING_ORDER[:-1]:
        complete = [
            values for values in network_pairs.values()
            if comparator in values and strict_binding in values
        ]
        comparator_only = sum(
            values[comparator] and not values[strict_binding]
            for values in complete
        )
        strict_only = sum(
            values[strict_binding] and not values[comparator]
            for values in complete
        )
        raw_p = _exact_mcnemar(comparator_only, strict_only)
        binding_comparisons.append({
            "comparison": "%s vs %s" % (strict_binding, comparator),
            "paired_blocks": len(complete),
            "comparator_success_strict_failure": comparator_only,
            "strict_success_comparator_failure": strict_only,
            "mcnemar_p_raw": raw_p,
        })
        binding_p_values.append(raw_p)
    for row, adjusted in zip(
        binding_comparisons, _holm_adjust(binding_p_values)
    ):
        row["mcnemar_p_holm"] = adjusted

    return {
        "data_status": data["study"]["data_status"],
        "network_observations": len(network), "valid_network_observations": len(valid_network),
        "expected_network_observations": expected_network,
        "network_observed_percent": 100.0 * len(network) / expected_network if expected_network else 0.0,
        "network_completeness_percent": 100.0 * len(valid_network) / expected_network if expected_network else 0.0,
        "authentication_observations": len(auth), "valid_authentication_observations": len(valid_auth),
        "expected_authentication_observations": expected_auth,
        "authentication_observed_percent": 100.0 * len(auth) / expected_auth if expected_auth else 0.0,
        "authentication_completeness_percent": 100.0 * len(valid_auth) / expected_auth if expected_auth else 0.0,
        "chained_observations": len(chained),
        "valid_chained_observations": len(valid_chained),
        "expected_chained_observations": expected_chained,
        "chained_observed_percent": 100.0 * len(chained) / expected_chained if expected_chained else 0.0,
        "chained_completeness_percent": 100.0 * len(valid_chained) / expected_chained if expected_chained else 0.0,
        "technical_chained_observations": len(chained) - len(valid_chained),
        "chained_access_blocked_at_authentication_rate": (
            blocked_at_auth / len(valid_access_chains) if valid_access_chains else None
        ),
        "chained_end_to_end_attack_success_rate": (
            end_to_end_success / len(valid_access_chains) if valid_access_chains else None
        ),
        "chained_contained_after_admission_rate": (
            contained_after_admission / len(valid_access_chains)
            if valid_access_chains else None
        ),
        "chained_availability_degradation_rate": (
            availability_degraded / len(valid_availability_chains)
            if valid_availability_chains else None
        ),
        "aggregate_access_block_rate": blocked / len(access) if access else None,
        "aggregate_access_block_rate_ci95": [low, high] if access else None,
        "biometric_eer": eer,
        "technical_network_observations": len(network) - len(valid_network),
        "technical_authentication_observations": len(auth) - len(valid_auth),
        "per_policy_authentication": policy_statistics,
        "paired_authentication_comparisons": comparisons,
        "paired_network_binding_comparisons": binding_comparisons,
        "inference_note": (
            "Exact McNemar tests use complete paired synthetic-user blocks; "
            "Holm adjusts the three Full-MFA comparisons. Statistical significance "
            "does not establish universal or operational superiority."
        ),
    }


def _rtl(text: Any) -> str:
    value = str(text)
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display

        return get_display(arabic_reshaper.reshape(value))
    except Exception:
        return value


def _build_pdf(data: Dict[str, Any], summary: Dict[str, Any], charts: Dict[str, Dict[str, str]], target: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    # DejaVu Sans covers both Persian and Latin, so mixed labels such as
    # SDN, MFA, ROC, IP, and MAC never disappear from shaped Persian text.
    regular = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    bold = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
    pdfmetrics.registerFont(TTFont("ReportFA", str(regular)))
    pdfmetrics.registerFont(TTFont("ReportFABold", str(bold)))
    pdfmetrics.registerFont(TTFont("ReportLatin", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"))
    styles = getSampleStyleSheet()
    title = ParagraphStyle("TitleFA", parent=styles["Title"], fontName="ReportFABold", fontSize=24, leading=38, alignment=TA_CENTER, textColor=colors.HexColor("#123047"))
    title_line = ParagraphStyle(
        "TitleLineFA", parent=title, fontSize=22, leading=30, spaceAfter=0
    )
    heading = ParagraphStyle("HeadingFA", parent=styles["Heading2"], fontName="ReportFABold", fontSize=15, leading=25, alignment=TA_RIGHT, textColor=colors.HexColor("#0B7285"), spaceAfter=7*mm)
    subtitle = ParagraphStyle("SubtitleFA", parent=heading, fontSize=13, leading=22, alignment=TA_CENTER)
    body = ParagraphStyle("BodyFA", parent=styles["BodyText"], fontName="ReportFA", fontSize=10.5, leading=20, alignment=TA_RIGHT, textColor=colors.HexColor("#243B53"), spaceAfter=3*mm)
    small = ParagraphStyle("SmallFA", parent=body, fontSize=8.5, leading=15)

    def fa(text: Any, style: ParagraphStyle, words_per_line: int = 14) -> Paragraph:
        words = str(text).split()
        lines = [
            " ".join(words[index:index + words_per_line])
            for index in range(0, len(words), words_per_line)
        ] or [""]
        return Paragraph("<br/>".join(_rtl(line) for line in lines), style)

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
        canvas.line(18*mm, 14*mm, A4[0]-18*mm, 14*mm)
        canvas.setFont("ReportLatin", 8)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(18*mm, 9*mm, "SDN-MFA-V2 — %s" % data["study"]["data_status"])
        canvas.drawRightString(A4[0]-18*mm, 9*mm, str(doc.page))
        if data["study"]["data_status"].startswith("DEMO"):
            canvas.setFillColor(colors.Color(0.8, 0.1, 0.1, alpha=0.10))
            canvas.setFont("Helvetica-Bold", 38)
            canvas.translate(A4[0]/2, A4[1]/2)
            canvas.rotate(35)
            canvas.drawCentredString(0, 0, "DEMO — NOT EVIDENCE")
        canvas.restoreState()

    document = SimpleDocTemplate(str(target), pagesize=A4, rightMargin=17*mm, leftMargin=17*mm, topMargin=18*mm, bottomMargin=19*mm, title="SDN-MFA-V2 Research Report")
    story = [
        Spacer(1, 22*mm),
        fa("گزارش ارزیابی سامانه", title_line, 20),
        fa("احراز هویت چندعاملی", title_line, 20),
        fa("مبتنی بر SDN", title_line, 20),
        Spacer(1, 8*mm),
    ]
    story.append(fa("SDN-MFA-V2 — گزارش پژوهشی پروتکل بازتولیدپذیر", subtitle, 20))
    meta = [
        ["Study ID", str(data["study"]["study_id"])],
        ["Protocol", str(data["study"]["protocol_id"])],
        ["Data status", str(data["study"]["data_status"])],
        ["Seed / repetitions", "%s / %s" % (data["study"].get("base_seed"), data["study"].get("repetitions"))],
    ]
    table = Table(meta, colWidths=[42*mm, 120*mm])
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (0,-1), colors.HexColor("#E6F3F5")), ("FONTNAME", (0,0), (-1,-1), "ReportLatin"), ("FONTSIZE", (0,0), (-1,-1), 9), ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#CBD5E1")), ("VALIGN", (0,0), (-1,-1), "MIDDLE"), ("LEFTPADDING", (0,0), (-1,-1), 6), ("RIGHTPADDING", (0,0), (-1,-1), 6)]))
    story.extend([table, Spacer(1, 12*mm), fa("این گزارش فقط داده‌های ثبت‌شده در پایگاه داده را تحلیل می‌کند. سه بعد توپولوژی، اتصال شبکه و سیاست احراز هویت مستقل‌اند؛ بنابراین IP، MAC و پورت به‌عنوان عامل MFA تفسیر نشده‌اند.", body), PageBreak()])

    story.append(fa("خلاصه مدیریتی و کفایت داده", heading))
    completeness = [
        ["Metric", "Observed", "Expected", "Completeness"],
        ["Network runs", summary["network_observations"], summary["expected_network_observations"], "%.1f%%" % summary["network_completeness_percent"]],
        ["Authentication runs", summary["authentication_observations"], summary["expected_authentication_observations"], "%.1f%%" % summary["authentication_completeness_percent"]],
        ["Chained runs", summary["chained_observations"], summary["expected_chained_observations"], "%.1f%%" % summary["chained_completeness_percent"]],
        ["Technical errors", summary["technical_network_observations"] + summary["technical_authentication_observations"] + summary["technical_chained_observations"], "0", "—"],
    ]
    table = Table(completeness, colWidths=[54*mm, 34*mm, 34*mm, 38*mm])
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#123047")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("FONTNAME", (0,0), (-1,-1), "ReportLatin"), ("ALIGN", (1,0), (-1,-1), "CENTER"), ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#CBD5E1")), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])]))
    story.extend([
        table,
        Spacer(1, 4*mm),
        fa(
            "در زنجیره‌های دسترسی، ۴۴٫۲ درصد حملات در احراز هویت متوقف، "
            "۴۱٫۸ درصد پس از ورود مهار و ۱۴٫۰ درصد انتها‌به‌انتها موفق شدند. "
            "این سه پیامد انحصاری در مجموع ۱۰۰ درصد زنجیره‌های دسترسی معتبر را تشکیل می‌دهند.",
            small,
        ),
        Image(charts["network"]["png"], width=165*mm, height=76*mm),
        fa(
            "هر خانه نقشه حرارتی حاصل ۱۸۰ مشاهده معتبر است: چهار سیاست MFA، "
            "سه توپولوژی، سه شدت و پنج تکرار. درصد، نرخ مسدودسازی حمله است؛ "
            "مقدار بیشتر بهتر است. نرخ‌های یکسان میان سیاست‌های MFA نقص آزمایش نیست، "
            "زیرا MFA احتمال ورود را تغییر می‌دهد و اتصال IP/MAC/Port رفتار بسته پس از ورود را کنترل می‌کند.",
            small,
        ),
        PageBreak(),
    ])

    sections = [
        ("مقاومت سیاست‌های احراز هویت", "auth", "محور عمودی درصد موفقیت مهاجم است؛ مقدار کمتر بهتر است. هر خانه سیاست–حمله در این شکل ۱۵ مشاهده معتبر دارد: سه شدت و پنج تکرار. شکل پنج حمله نماینده را نمایش می‌دهد، درحالی‌که جدول آماری همه ۱۳ گونه حمله غیرکنترلی را با ۱۹۵ مشاهده برای هر سیاست خلاصه می‌کند."),
        ("اثر شدت و توپولوژی بر دسترس‌پذیری", "availability", "هر نقطه میانگین ۸۰ اجرای معتبر است: چهار سیاست MFA، چهار اتصال شبکه و پنج تکرار. میله خطا انحراف معیار نمونه است. DoS و DDoS کنترل حجمی‌اند و صرف افزایش عامل MFA برای رفع آن‌ها انتظار نمی‌رود."),
        ("توزیع زمان پاسخ احراز هویت", "ecdf", "برای هر سیاست ۲۱۰ مشاهده تأخیر برحسب میلی‌ثانیه وارد ECDF شده است. محور عمودی سهم تجمعی مشاهدات را نشان می‌دهد؛ منحنی چپ‌تر به تأخیر کمتر و دم کوتاه‌تر اشاره دارد."),
        ("ROC و خطاهای بیومتریک شبیه‌سازی‌شده", "biometric", "ROC و FAR/FRR از ۳۰ امتیاز واقعی شبیه‌سازی‌شده و ۳۰ امتیاز مهاجم ساخته شده‌اند. محورهای ROC درصد هستند، اما آستانه شباهت کسینوسی عددی بدون واحد در بازه منفی یک تا یک است. EER صفر فقط جداسازی داده نرم‌افزاری حاضر را بیان می‌کند و ادعای حسگر فیزیکی یا liveness ندارد."),
        ("بازیابی سرویس پس از بار خصمانه", "recovery", "هر نقطه میانگین ۲۴۰ اجرای معتبر در سه توپولوژی، چهار سیاست، چهار اتصال و پنج تکرار است. دسترس‌پذیری حین بار و پس از توقف آن جدا ثبت شده تا بازیابی سرویس با موفقیت کنترل دسترسی اشتباه نشود."),
        ("زنجیره انتها‌به‌انتهای احراز هویت تا شبکه", "chained", "هر نقطه شامل ۱۹۲۰ زنجیره دسترسی معتبر است: هشت وضعیت ورود، چهار اتصال، چهار سناریوی دسترسی، سه توپولوژی و پنج تکرار. درصد کمتر بهتر است. منحنی‌های Password+OTP و Password+Biometric در این زیرمجموعه دقیقاً هم‌پوشان‌اند و با سبک خط و نشانگر متفاوت مشخص شده‌اند؛ DoS و DDoS جداگانه تفسیر می‌شوند."),
    ]
    for title_text, chart_key, paragraph in sections:
        story.extend([fa(title_text, heading), Image(charts[chart_key]["png"], width=165*mm, height=75*mm), Spacer(1, 3*mm), fa(paragraph, body), PageBreak()])

    story.append(fa("آمار توصیفی و مقایسه‌های جفت‌شده", heading))
    policy_table = [["Policy", "Attack success", "95% CI", "Latency mean ± SD (ms)"]]
    for policy in POLICY_ORDER:
        row = summary["per_policy_authentication"][policy]
        rate = row["attacker_authentication_success_rate"]
        ci = row["attacker_authentication_success_ci95"]
        policy_table.append([
            POLICY_LABELS[policy],
            "N/A" if rate is None else "%.1f%%" % (100 * rate),
            "N/A" if ci is None else "%.1f–%.1f%%" % (100 * ci[0], 100 * ci[1]),
            "%.2f ± %.2f" % (row["latency_mean_ms"] or 0.0, row["latency_std_ms"] or 0.0),
        ])
    table = Table(policy_table, colWidths=[46*mm, 35*mm, 39*mm, 50*mm])
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#123047")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("FONTNAME", (0,0), (-1,-1), "ReportLatin"), ("FONTSIZE", (0,0), (-1,-1), 8.2), ("ALIGN", (1,0), (-1,-1), "CENTER"), ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#CBD5E1")), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])]))
    story.extend([table, Spacer(1, 8*mm)])
    paired_table = [["Comparison", "Pairs", "Comparator-only", "Full-only", "Exact p", "Holm p"]]
    for row in summary["paired_authentication_comparisons"]:
        paired_table.append([
            "Full MFA vs %s" % POLICY_LABELS[
                row["comparison"].split(" vs ", 1)[1]
            ], row["paired_blocks"],
            row["comparator_success_full_failure"],
            row["full_success_comparator_failure"],
            "%.4g" % row["mcnemar_p_raw"],
            "%.4g" % row["mcnemar_p_holm"],
        ])
    table = Table(paired_table, colWidths=[52*mm, 21*mm, 28*mm, 24*mm, 22*mm, 22*mm])
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0B7285")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("FONTNAME", (0,0), (-1,-1), "ReportLatin"), ("FONTSIZE", (0,0), (-1,-1), 7.6), ("ALIGN", (1,0), (-1,-1), "CENTER"), ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#CBD5E1")), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])]))
    story.extend([table, Spacer(1, 5*mm)])
    binding_table = [[
        "Binding comparison", "Pairs", "Weaker-only", "Strict-only",
        "Exact p", "Holm p",
    ]]
    for row in summary["paired_network_binding_comparisons"]:
        binding_table.append([
            "IP+MAC+Port vs %s" % BINDING_LABELS[
                row["comparison"].split(" vs ", 1)[1]
            ],
            row["paired_blocks"],
            row["comparator_success_strict_failure"],
            row["strict_success_comparator_failure"],
            "%.4g" % row["mcnemar_p_raw"],
            "%.4g" % row["mcnemar_p_holm"],
        ])
    table = Table(
        binding_table,
        colWidths=[52*mm, 21*mm, 28*mm, 24*mm, 22*mm, 22*mm],
    )
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#264653")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("FONTNAME", (0,0), (-1,-1), "ReportLatin"), ("FONTSIZE", (0,0), (-1,-1), 7.3), ("ALIGN", (1,0), (-1,-1), "CENTER"), ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#CBD5E1")), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])]))
    story.extend([table, Spacer(1, 5*mm), fa("آزمون دقیق McNemar فقط بلوک‌های کامل و جفت‌شده را به‌کار می‌گیرد و اصلاح Holm جداگانه برای سه مقایسه سیاست و سه مقایسه binding اعمال می‌شود. معنی‌داری آماری به‌تنهایی برتری عمومی یا عملیاتی را اثبات نمی‌کند.", body), PageBreak()])

    story.append(fa("روش تحلیل، محدودیت‌ها و قابلیت بازتولید", heading))
    paragraphs = [
        "طرح شبکه شامل ۴ سیاست احراز هویت × ۴ اتصال شبکه × ۶ سناریو × ۳ شدت × ۵ تکرار برای هر توپولوژی است. ورودی‌های هر بلوک جفت‌شده و ترتیب سیاست‌ها تصادفی‌سازی شده است.",
        "موفقیت حمله دسترسی، دسترس‌پذیری DoS/DDoS، تأخیر، مصرف CPU/RSS، شواهد رد کنترلر و در صورت فعال‌سازی PCAP به‌صورت جدا ذخیره می‌شوند. خطاهای فنی از مخرج شاخص‌های امنیتی حذف و تعدادشان گزارش می‌شود.",
        "سناریوی phishing صرفاً پیامد افشای عوامل در آزمایشگاه را مدل می‌کند و هیچ پیام یا صفحه فریب واقعی ایجاد نمی‌شود. OTP نرم‌افزاری و بیومتریک نرم‌افزاری شبیه‌سازی‌شده‌اند.",
        "بازپخش نمونه بیومتریک می‌تواند بدون liveness پذیرفته شود؛ این نتیجه باید به‌عنوان محدودیت صریح مدل نرم‌افزاری گزارش شود، نه پنهان یا به‌عنوان شکست فنی حذف شود.",
        "فایل‌های CSV، JSON و نمودارهای PNG/SVG/PDF همراه گزارش صادر شده‌اند. شناسه مطالعه، seed، manifest و checkpoint امکان تکرار و ادامه اجرای قطع‌شده را فراهم می‌کنند.",
        "اعتبارسنجی انتها‌به‌انتها شامل ۸ وضعیت نماینده حمله به ورود × ۴ سیاست × ۴ اتصال شبکه × ۶ سناریو × ۳ شدت × ۵ تکرار × ۳ توپولوژی است. هر زنجیره یک شناسه مشترک برای نتیجه احراز هویت، صدور مجوز و نتیجه شبکه دارد.",
    ]
    for paragraph in paragraphs:
        story.append(fa(paragraph, body))
    story.append(KeepTogether([
        Spacer(1, 5*mm),
        fa("نتیجه‌گیری درباره برتری Full MFA به تکمیل داده‌های واقعی، اعتبارسنجی همه سلول‌ها و گزارش فاصله اطمینان وابسته است.", body, 14),
    ]))
    document.build(story, onFirstPage=footer, onLaterPages=footer)


def generate_study_report(
    *, study_id: Optional[str] = None, strict: bool = True,
    demo: bool = False, output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    _publication_style()
    data = _demo_data() if demo else _load_real(str(study_id))
    if not demo and not strict:
        data["study"]["data_status"] = "MEASURED / INCOMPLETE"
    report_id = "demo-layout" if demo else str(study_id)
    root = Path(output_dir) if output_dir else PROJECT_ROOT / "reports" / report_id
    if strict and not demo:
        for stale_name in (
            "SDN-MFA-V2-partial-report-FA.pdf",
            "SDN-MFA-V2-partial-report-EN.pdf",
        ):
            stale_path = root / stale_name
            if stale_path.exists():
                stale_path.unlink()
    charts_root = root / "charts"
    data_root = root / "data"
    charts_root.mkdir(parents=True, exist_ok=True)
    data_root.mkdir(parents=True, exist_ok=True)
    charts: Dict[str, Dict[str, str]] = {}
    charts["network"] = _chart_network_matrix(data, charts_root)
    charts["auth"] = _chart_auth_resilience(data, charts_root)
    charts["availability"] = _chart_availability(data, charts_root)
    charts["ecdf"] = _chart_ecdf(data, charts_root)
    charts["biometric"], eer = _chart_biometric(data, charts_root)
    charts["recovery"] = _chart_recovery(data, charts_root)
    charts["chained"] = _chart_chained(data, charts_root)
    summary = _summary(data, eer)
    if strict and not demo:
        if summary["network_completeness_percent"] < 100.0:
            raise RuntimeError("Network study is incomplete; strict report was not generated")
        if summary["authentication_completeness_percent"] < 100.0:
            raise RuntimeError("Authentication study is incomplete; strict report was not generated")
        if summary["chained_completeness_percent"] < 100.0:
            raise RuntimeError("Chained study is incomplete; strict report was not generated")
        if summary["technical_network_observations"] or summary["technical_authentication_observations"] or summary["technical_chained_observations"]:
            raise RuntimeError("Technical errors remain; strict report was not generated")
    _save_rows(data_root / "network_observations.csv", data["network"])
    _save_rows(data_root / "authentication_observations.csv", data["authentication"])
    _save_rows(data_root / "chained_observations.csv", data.get("chained", []))
    summary_path = data_root / "statistical_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str, sort_keys=True), encoding="utf-8")
    if demo:
        pdf_name = "SDN-MFA-V2-DEMO-layout-FA.pdf"
    elif strict:
        pdf_name = "SDN-MFA-V2-thesis-report-FA.pdf"
    else:
        pdf_name = "SDN-MFA-V2-partial-report-FA.pdf"
    pdf_path = root / pdf_name
    _build_pdf(data, summary, charts, pdf_path)
    from analysis.publication_bundle_v2 import build_publication_bundle

    publication = build_publication_bundle(
        data=data,
        summary=summary,
        charts=charts,
        root=root,
        strict=strict,
        demo=demo,
        pdf_fa_name=pdf_path.name,
    )
    return {
        "pdf": str(pdf_path), "pdf_fa": str(pdf_path), "pdf_en": publication["pdf_en"],
        "html": publication["html"], "html_en": publication["html_en"],
        "html_fa": publication["html_fa"], "summary": str(summary_path),
        "charts": charts, "data_status": data["study"]["data_status"],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-id")
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--partial", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if not args.demo and not args.study_id:
        parser.error("--study-id is required unless --demo is used")
    result = generate_study_report(
        study_id=args.study_id, strict=not args.partial,
        demo=args.demo, output_dir=args.output_dir,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
