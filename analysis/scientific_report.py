"""Generate bilingual single-campaign and aggregate evidence dashboards."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import hmac
import json
import math
import os
import shutil
import stat
import statistics
import sys
import tempfile
import uuid
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

os.environ.setdefault("MPLBACKEND", "Agg")
os.environ.setdefault("MPLCONFIGDIR", "/tmp/sdnmfa_matplotlib_cache")
import matplotlib.pyplot as plt

try:
    import arabic_reshaper
    from bidi.algorithm import get_display as bidi_display
except ImportError:  # preflight requires these for correctly shaped Persian charts
    arabic_reshaper = None
    bidi_display = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root_text = str(PROJECT_ROOT)
while project_root_text in sys.path:
    sys.path.remove(project_root_text)
sys.path.insert(0, project_root_text)

from config.experiment_protocol import (
    AUTH_SCENARIO_ORDER,
    AUTH_SCENARIO_SPECS,
    INTENSITY_ORDER,
    POLICY_ORDER,
    POLICY_SPECS,
    SCENARIO_SPECS,
)
from experiments.campaign import manifest_digest
from analysis.evidence_export import (
    compute_checksum_inventory,
    export_evidence_package,
    student_t_summary,
)
from analysis.aggregate_charts import save_aggregate_charts
from analysis.aggregate_dashboard import render_aggregate_dashboard


COLORS = {
    "password_only": "#334155",
    "password_otp": "#2563eb",
    "password_biometric": "#d97706",
    "password_otp_biometric": "#059669",
}
MARKERS = {
    "password_only": "o",
    "password_otp": "s",
    "password_biometric": "D",
    "password_otp_biometric": "^",
}
LINE_STYLES = {
    "password_only": "-",
    "password_otp": "--",
    "password_biometric": "-.",
    "password_otp_biometric": ":",
}
OUTCOME_COLORS = {
    "attack_blocked": "#059669",
    "availability_preserved": "#0f766e",
    "attack_success": "#dc2626",
    "availability_degraded": "#ea580c",
    "not_evaluable": "#64748b",
}
EVALUABLE_OUTCOMES = {
    "attack_blocked",
    "attack_success",
    "availability_preserved",
    "availability_degraded",
}

PERSIAN_SCENARIO_LABELS = {
    "unauthorized_access": "دسترسی مستقیمِ بدون مجوز",
    "ip_spoofing": "جعل نشانی مبدأ IP",
    "ip_mac_spoofing": "جعل هم‌زمان IP و MAC",
    "arp_mitm": "تلاش مسموم‌سازی ARP و مرد میانی",
    "dos_udp_flood": "سیلاب UDP تک‌مبدأ",
    "ddos_udp_flood": "سیلاب UDP چندمبدأ",
}
PERSIAN_POLICY_LABELS = {
    "password_only": "فقط گذرواژه",
    "password_otp": "گذرواژه + OTP",
    "password_biometric": "گذرواژه + بایومتریک شبیه‌سازی‌شده",
    "password_otp_biometric": "احراز هویت کامل چندعاملی",
}
PERSIAN_INTENSITY_LABELS = {"low": "کم", "medium": "متوسط", "high": "زیاد"}
PERSIAN_OUTCOME_LABELS = {
    "attack_blocked": "حمله مسدود شد",
    "availability_preserved": "دسترس‌پذیری حفظ شد",
    "attack_success": "حمله موفق بود",
    "availability_degraded": "دسترس‌پذیری افت کرد",
    "not_evaluable": "غیرقابل ارزیابی",
}
PERSIAN_AUTH_SCENARIO_LABELS = {
    "valid_factors": "عوامل معتبر کاربر",
    "password_compromised": "فقط گذرواژه در دسترس",
    "password_and_otp_compromised": "گذرواژه و OTP در دسترس",
    "password_and_biometric_compromised": "گذرواژه و بایومتریک در دسترس",
    "all_factors_compromised": "همه عوامل در دسترس",
}


def _chart_text(value: Any, persian: bool) -> str:
    text = str(value)
    if not persian:
        return text
    if arabic_reshaper is None or bidi_display is None:
        raise RuntimeError(
            "Persian charts require arabic-reshaper and python-bidi. "
            "Run the report with ./venv/bin/python."
        )
    return bidi_display(arabic_reshaper.reshape(text), base_dir="R")


def _dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def _manifest_artifact_path(campaign: Dict[str, Any]) -> Path:
    return (
        PROJECT_ROOT
        / "evidence"
        / "manifests"
        / ("%s.json" % str(campaign.get("campaign_id") or "unknown"))
    )


def _evidence_integrity_summary(
    inventory: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Summarize independently checked manifest and optional PCAP evidence."""
    manifest_rows = [row for row in inventory if row.get("artifact_type") == "manifest"]
    manifest_payload_valid = len(manifest_rows) == 1 and all(
        row.get("payload_checksum_status") == "verified" for row in manifest_rows
    )
    manifest_file_valid = len(manifest_rows) == 1 and all(
        row.get("presence_status") == "present"
        and row.get("checksum_status") == "verified"
        for row in manifest_rows
    )
    pcap_rows = [
        row
        for row in inventory
        if row.get("artifact_type") == "pcap"
        and (
            row.get("enabled") is True
            or bool(row.get("recorded_path"))
            or bool(row.get("declared_sha256"))
        )
    ]
    verified = [
        row
        for row in pcap_rows
        if row.get("checksum_status") == "verified"
        and row.get("size_status") != "mismatch"
    ]
    missing = [row for row in pcap_rows if row.get("presence_status") == "missing"]
    mismatched = [
        row
        for row in pcap_rows
        if row.get("checksum_status") == "mismatch"
        or row.get("size_status") == "mismatch"
    ]
    unverified = [
        row
        for row in pcap_rows
        if row not in verified and row not in missing and row not in mismatched
    ]
    return {
        "manifest_payload_checksum_valid": manifest_payload_valid,
        "manifest_file_checksum_valid": manifest_file_valid,
        "pcap_expected_n": len(pcap_rows),
        "pcap_verified_n": len(verified),
        "pcap_missing_n": len(missing),
        "pcap_mismatch_n": len(mismatched),
        "pcap_unverified_n": len(unverified),
        "pcap_evidence_complete": len(verified) == len(pcap_rows),
        "evidence_integrity_valid": (
            manifest_payload_valid
            and manifest_file_valid
            and len(verified) == len(pcap_rows)
        ),
    }


def _campaign_observations(cur: Any, campaign: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Load and decode one campaign after its database row has been selected."""
    cur.execute(
        """
        SELECT * FROM experiment_runs
        WHERE campaign_id = %s
        ORDER BY repetition, intensity_level, policy_position
        """,
        (campaign["campaign_id"],),
    )
    run_columns = [item[0] for item in cur.description]
    runs = [dict(zip(run_columns, item)) for item in cur.fetchall()]
    cur.execute(
        """
        SELECT * FROM authentication_experiment_logs
        WHERE campaign_id = %s
        ORDER BY repetition, scenario, mfa_mode
        """,
        (campaign["campaign_id"],),
    )
    auth_columns = [item[0] for item in cur.description]
    auth_runs = [dict(zip(auth_columns, item)) for item in cur.fetchall()]

    campaign = dict(campaign)
    campaign["manifest"] = _dict(campaign.get("manifest"))
    for run in runs:
        run["sampled_parameters"] = _dict(run.get("sampled_parameters"))
        run["observed_result"] = _dict(run.get("observed_result"))
        run["resource_metrics"] = _dict(run.get("resource_metrics"))
        run["pcap_evidence"] = _dict(run.get("pcap_evidence"))
    for auth_run in auth_runs:
        auth_run["supplied_factors"] = _dict(auth_run.get("supplied_factors"))
        auth_run["resource_metrics"] = _dict(auth_run.get("resource_metrics"))
    campaign["authentication_runs"] = auth_runs
    return campaign, runs


def _query(campaign_id: Optional[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Load one campaign, preserving the legacy latest-campaign default."""
    from database.db_config import get_db_connection, release_db_connection
    conn = get_db_connection()
    if conn is None:
        raise RuntimeError("Database connection is unavailable")
    try:
        with conn.cursor() as cur:
            if campaign_id:
                cur.execute("SELECT * FROM experiment_campaigns WHERE campaign_id = %s", (campaign_id,))
            else:
                cur.execute(
                    """
                    SELECT * FROM experiment_campaigns
                    ORDER BY COALESCE(completed_at, started_at, created_at) DESC
                    LIMIT 1
                    """
                )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("No experiment campaign was found")
            columns = [item[0] for item in cur.description]
            return _campaign_observations(cur, dict(zip(columns, row)))
    finally:
        release_db_connection(conn)


def _normalize_campaign_ids(campaign_ids: Iterable[str]) -> List[str]:
    """Return unique canonical UUIDs while preserving the caller's order."""
    normalized: List[str] = []
    seen = set()
    for value in campaign_ids:
        for item in str(value).split(","):
            raw = item.strip()
            if not raw:
                continue
            try:
                campaign_id = str(uuid.UUID(raw))
            except ValueError as exc:
                raise ValueError("Invalid campaign UUID: %s" % raw) from exc
            if campaign_id not in seen:
                normalized.append(campaign_id)
                seen.add(campaign_id)
    if not normalized:
        raise ValueError("At least one campaign UUID is required")
    return normalized


def _select_latest_complete_suite(
    campaign_rows: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Select the newest complete, internally comparable six-scenario suite.

    A suite shares the protocol/schema, seed, topology, binding, repetition
    count, randomized-block design and versioned protocol parameters.
    Selecting the newest row independently for each scenario could silently
    combine incompatible experiments, so only complete signatures are eligible.
    """
    required_scenarios = list(SCENARIO_SPECS)
    grouped: Dict[Tuple[str, ...], Dict[str, Dict[str, Any]]] = (
        defaultdict(dict)
    )

    def row_rank(row: Dict[str, Any]) -> Tuple[str, str]:
        observed_at = (
            row.get("completed_at")
            or row.get("started_at")
            or row.get("created_at")
            or ""
        )
        return str(observed_at), str(row.get("campaign_id") or "")

    for row in campaign_rows:
        scenario = str(row.get("scenario") or "")
        if scenario not in SCENARIO_SPECS:
            continue
        manifest = _dict(row.get("manifest"))
        protocol_parameters = dict(_dict(manifest.get("protocol_parameters")))
        protocol_parameters.pop("declared_intensity_ranges", None)
        signature = (
            str(row.get("protocol_id") or ""),
            str(row.get("schema_version") or ""),
            str(row.get("seed") or ""),
            str(row.get("topology_id") or ""),
            str(row.get("binding_profile") or ""),
            str(row.get("repetitions") or ""),
            str(row.get("design") or manifest.get("design") or ""),
            _canonical_json(manifest.get("design") or {}),
            _canonical_json(protocol_parameters),
        )
        existing = grouped[signature].get(scenario)
        if existing is None or row_rank(row) > row_rank(existing):
            grouped[signature][scenario] = row

    candidates = [
        (max(row_rank(row) for row in scenario_rows.values()), signature, scenario_rows)
        for signature, scenario_rows in grouped.items()
        if set(scenario_rows) == set(required_scenarios)
    ]
    if not candidates:
        raise RuntimeError(
            "No complete six-scenario suite with a common protocol, seed, topology, "
            "binding, and repetition count was found"
        )
    _rank, _signature, selected = max(
        candidates,
        key=lambda item: (item[0], item[1]),
    )
    return [selected[scenario] for scenario in required_scenarios]


def _query_campaigns(
    campaign_ids: Optional[Iterable[str]] = None,
    *,
    selector: Optional[str] = None,
    latest_count: int = 1,
    days: Optional[int] = None,
) -> List[Tuple[Dict[str, Any], List[Dict[str, Any]]]]:
    """Load explicit campaigns or completed campaigns from the database store.

    ``selector`` accepts ``all-completed``, ``latest-completed``, or
    ``latest-suite`` (the newest compatible complete six-scenario suite).
    Explicit identifiers retain caller order; selectors use the completion
    timestamp already stored by ``experiment_campaigns``.
    """
    if campaign_ids is not None and selector is not None:
        raise ValueError("Campaign UUIDs and a campaign selector are mutually exclusive")
    normalized_ids = _normalize_campaign_ids(campaign_ids) if campaign_ids is not None else []
    normalized_selector = str(selector or "").strip().lower().replace("_", "-")
    if not normalized_ids and normalized_selector not in {
        "all-completed",
        "latest-completed",
        "latest-suite",
    }:
        raise ValueError(
            "Use explicit campaign UUIDs, all-completed, latest-completed, or latest-suite"
        )
    if normalized_selector == "latest-completed" and int(latest_count) < 1:
        raise ValueError("latest_count must be at least 1")
    if days is not None and int(days) < 1:
        raise ValueError("days must be at least 1")
    if normalized_ids and days is not None:
        raise ValueError("days bounds broad selectors, not explicit campaign UUIDs")

    from database.db_config import get_db_connection, release_db_connection
    conn = get_db_connection()
    if conn is None:
        raise RuntimeError("Database connection is unavailable")
    try:
        with conn.cursor() as cur:
            campaign_rows: List[Dict[str, Any]] = []
            if normalized_ids:
                for campaign_id in normalized_ids:
                    cur.execute(
                        "SELECT * FROM experiment_campaigns WHERE campaign_id = %s",
                        (campaign_id,),
                    )
                    row = cur.fetchone()
                    if not row:
                        raise RuntimeError("Campaign was not found: %s" % campaign_id)
                    columns = [item[0] for item in cur.description]
                    campaign_rows.append(dict(zip(columns, row)))
            else:
                where = "WHERE status = 'completed'"
                parameters: List[Any] = []
                if days is not None:
                    where += (
                        " AND COALESCE(completed_at, started_at, created_at) "
                        ">= CURRENT_TIMESTAMP - (%s * INTERVAL '1 day')"
                    )
                    parameters.append(int(days))
                query = """
                    SELECT * FROM experiment_campaigns
                    %s
                    ORDER BY COALESCE(completed_at, started_at, created_at) DESC,
                             campaign_id
                """ % where
                if normalized_selector == "latest-completed":
                    query += " LIMIT %s"
                    parameters.append(int(latest_count))
                cur.execute(query, tuple(parameters))
                columns = [item[0] for item in cur.description]
                campaign_rows = [dict(zip(columns, row)) for row in cur.fetchall()]
                if normalized_selector == "latest-suite":
                    campaign_rows = _select_latest_complete_suite(campaign_rows)
            if not campaign_rows:
                raise RuntimeError("No completed experiment campaign was found")
            return [_campaign_observations(cur, campaign) for campaign in campaign_rows]
    finally:
        release_db_connection(conn)


def _outcome(run: Dict[str, Any]) -> str:
    metrics = _dict(run.get("observed_result")).get("metrics")
    metrics = metrics if isinstance(metrics, dict) else {}
    return str(metrics.get("security_outcome") or "not_evaluable")


def _is_resisted(outcome: str) -> bool:
    return outcome in {"attack_blocked", "availability_preserved"}


def _valid(run: Dict[str, Any]) -> bool:
    return (
        str(run.get("execution_status") or "").strip().lower() == "completed"
        and run.get("is_valid") is True
        and _outcome(run) in EVALUABLE_OUTCOMES
    )


def _mean(values: Iterable[float]) -> Optional[float]:
    rows = [float(value) for value in values if value is not None]
    return statistics.fmean(rows) if rows else None


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> Tuple[Optional[float], Optional[float]]:
    """Return a two-sided 95% Wilson score interval in percentage points."""
    if total <= 0:
        return None, None
    proportion = float(successes) / float(total)
    z_squared = z * z
    denominator = 1.0 + z_squared / total
    centre = (proportion + z_squared / (2.0 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / total
            + z_squared / (4.0 * total * total)
        )
        / denominator
    )
    return 100.0 * max(0.0, centre - margin), 100.0 * min(1.0, centre + margin)


PARTIAL_FACTOR_COMPROMISE_SCENARIOS = (
    "password_compromised",
    "password_and_otp_compromised",
    "password_and_biometric_compromised",
)


def factor_compromise_resistance_rows(
    verifier_rows: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Summarize resistance to the three declared partial-factor compromises."""
    results: List[Dict[str, Any]] = []
    for policy in POLICY_ORDER:
        policy_rows = [
            row
            for row in verifier_rows
            if str(row.get("policy")) == policy
            and str(row.get("scenario")) in PARTIAL_FACTOR_COMPROMISE_SCENARIOS
        ]
        by_scenario = {str(row.get("scenario")): row for row in policy_rows}
        ordered = [
            by_scenario[scenario]
            for scenario in PARTIAL_FACTOR_COMPROMISE_SCENARIOS
            if scenario in by_scenario
        ]
        observations = sum(int(row.get("observation_n") or 0) for row in ordered)
        successes = sum(
            int(row.get("authentication_success_n") or 0) for row in ordered
        )
        blocked = max(0, observations - successes)
        low, high = wilson_interval(blocked, observations)
        fully_resisted_states = sum(
            1
            for row in ordered
            if int(row.get("observation_n") or 0) > 0
            and int(row.get("authentication_success_n") or 0) == 0
        )
        results.append(
            {
                "policy": policy,
                "policy_label": POLICY_SPECS[policy]["label"],
                "compromise_state_n": len(ordered),
                "fully_resisted_state_n": fully_resisted_states,
                "exposed_state_n": len(ordered) - fully_resisted_states,
                "observation_n": observations,
                "blocked_authentication_n": blocked,
                "successful_authentication_n": successes,
                "resistance_percent": (
                    100.0 * blocked / observations if observations else None
                ),
                "resistance_ci95_low": low,
                "resistance_ci95_high": high,
                "evidence_scope": "controlled_partial_factor_compromise",
            }
        )
    return results


def exact_mcnemar_p(left_only: int, right_only: int) -> float:
    """Return the two-sided exact McNemar p-value for discordant pairs."""
    left_only = int(left_only)
    right_only = int(right_only)
    if left_only < 0 or right_only < 0:
        raise ValueError("Discordant-pair counts cannot be negative")
    discordant = left_only + right_only
    if discordant == 0:
        return 1.0
    smaller = min(left_only, right_only)
    lower_tail = sum(math.comb(discordant, value) for value in range(smaller + 1))
    return min(1.0, 2.0 * lower_tail / float(2**discordant))


def _paired_policy_comparisons(valid_runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_sample: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for run in valid_runs:
        sample_id = str(run.get("sample_id") or "")
        policy = str(run.get("mfa_mode") or "")
        if sample_id and policy in POLICY_ORDER:
            by_sample[sample_id][policy].append(run)

    rows: List[Dict[str, Any]] = []
    for left_index, left in enumerate(POLICY_ORDER):
        for right in POLICY_ORDER[left_index + 1:]:
            paired = [
                (policies[left][0], policies[right][0])
                for policies in by_sample.values()
                if len(policies.get(left, [])) == 1
                and len(policies.get(right, [])) == 1
            ]
            left_only = sum(
                _is_resisted(_outcome(left_run))
                and not _is_resisted(_outcome(right_run))
                for left_run, right_run in paired
            )
            right_only = sum(
                _is_resisted(_outcome(right_run))
                and not _is_resisted(_outcome(left_run))
                for left_run, right_run in paired
            )
            rows.append(
                {
                    "left_policy": left,
                    "left_label": POLICY_SPECS[left]["label"],
                    "right_policy": right,
                    "right_label": POLICY_SPECS[right]["label"],
                    "paired_n": len(paired),
                    "left_only_resisted": left_only,
                    "right_only_resisted": right_only,
                    "discordant_n": left_only + right_only,
                    "exact_mcnemar_p": (
                        exact_mcnemar_p(left_only, right_only) if paired else None
                    ),
                    "holm_adjusted_p": None,
                    "inference_status": (
                        "descriptive_exact_test" if paired else "insufficient_pairs"
                    ),
                }
            )

    ordered = sorted(
        (
            index
            for index, row in enumerate(rows)
            if row["exact_mcnemar_p"] is not None
        ),
        key=lambda index: rows[index]["exact_mcnemar_p"],
    )
    previous = 0.0
    comparison_count = len(ordered)
    for rank, index in enumerate(ordered):
        adjusted = min(
            1.0,
            (comparison_count - rank) * float(rows[index]["exact_mcnemar_p"]),
        )
        adjusted = max(previous, adjusted)
        rows[index]["holm_adjusted_p"] = adjusted
        previous = adjusted
    return rows


def _extract_cpu_p95(run: Dict[str, Any]) -> Optional[float]:
    metrics = _dict(run.get("resource_metrics"))
    process = _dict(metrics.get("process_cpu_percent"))
    try:
        return float(process["p95"]) if process.get("p95") is not None else None
    except (TypeError, ValueError):
        return None


def _sample_latency_p95(samples: Any) -> Optional[float]:
    if not isinstance(samples, list):
        return None
    values: List[float] = []
    for item in samples:
        if not isinstance(item, dict) or item.get("elapsed_ms") is None:
            continue
        try:
            value = float(item.get("elapsed_ms"))
        except (TypeError, ValueError, OverflowError):
            continue
        if math.isfinite(value) and value >= 0.0:
            values.append(value)
    values.sort()
    if not values:
        return None
    index = max(0, int(round(0.95 * (len(values) - 1))))
    return values[index]


def _extract_attack_latency_p95(run: Dict[str, Any]) -> Optional[float]:
    result_metrics = _dict(_dict(run.get("observed_result")).get("metrics"))
    attack_probe = _dict(result_metrics.get("attack_probe"))
    value = attack_probe.get("latency_p95_ms")
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _extract_legitimate_latency_p95(run: Dict[str, Any]) -> Optional[float]:
    result_metrics = _dict(_dict(run.get("observed_result")).get("metrics"))
    availability_value = _sample_latency_p95(result_metrics.get("availability_samples"))
    if availability_value is not None:
        return availability_value
    preflight = _dict(result_metrics.get("preflight"))
    postflight = _dict(result_metrics.get("postflight"))
    samples = list(preflight.get("legitimate_samples") or []) + list(
        postflight.get("samples") or []
    )
    return _sample_latency_p95(samples)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _runs_match_manifest(manifest: Dict[str, Any], runs: List[Dict[str, Any]]) -> bool:
    """Verify that every recorded task is the exact task declared in the manifest."""
    raw_tasks = manifest.get("tasks") or []
    if not isinstance(raw_tasks, list) or not raw_tasks:
        return False
    expected: Dict[str, Dict[str, Any]] = {}
    for task in raw_tasks:
        if not isinstance(task, dict) or not task.get("task_id"):
            return False
        task_id = str(task["task_id"])
        if task_id in expected:
            return False
        expected[task_id] = task
    observed_ids = [str(run.get("task_id") or "") for run in runs]
    if len(observed_ids) != len(set(observed_ids)) or set(observed_ids) != set(expected):
        return False
    field_pairs = (
        ("sample_id", "sample_id"),
        ("scenario", "scenario"),
        ("intensity", "intensity_level"),
        ("repetition", "repetition"),
        ("policy", "mfa_mode"),
        ("policy_position", "policy_position"),
        ("binding_profile", "binding_profile"),
        ("topology_id", "topology_id"),
    )
    for run in runs:
        task = expected[str(run.get("task_id"))]
        for task_field, run_field in field_pairs:
            if str(task.get(task_field)) != str(run.get(run_field)):
                return False
        if _canonical_json(task.get("parameters") or {}) != _canonical_json(
            _dict(run.get("sampled_parameters"))
        ):
            return False
    return True


def _authentication_evidence_valid(
    repetitions: int,
    authentication_runs: List[Dict[str, Any]],
) -> bool:
    expected_cells = {
        (repetition, scenario, policy)
        for repetition in range(1, int(repetitions) + 1)
        for scenario in AUTH_SCENARIO_ORDER
        for policy in POLICY_ORDER
    }
    try:
        observed_cells = [
            (
                int(row.get("repetition") or 0),
                str(row.get("scenario") or ""),
                str(row.get("mfa_mode") or ""),
            )
            for row in authentication_runs
        ]
    except (TypeError, ValueError):
        return False
    if len(observed_cells) != len(set(observed_cells)) or set(observed_cells) != expected_cells:
        return False
    for row in authentication_runs:
        scenario = str(row.get("scenario"))
        policy = str(row.get("mfa_mode"))
        required = set(POLICY_SPECS[policy]["factor_keys"])
        available = set(AUTH_SCENARIO_SPECS[scenario]["available_factors"])
        expected_supplied = sorted(required & available)
        supplied_payload = _dict(row.get("supplied_factors"))
        if supplied_payload:
            if sorted(supplied_payload.get("required") or []) != sorted(required):
                return False
            if sorted(supplied_payload.get("supplied") or []) != expected_supplied:
                return False
            if supplied_payload.get("simulation") != "software_factor_availability":
                return False
        else:
            return False
        if bool(row.get("authentication_succeeded")) != required.issubset(available):
            return False
        try:
            latency = float(row.get("latency_ms"))
            cpu_equivalent = float(
                _dict(row.get("resource_metrics"))["cpu_percent_equivalent"]
            )
        except (KeyError, TypeError, ValueError):
            return False
        if not math.isfinite(latency) or latency < 0.0:
            return False
        if not math.isfinite(cpu_equivalent) or cpu_equivalent < 0.0:
            return False
    return True


def summarize(campaign: Dict[str, Any], runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    manifest = _dict(campaign.get("manifest"))
    stored_manifest_digest = str(
        campaign.get("manifest_sha256") or manifest.get("manifest_sha256") or ""
    )
    computed_manifest_digest = manifest_digest(manifest) if manifest else ""
    manifest_integrity_valid = bool(stored_manifest_digest) and hmac.compare_digest(
        stored_manifest_digest,
        computed_manifest_digest,
    )
    planned = len(manifest.get("tasks") or [])
    completed = sum(1 for run in runs if run.get("execution_status") == "completed")
    run_manifest_alignment_valid = _runs_match_manifest(manifest, runs)
    authentication_runs = list(campaign.get("authentication_runs") or [])
    expected_authentication_observations = (
        int(campaign["repetitions"])
        * len(AUTH_SCENARIO_ORDER)
        * len(POLICY_ORDER)
    )
    authentication_evidence_valid = _authentication_evidence_valid(
        int(campaign["repetitions"]), authentication_runs
    )
    authentication_complete = (
        len(authentication_runs) == expected_authentication_observations
        and authentication_evidence_valid
    )
    analysis_eligible = bool(
        str(campaign.get("status") or "").strip().lower() == "completed"
        and manifest_integrity_valid
        and run_manifest_alignment_valid
        and authentication_complete
        and campaign.get("_report_evidence_integrity_valid", True) is True
    )
    task_level_valid_runs = [run for run in runs if _valid(run)]
    valid_runs = task_level_valid_runs if analysis_eligible else []
    outcome_counts = Counter(_outcome(run) for run in runs)
    valid_outcome_counts = Counter(_outcome(run) for run in valid_runs)
    task_classifications = Counter(_task_classification(run) for run in runs)

    blocks: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for run in valid_runs:
        blocks[(str(run.get("mfa_mode")), str(run.get("intensity_level")))].append(run)
    curve_rows: List[Dict[str, Any]] = []
    for policy in POLICY_ORDER:
        for intensity in INTENSITY_ORDER:
            rows = blocks.get((policy, intensity), [])
            resisted = sum(1 for row in rows if _is_resisted(_outcome(row)))
            interval_low, interval_high = wilson_interval(resisted, len(rows))
            curve_rows.append(
                {
                    "policy": policy,
                    "intensity": intensity,
                    "n": len(rows),
                    "resistance_percent": (100.0 * resisted / len(rows)) if rows else None,
                    "resistance_ci95_low": interval_low,
                    "resistance_ci95_high": interval_high,
                    "legitimate_latency_p95_ms": _mean(
                        _extract_legitimate_latency_p95(row) for row in rows
                    ),
                    "process_cpu_p95": _mean(_extract_cpu_p95(row) for row in rows),
                }
            )

    policy_rows: List[Dict[str, Any]] = []
    for policy in POLICY_ORDER:
        rows = [run for run in valid_runs if run.get("mfa_mode") == policy]
        resisted = sum(1 for row in rows if _is_resisted(_outcome(row)))
        interval_low, interval_high = wilson_interval(resisted, len(rows))
        policy_rows.append(
            {
                "policy": policy,
                "label": POLICY_SPECS[policy]["label"],
                "valid_n": len(rows),
                "resistance_percent": (100.0 * resisted / len(rows)) if rows else None,
                "resistance_ci95_low": interval_low,
                "resistance_ci95_high": interval_high,
                "mean_legitimate_latency_p95_ms": _mean(
                    _extract_legitimate_latency_p95(row) for row in rows
                ),
                "mean_process_cpu_p95": _mean(_extract_cpu_p95(row) for row in rows),
            }
        )
    rates = [row["resistance_percent"] for row in policy_rows if row["resistance_percent"] is not None]
    paired_rows = _paired_policy_comparisons(valid_runs)
    auth_rows: List[Dict[str, Any]] = []
    for scenario in AUTH_SCENARIO_ORDER:
        for policy in POLICY_ORDER:
            observed_rows = [
                row
                for row in authentication_runs
                if row.get("scenario") == scenario and row.get("mfa_mode") == policy
            ]
            rows = observed_rows if authentication_evidence_valid else []
            successes = sum(1 for row in rows if row.get("authentication_succeeded"))
            auth_rows.append(
                {
                    "scenario": scenario,
                    "scenario_label": AUTH_SCENARIO_SPECS[scenario]["label"],
                    "policy": policy,
                    "policy_label": POLICY_SPECS[policy]["label"],
                    "n": len(rows),
                    "authentication_success_percent": (
                        100.0 * successes / len(rows) if rows else None
                    ),
                    "mean_latency_ms": _mean(
                        row.get("latency_ms") for row in rows if row.get("latency_ms") is not None
                    ),
                    "evidence_valid": authentication_evidence_valid,
                    "recorded_n": len(observed_rows),
                }
            )
    for policy_row in policy_rows:
        valid_control_rows = [
            row
            for row in authentication_runs
            if authentication_evidence_valid
            and row.get("scenario") == "valid_factors"
            and row.get("mfa_mode") == policy_row["policy"]
            and row.get("authentication_succeeded")
        ]
        latency_statistics = student_t_summary(
            row.get("latency_ms") for row in valid_control_rows
        )
        cpu_statistics = student_t_summary(
            _dict(row.get("resource_metrics")).get("cpu_percent_equivalent")
            for row in valid_control_rows
        )
        policy_row.update(
            {
                "valid_authentication_n": latency_statistics["n"],
                "mean_valid_authentication_latency_ms": latency_statistics["mean"],
                "sd_valid_authentication_latency_ms": latency_statistics[
                    "standard_deviation"
                ],
                "ci95_valid_authentication_latency_low_ms": latency_statistics[
                    "ci95_low"
                ],
                "ci95_valid_authentication_latency_high_ms": latency_statistics[
                    "ci95_high"
                ],
                "mean_valid_authentication_cpu_percent": cpu_statistics["mean"],
                "sd_valid_authentication_cpu_percent": cpu_statistics[
                    "standard_deviation"
                ],
                "ci95_valid_authentication_cpu_low_percent": cpu_statistics[
                    "ci95_low"
                ],
                "ci95_valid_authentication_cpu_high_percent": cpu_statistics[
                    "ci95_high"
                ],
            }
        )
    return {
        "campaign_id": str(campaign["campaign_id"]),
        "protocol_id": campaign["protocol_id"],
        "scenario": campaign["scenario"],
        "topology_id": campaign["topology_id"],
        "binding_profile": campaign["binding_profile"],
        "protocol_parameters": _dict(manifest.get("protocol_parameters")),
        # JSON numbers above 2**53 cannot be reproduced exactly by common
        # JavaScript readers. The seed is an identifier, so serialize it as
        # text in every report representation.
        "seed": str(campaign["seed"]),
        "repetitions": campaign["repetitions"],
        "status": campaign["status"],
        "manifest_integrity_valid": manifest_integrity_valid,
        "planned": planned,
        "recorded": len(runs),
        "completed": completed,
        "valid": len(valid_runs),
        "task_level_valid_before_campaign_checks": len(task_level_valid_runs),
        "excluded_campaign_task_n": (
            len(task_level_valid_runs) if not analysis_eligible else 0
        ),
        "analysis_eligible": analysis_eligible,
        "technical_errors": task_classifications["technical_error"],
        "incomplete": task_classifications["incomplete"],
        "invalid_nontechnical": task_classifications["invalid_nontechnical"],
        "complete": (
            bool(planned)
            and str(campaign.get("status") or "").strip().lower() == "completed"
            and completed == planned
            and run_manifest_alignment_valid
            and manifest_integrity_valid
            and authentication_complete
            and campaign.get("_report_evidence_integrity_valid", True) is True
        ),
        "run_manifest_alignment_valid": run_manifest_alignment_valid,
        "outcome_counts": dict(outcome_counts),
        "valid_outcome_counts": dict(valid_outcome_counts),
        "curve_rows": curve_rows,
        "policy_rows": policy_rows,
        "paired_policy_rows": paired_rows,
        "policy_comparison_evidence_available": (
            len(rates) >= 2 and any(row["paired_n"] > 0 for row in paired_rows)
        ),
        "policy_spread_percentage_points": (max(rates) - min(rates)) if rates else None,
        "authentication_observations": len(authentication_runs),
        "expected_authentication_observations": expected_authentication_observations,
        "authentication_complete": authentication_complete,
        "authentication_evidence_valid": authentication_evidence_valid,
        "authentication_evidence_scope": "software_verifier_conformance",
        "authentication_rows": auth_rows,
    }


def _task_classification(run: Dict[str, Any]) -> str:
    """Classify a recorded task without turning invalid data into an outcome."""
    status = str(run.get("execution_status") or "").strip().lower()
    if status == "completed":
        return "valid_evaluable" if _valid(run) else "invalid_nontechnical"
    if status == "technical_error":
        return "technical_error"
    if status in {"", "planned", "running"}:
        return "incomplete"
    return "invalid_nontechnical"


def _ordered_values(values: Iterable[str], preferred: Sequence[str]) -> List[str]:
    observed = {str(value) for value in values if str(value)}
    return [value for value in preferred if value in observed] + sorted(
        observed.difference(preferred)
    )


def _aggregate_descriptive_row(
    records: Sequence[Tuple[str, Dict[str, Any]]],
    eligible_campaign_ids: Optional[set] = None,
    **dimensions: Any,
) -> Dict[str, Any]:
    classifications = Counter(_task_classification(run) for _, run in records)
    eligible = (
        {campaign_id for campaign_id, _ in records}
        if eligible_campaign_ids is None
        else set(eligible_campaign_ids)
    )
    valid_records = [
        item
        for item in records
        if item[0] in eligible
        and _task_classification(item[1]) == "valid_evaluable"
    ]
    resisted = sum(_is_resisted(_outcome(run)) for _, run in valid_records)
    adverse = len(valid_records) - resisted
    low, high = wilson_interval(resisted, len(valid_records))
    block_ids = {
        (campaign_id, str(run.get("sample_id") or run.get("task_id") or ""))
        for campaign_id, run in records
    }
    return {
        **dimensions,
        "campaign_n": len({campaign_id for campaign_id, _ in records}),
        "block_n": len(block_ids),
        "recorded_n": len(records),
        "valid_n": len(valid_records),
        "technical_error_n": classifications["technical_error"],
        "incomplete_n": classifications["incomplete"],
        "invalid_nontechnical_n": classifications["invalid_nontechnical"],
        "excluded_campaign_evidence_n": sum(
            1 for campaign_id, _ in records if campaign_id not in eligible
        ),
        "resisted_n": resisted,
        "adverse_outcome_n": adverse,
        "resistance_percent": 100.0 * resisted / len(valid_records) if valid_records else None,
        "resistance_ci95_low": low,
        "resistance_ci95_high": high,
        "mean_legitimate_latency_p95_ms": _mean(
            _extract_legitimate_latency_p95(run) for _, run in valid_records
        ),
        "mean_attack_latency_p95_ms": _mean(
            _extract_attack_latency_p95(run) for _, run in valid_records
        ),
        "mean_process_cpu_p95": _mean(
            _extract_cpu_p95(run) for _, run in valid_records
        ),
    }


def summarize_aggregate(
    campaign_observations: Iterable[Tuple[Dict[str, Any], List[Dict[str, Any]]]],
    *,
    selection: str = "explicit",
) -> Dict[str, Any]:
    """Build a descriptive, block-aware summary across campaigns.

    Outcome rates use valid/evaluable tasks only. Technical errors, unfinished
    tasks, and other invalid records remain explicit counts and never enter a
    success/failure denominator.
    """
    bundles = list(campaign_observations)
    if not bundles:
        raise ValueError("At least one campaign is required for aggregation")
    selected_ids = [str(campaign.get("campaign_id") or "") for campaign, _ in bundles]
    if any(not campaign_id for campaign_id in selected_ids):
        raise ValueError("Every aggregate campaign requires a campaign_id")
    if len(selected_ids) != len(set(selected_ids)):
        raise ValueError("Aggregate campaigns must be unique")

    campaign_rows: List[Dict[str, Any]] = []
    records: List[Tuple[str, Dict[str, Any]]] = []
    auth_records: List[Tuple[str, Dict[str, Any]]] = []
    individual_summaries: List[Dict[str, Any]] = []
    eligible_campaign_ids = set()
    for campaign, runs in bundles:
        campaign_id = str(campaign["campaign_id"])
        summary = summarize(campaign, runs)
        individual_summaries.append(summary)
        classifications = Counter(_task_classification(run) for run in runs)
        campaign_analysis_eligible = bool(
            str(campaign.get("status") or "").strip().lower() == "completed"
            and summary["manifest_integrity_valid"]
            and summary["run_manifest_alignment_valid"]
            and summary["authentication_complete"]
            and summary["authentication_evidence_valid"]
            and campaign.get("_report_evidence_integrity_valid", True) is True
        )
        if campaign_analysis_eligible:
            eligible_campaign_ids.add(campaign_id)
        campaign_rows.append(
            {
                "campaign_id": campaign_id,
                "protocol_id": str(campaign.get("protocol_id") or ""),
                "implementation_revision": str(
                    _dict(_dict(campaign.get("manifest")).get("protocol_parameters")).get(
                        "implementation_revision"
                    )
                    or "unrecorded"
                ),
                "scenario": str(campaign.get("scenario") or ""),
                "topology_id": str(campaign.get("topology_id") or ""),
                "binding_profile": str(campaign.get("binding_profile") or ""),
                "seed": str(campaign.get("seed")),
                "repetitions": campaign.get("repetitions"),
                "status": str(campaign.get("status") or ""),
                "planned_n": summary["planned"],
                "recorded_n": len(runs),
                "completed_n": summary["completed"],
                "valid_n": classifications["valid_evaluable"],
                "technical_error_n": classifications["technical_error"],
                "incomplete_n": classifications["incomplete"],
                "invalid_nontechnical_n": classifications["invalid_nontechnical"],
                "campaign_complete": summary["complete"],
                "manifest_integrity_valid": summary["manifest_integrity_valid"],
                "run_manifest_alignment_valid": summary["run_manifest_alignment_valid"],
                "authentication_observations": summary["authentication_observations"],
                "authentication_complete": summary["authentication_complete"],
                "authentication_evidence_valid": summary["authentication_evidence_valid"],
                "analysis_eligible": campaign_analysis_eligible,
                "outcome_evaluable": classifications["valid_evaluable"] > 0,
                "strictly_complete": bool(
                    summary["complete"]
                    and classifications["technical_error"] == 0
                    and classifications["incomplete"] == 0
                    and classifications["invalid_nontechnical"] == 0
                ),
            }
        )
        records.extend((campaign_id, run) for run in runs)
        if campaign_analysis_eligible:
            auth_records.extend(
                (campaign_id, row)
                for row in list(campaign.get("authentication_runs") or [])
            )

    scenario_order = _ordered_values(
        (str(run.get("scenario") or "") for _, run in records),
        list(SCENARIO_SPECS),
    )
    intensity_order = _ordered_values(
        (str(run.get("intensity_level") or "") for _, run in records),
        INTENSITY_ORDER,
    )
    policy_order = _ordered_values(
        (str(run.get("mfa_mode") or "") for _, run in records),
        POLICY_ORDER,
    )

    def selected(**values: str) -> List[Tuple[str, Dict[str, Any]]]:
        return [
            item
            for item in records
            if all(str(item[1].get(field) or "") == value for field, value in values.items())
        ]

    scenario_rows = [
        _aggregate_descriptive_row(
            selected(scenario=scenario), eligible_campaign_ids, scenario=scenario
        )
        for scenario in scenario_order
    ]
    policy_rows = [
        _aggregate_descriptive_row(
            selected(mfa_mode=policy), eligible_campaign_ids, policy=policy
        )
        for policy in policy_order
    ]
    scenario_intensity_rows = [
        _aggregate_descriptive_row(
            selected(scenario=scenario, intensity_level=intensity),
            eligible_campaign_ids,
            scenario=scenario,
            intensity=intensity,
        )
        for scenario in scenario_order
        for intensity in intensity_order
        if selected(scenario=scenario, intensity_level=intensity)
    ]
    scenario_policy_rows = [
        _aggregate_descriptive_row(
            selected(scenario=scenario, mfa_mode=policy),
            eligible_campaign_ids,
            scenario=scenario,
            policy=policy,
        )
        for scenario in scenario_order
        for policy in policy_order
        if selected(scenario=scenario, mfa_mode=policy)
    ]
    scenario_intensity_policy_rows = [
        _aggregate_descriptive_row(
            selected(
                scenario=scenario,
                intensity_level=intensity,
                mfa_mode=policy,
            ),
            eligible_campaign_ids,
            scenario=scenario,
            intensity=intensity,
            policy=policy,
        )
        for scenario in scenario_order
        for intensity in intensity_order
        for policy in policy_order
        if selected(
            scenario=scenario,
            intensity_level=intensity,
            mfa_mode=policy,
        )
    ]

    quality_rows: List[Dict[str, Any]] = []
    for scenario in scenario_order:
        rows = selected(scenario=scenario)
        quality = Counter()
        for campaign_id, run in rows:
            if campaign_id not in eligible_campaign_ids:
                quality["excluded_campaign_evidence"] += 1
            else:
                quality[_task_classification(run)] += 1
        quality_rows.append(
            {
                "scenario": scenario,
                "recorded_n": len(rows),
                "valid_evaluable_n": quality["valid_evaluable"],
                "technical_error_n": quality["technical_error"],
                "incomplete_n": quality["incomplete"],
                "invalid_nontechnical_n": quality["invalid_nontechnical"],
                "excluded_campaign_evidence_n": quality[
                    "excluded_campaign_evidence"
                ],
            }
        )

    technical_error_groups: Dict[Tuple[str, str], List[Tuple[str, Dict[str, Any]]]] = defaultdict(list)
    for campaign_id, run in records:
        if _task_classification(run) != "technical_error":
            continue
        result = _dict(run.get("observed_result"))
        metrics = _dict(result.get("metrics"))
        error_type = str(
            metrics.get("error_type")
            or result.get("error_type")
            or "unspecified_technical_error"
        )
        technical_error_groups[(str(run.get("scenario") or ""), error_type)].append(
            (campaign_id, run)
        )
    technical_error_rows = []
    for (scenario, error_type), rows in sorted(technical_error_groups.items()):
        technical_error_rows.append(
            {
                "scenario": scenario,
                "error_type": error_type,
                "task_n": len(rows),
                "affected_block_n": len(
                    {
                        (
                            campaign_id,
                            str(run.get("sample_id") or run.get("task_id") or ""),
                        )
                        for campaign_id, run in rows
                    }
                ),
                "campaign_n": len({campaign_id for campaign_id, _ in rows}),
            }
        )

    block_records: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for campaign_id, run in records:
        block_key = str(run.get("sample_id") or run.get("task_id") or "")
        block_records[(campaign_id, block_key)].append(run)
    block_rows: List[Dict[str, Any]] = []
    for (campaign_id, sample_id), block_runs in block_records.items():
        scenario = str(block_runs[0].get("scenario") or "")
        intensity = str(block_runs[0].get("intensity_level") or "")
        metadata_consistent = (
            len({str(run.get("scenario") or "") for run in block_runs}) == 1
            and len({str(run.get("intensity_level") or "") for run in block_runs}) == 1
            and len({str(run.get("repetition") or "") for run in block_runs}) == 1
        )
        parameter_signatures = {
            _canonical_json(_dict(run.get("sampled_parameters")))
            for run in block_runs
            if _dict(run.get("sampled_parameters"))
        }
        paired_parameters_consistent = (
            len(parameter_signatures) == 1
            and all(bool(_dict(run.get("sampled_parameters"))) for run in block_runs)
        )
        policies = Counter(str(run.get("mfa_mode") or "") for run in block_runs)
        valid_by_policy = {
            str(run.get("mfa_mode") or ""): run
            for run in block_runs
            if _task_classification(run) == "valid_evaluable"
        }
        complete_recorded = (
            len(block_runs) == len(POLICY_ORDER)
            and set(policies) == set(POLICY_ORDER)
            and all(policies[policy] == 1 for policy in POLICY_ORDER)
        )
        comparable = (
            campaign_id in eligible_campaign_ids
            and complete_recorded
            and metadata_consistent
            and paired_parameters_consistent
            and all(policy in valid_by_policy for policy in POLICY_ORDER)
        )
        resisted_n = sum(
            _is_resisted(_outcome(run)) for run in valid_by_policy.values()
        )
        if not comparable:
            pattern = "not_comparable"
        elif resisted_n == len(POLICY_ORDER):
            pattern = "unanimous_resisted"
        elif resisted_n == 0:
            pattern = "unanimous_adverse"
        else:
            pattern = "mixed_policy_outcomes"
        classifications = Counter(_task_classification(run) for run in block_runs)
        block_rows.append(
            {
                "campaign_id": campaign_id,
                "sample_id": sample_id,
                "scenario": scenario,
                "intensity": intensity,
                "repetition": block_runs[0].get("repetition"),
                "recorded_policy_n": len(block_runs),
                "valid_policy_n": classifications["valid_evaluable"],
                "technical_error_n": classifications["technical_error"],
                "incomplete_n": classifications["incomplete"],
                "invalid_nontechnical_n": classifications["invalid_nontechnical"],
                "complete_recorded_block": complete_recorded,
                "campaign_evidence_valid": campaign_id in eligible_campaign_ids,
                "metadata_consistent": metadata_consistent,
                "paired_parameters_consistent": paired_parameters_consistent,
                "comparable_valid_block": comparable,
                "valid_resisted_policy_n": resisted_n,
                "outcome_pattern": pattern,
            }
        )

    block_summary_rows: List[Dict[str, Any]] = []
    for scenario in scenario_order:
        for intensity in intensity_order:
            rows = [
                row
                for row in block_rows
                if row["scenario"] == scenario and row["intensity"] == intensity
            ]
            if not rows:
                continue
            comparable_rows = [row for row in rows if row["comparable_valid_block"]]
            block_summary_rows.append(
                {
                    "scenario": scenario,
                    "intensity": intensity,
                    "campaign_n": len({row["campaign_id"] for row in rows}),
                    "block_n": len(rows),
                    "complete_recorded_block_n": sum(row["complete_recorded_block"] for row in rows),
                    "comparable_valid_block_n": len(comparable_rows),
                    "not_comparable_block_n": len(rows) - len(comparable_rows),
                    "unanimous_resisted_block_n": sum(
                        row["outcome_pattern"] == "unanimous_resisted" for row in comparable_rows
                    ),
                    "unanimous_adverse_block_n": sum(
                        row["outcome_pattern"] == "unanimous_adverse" for row in comparable_rows
                    ),
                    "mixed_policy_outcome_block_n": sum(
                        row["outcome_pattern"] == "mixed_policy_outcomes" for row in comparable_rows
                    ),
                }
            )

    paired_policy_rows: List[Dict[str, Any]] = []
    comparable_block_keys = {
        (row["campaign_id"], row["sample_id"])
        for row in block_rows
        if row["comparable_valid_block"]
    }
    for scenario in scenario_order:
        for intensity in intensity_order:
            relevant_blocks = [
                ((campaign_id, sample_id), block_runs)
                for (campaign_id, sample_id), block_runs in block_records.items()
                if (campaign_id, sample_id) in comparable_block_keys
                and str(block_runs[0].get("scenario") or "") == scenario
                and str(block_runs[0].get("intensity_level") or "") == intensity
            ]
            if not relevant_blocks:
                continue
            for left_index, left in enumerate(policy_order):
                for right in policy_order[left_index + 1:]:
                    pairs: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
                    for _, block_runs in relevant_blocks:
                        valid_by_policy = {
                            str(run.get("mfa_mode") or ""): run
                            for run in block_runs
                            if _task_classification(run) == "valid_evaluable"
                        }
                        if left in valid_by_policy and right in valid_by_policy:
                            pairs.append((valid_by_policy[left], valid_by_policy[right]))
                    if not pairs:
                        continue
                    left_only = sum(
                        _is_resisted(_outcome(left_run))
                        and not _is_resisted(_outcome(right_run))
                        for left_run, right_run in pairs
                    )
                    right_only = sum(
                        _is_resisted(_outcome(right_run))
                        and not _is_resisted(_outcome(left_run))
                        for left_run, right_run in pairs
                    )
                    both_resisted = sum(
                        _is_resisted(_outcome(left_run))
                        and _is_resisted(_outcome(right_run))
                        for left_run, right_run in pairs
                    )
                    both_adverse = len(pairs) - left_only - right_only - both_resisted
                    paired_policy_rows.append(
                        {
                            "scenario": scenario,
                            "intensity": intensity,
                            "left_policy": left,
                            "right_policy": right,
                            "paired_valid_block_n": len(pairs),
                            "both_resisted_n": both_resisted,
                            "both_adverse_n": both_adverse,
                            "left_only_resisted_n": left_only,
                            "right_only_resisted_n": right_only,
                            "discordant_n": left_only + right_only,
                            "interpretation": "descriptive_only_not_equivalence",
                        }
                    )

    def observed_metric(run: Dict[str, Any], key: str) -> Optional[float]:
        metrics = _dict(_dict(run.get("observed_result")).get("metrics"))
        value = metrics.get(key)
        try:
            parsed = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return parsed if math.isfinite(parsed) else None

    def resource_stat(
        run: Dict[str, Any], family: str, statistic: str, scale: float = 1.0
    ) -> Optional[float]:
        resource = _dict(run.get("resource_metrics"))
        values = _dict(resource.get(family))
        try:
            parsed = float(values.get(statistic)) / float(scale)
        except (TypeError, ValueError, OverflowError, ZeroDivisionError):
            return None
        return parsed if math.isfinite(parsed) else None

    availability_phase_rows: List[Dict[str, Any]] = []
    block_metric_rows: List[Dict[str, Any]] = []
    for scenario in scenario_order:
        for intensity in intensity_order:
            relevant_blocks = [
                block_runs
                for (campaign_id, sample_id), block_runs in block_records.items()
                if (campaign_id, sample_id) in comparable_block_keys
                and str(block_runs[0].get("scenario") or "") == scenario
                and str(block_runs[0].get("intensity_level") or "") == intensity
            ]
            if not relevant_blocks:
                continue
            for phase in ("baseline", "during", "recovery"):
                block_values = [
                    value
                    for value in (
                        _mean(
                            observed_metric(run, "%s_availability_rate" % phase)
                            for run in block_runs
                        )
                        for block_runs in relevant_blocks
                    )
                    if value is not None
                ]
                if block_values:
                    phase_statistics = student_t_summary(
                        100.0 * value for value in block_values
                    )
                    availability_phase_rows.append(
                        {
                            "scenario": scenario,
                            "intensity": intensity,
                            "phase": phase,
                            "block_n": len(block_values),
                            "mean_availability_percent": phase_statistics["mean"],
                            "sd_availability_percent": phase_statistics[
                                "standard_deviation"
                            ],
                            "ci95_availability_low_percent": phase_statistics[
                                "ci95_low"
                            ],
                            "ci95_availability_high_percent": phase_statistics[
                                "ci95_high"
                            ],
                            "analysis_unit": "sample_id_block_mean_across_policies",
                        }
                    )
            for metric, extractor, unit in (
                (
                    "legitimate_http_p95_latency_ms",
                    _extract_legitimate_latency_p95,
                    "ms",
                ),
                ("controller_cpu_p95_percent", _extract_cpu_p95, "percent"),
                (
                    "controller_rss_p95_mib",
                    lambda run: resource_stat(
                        run, "process_rss_bytes", "p95", 1024.0 * 1024.0
                    ),
                    "MiB",
                ),
                (
                    "system_cpu_p95_percent",
                    lambda run: resource_stat(run, "system_cpu_percent", "p95"),
                    "percent",
                ),
                (
                    "system_memory_p95_percent",
                    lambda run: resource_stat(
                        run, "system_memory_percent", "p95"
                    ),
                    "percent",
                ),
                (
                    "rate_achievement_percent",
                    lambda run: observed_metric(run, "rate_achievement_percent"),
                    "percent",
                ),
                (
                    "packet_delivery_percent",
                    lambda run: observed_metric(run, "packet_delivery_percent"),
                    "percent",
                ),
            ):
                block_values = [
                    value
                    for value in (
                        _mean(extractor(run) for run in block_runs)
                        for block_runs in relevant_blocks
                    )
                    if value is not None
                ]
                if block_values:
                    metric_statistics = student_t_summary(block_values)
                    block_metric_rows.append(
                        {
                            "scenario": scenario,
                            "intensity": intensity,
                            "metric": metric,
                            "unit": unit,
                            "block_n": len(block_values),
                            "mean": metric_statistics["mean"],
                            "standard_deviation": metric_statistics[
                                "standard_deviation"
                            ],
                            "ci95_low": metric_statistics["ci95_low"],
                            "ci95_high": metric_statistics["ci95_high"],
                            "analysis_unit": "sample_id_block_mean_across_policies",
                        }
                    )

    verifier_rows: List[Dict[str, Any]] = []
    auth_scenarios = _ordered_values(
        (str(row.get("scenario") or "") for _, row in auth_records),
        AUTH_SCENARIO_ORDER,
    )
    auth_policies = _ordered_values(
        (str(row.get("mfa_mode") or "") for _, row in auth_records),
        POLICY_ORDER,
    )
    for scenario in auth_scenarios:
        for policy in auth_policies:
            rows = [
                (campaign_id, row)
                for campaign_id, row in auth_records
                if str(row.get("scenario") or "") == scenario
                and str(row.get("mfa_mode") or "") == policy
            ]
            if not rows:
                continue
            successes = sum(bool(row.get("authentication_succeeded")) for _, row in rows)
            latency_statistics = student_t_summary(
                row.get("latency_ms") for _, row in rows
            )
            cpu_statistics = student_t_summary(
                _dict(row.get("resource_metrics")).get("cpu_percent_equivalent")
                for _, row in rows
            )
            verifier_rows.append(
                {
                    "scenario": scenario,
                    "scenario_label": AUTH_SCENARIO_SPECS.get(scenario, {}).get("label", scenario),
                    "policy": policy,
                    "policy_label": POLICY_SPECS.get(policy, {}).get("label", policy),
                    "campaign_n": len({campaign_id for campaign_id, _ in rows}),
                    "observation_n": len(rows),
                    "authentication_success_n": successes,
                    "authentication_success_percent": 100.0 * successes / len(rows),
                    "mean_latency_ms": latency_statistics["mean"],
                    "sd_latency_ms": latency_statistics["standard_deviation"],
                    "ci95_latency_low_ms": latency_statistics["ci95_low"],
                    "ci95_latency_high_ms": latency_statistics["ci95_high"],
                    "mean_cpu_percent": cpu_statistics["mean"],
                    "sd_cpu_percent": cpu_statistics["standard_deviation"],
                    "ci95_cpu_low_percent": cpu_statistics["ci95_low"],
                    "ci95_cpu_high_percent": cpu_statistics["ci95_high"],
                    "evidence_scope": "software_verifier_conformance",
                }
            )

    total_classifications = Counter(_task_classification(run) for _, run in records)
    inference_classifications = Counter(
        _task_classification(run)
        for campaign_id, run in records
        if campaign_id in eligible_campaign_ids
    )
    aggregate_id_source = "|".join(sorted(row["campaign_id"] for row in campaign_rows))
    aggregate_id = "aggregate-%s" % hashlib.sha256(
        aggregate_id_source.encode("utf-8")
    ).hexdigest()[:16]
    valid_outcome_counts = Counter(
        _outcome(run)
        for campaign_id, run in records
        if campaign_id in eligible_campaign_ids
        and _task_classification(run) == "valid_evaluable"
    )
    factor_resistance_rows = factor_compromise_resistance_rows(verifier_rows)
    return {
        "report_type": "multi_campaign_aggregate",
        "release_label": "v2",
        "aggregate_id": aggregate_id,
        "selection": selection,
        "campaign_ids": [row["campaign_id"] for row in campaign_rows],
        "campaign_n": len(campaign_rows),
        "campaign_status_counts": dict(Counter(row["status"] for row in campaign_rows)),
        "analysis_eligible_campaign_n": len(eligible_campaign_ids),
        "excluded_campaign_n": len(campaign_rows) - len(eligible_campaign_ids),
        "campaign_rows": campaign_rows,
        "recorded_task_n": len(records),
        "valid_task_n": inference_classifications["valid_evaluable"],
        "task_level_valid_before_campaign_checks_n": total_classifications[
            "valid_evaluable"
        ],
        "excluded_campaign_task_n": sum(
            1 for campaign_id, _ in records if campaign_id not in eligible_campaign_ids
        ),
        "technical_error_task_n": total_classifications["technical_error"],
        "incomplete_task_n": total_classifications["incomplete"],
        "invalid_nontechnical_task_n": total_classifications["invalid_nontechnical"],
        "valid_outcome_counts": dict(valid_outcome_counts),
        "complete": all(summary["complete"] for summary in individual_summaries),
        "all_manifest_integrity_valid": all(
            summary["manifest_integrity_valid"] for summary in individual_summaries
        ),
        "all_authentication_evidence_complete": all(
            summary["authentication_complete"] for summary in individual_summaries
        ),
        "scenario_rows": scenario_rows,
        "policy_rows": policy_rows,
        "scenario_intensity_rows": scenario_intensity_rows,
        "scenario_policy_rows": scenario_policy_rows,
        "scenario_intensity_policy_rows": scenario_intensity_policy_rows,
        "quality_rows": quality_rows,
        "technical_error_rows": technical_error_rows,
        "block_rows": block_rows,
        "block_summary_rows": block_summary_rows,
        "availability_phase_rows": availability_phase_rows,
        "block_metric_rows": block_metric_rows,
        "paired_policy_descriptive_rows": paired_policy_rows,
        "software_verifier_conformance_rows": verifier_rows,
        "factor_compromise_resistance_rows": factor_resistance_rows,
        "statistical_scope": {
            "rates": "valid_evaluable_tasks_only",
            "invalid_tasks": "reported_separately_not_outcomes",
            "wilson_intervals": "descriptive_task_level_not_block_adjusted",
            "paired_policy_rows": "descriptive_only_no_equivalence_claim",
            "factor_matrix": "software_verifier_conformance_not_physical_biometric_validation",
        },
    }


def _chart_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11,
            "axes.titlesize": 16,
            "axes.labelsize": 12,
            "axes.edgecolor": "#94a3b8",
            "axes.grid": True,
            "grid.alpha": 0.22,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
        }
    )


def _save_charts(
    summary: Dict[str, Any], chart_dir: Path, persian: bool = False
) -> Dict[str, str]:
    _chart_style()
    chart_dir.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, str] = {}
    policy_labels = {
        policy: _chart_text(
            PERSIAN_POLICY_LABELS[policy]
            if persian
            else POLICY_SPECS[policy]["label"],
            persian,
        )
        for policy in POLICY_ORDER
    }

    fig, axis = plt.subplots(figsize=(12.5, 6.5))
    x = list(range(len(INTENSITY_ORDER)))
    for policy_index, policy in enumerate(POLICY_ORDER):
        rows = [row for row in summary["curve_rows"] if row["policy"] == policy]
        horizontal_offset = (policy_index - (len(POLICY_ORDER) - 1) / 2.0) * 0.045
        policy_x = [value + horizontal_offset for value in x]
        values = [float(row["resistance_percent"]) if row["resistance_percent"] is not None else float("nan") for row in rows]
        lower_error = [
            value - float(row["resistance_ci95_low"])
            if row["resistance_ci95_low"] is not None and value == value else 0.0
            for value, row in zip(values, rows)
        ]
        upper_error = [
            float(row["resistance_ci95_high"]) - value
            if row["resistance_ci95_high"] is not None and value == value else 0.0
            for value, row in zip(values, rows)
        ]
        axis.errorbar(
            policy_x,
            values,
            yerr=[lower_error, upper_error],
            marker=MARKERS[policy],
            markersize=8,
            linewidth=2.8,
            capsize=4,
            linestyle=LINE_STYLES[policy],
            color=COLORS[policy],
            label=policy_labels[policy],
        )
    axis.set_xticks(
        x,
        [
            _chart_text(
                PERSIAN_INTENSITY_LABELS[item] if persian else item.title(),
                persian,
            )
            for item in INTENSITY_ORDER
        ],
    )
    axis.set_ylim(-2, 102)
    axis.set_ylabel(_chart_text("مقاومت مشاهده‌شده (درصد)" if persian else "Observed resistance (%)", persian))
    axis.set_xlabel(_chart_text("شدت ترافیک تعریف‌شده" if persian else "Declared traffic intensity", persian))
    axis.set_title(_chart_text("پاسخ امنیت و دسترس‌پذیری (بازه اطمینان ۹۵ درصد)" if persian else "Observed security/availability response (95% Wilson intervals)", persian))
    axis.legend(ncol=2, frameon=False, loc="lower left")
    fig.tight_layout()
    curve_path = chart_dir / "resistance_curve.png"
    fig.savefig(curve_path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    paths["curve"] = curve_path.name

    fig, axis = plt.subplots(figsize=(11.5, 6.2))
    policy_rows = summary["policy_rows"]
    labels = [policy_labels[row["policy"]] for row in policy_rows]
    values = [
        float(row["resistance_percent"])
        if row["resistance_percent"] is not None
        else float("nan")
        for row in policy_rows
    ]
    lower_error = [
        value - float(row["resistance_ci95_low"])
        if row["resistance_ci95_low"] is not None and value == value else 0.0
        for value, row in zip(values, policy_rows)
    ]
    upper_error = [
        float(row["resistance_ci95_high"]) - value
        if row["resistance_ci95_high"] is not None and value == value else 0.0
        for value, row in zip(values, policy_rows)
    ]
    bars = axis.bar(
        labels,
        values,
        yerr=[lower_error, upper_error],
        capsize=5,
        color=[COLORS[row["policy"]] for row in policy_rows],
        width=0.62,
    )
    axis.set_ylim(0, 108)
    axis.set_ylabel(_chart_text("مقاومت مشاهده‌شده (درصد)" if persian else "Observed resistance (%)", persian))
    axis.set_title(_chart_text("مقایسه سیاست‌ها با اتصال شبکه یکسان (بازه اطمینان ۹۵ درصد)" if persian else "Policy comparison under one controlled binding (95% CI)", persian))
    axis.tick_params(axis="x", rotation=12)
    for bar, value in zip(bars, values):
        if value == value:
            axis.text(bar.get_x() + bar.get_width() / 2, value + 2, "%.1f%%" % value, ha="center", fontweight="bold")
    fig.tight_layout()
    policy_path = chart_dir / "policy_comparison.png"
    fig.savefig(policy_path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    paths["policy"] = policy_path.name

    counts = summary["outcome_counts"]
    nonzero = [(key, value) for key, value in counts.items() if value]
    fig, axis = plt.subplots(figsize=(8.2, 6.2))
    if nonzero:
        axis.pie(
            [value for _, value in nonzero],
            labels=[
                _chart_text(
                    PERSIAN_OUTCOME_LABELS.get(key, key)
                    if persian
                    else key.replace("_", " ").title(),
                    persian,
                )
                for key, _ in nonzero
            ],
            colors=[OUTCOME_COLORS.get(key, "#64748b") for key, _ in nonzero],
            autopct="%1.1f%%",
            startangle=90,
            wedgeprops={"width": 0.42, "edgecolor": "white"},
        )
    else:
        axis.text(0.5, 0.5, _chart_text("بدون مشاهده" if persian else "No observations", persian), ha="center", va="center")
    axis.set_title(_chart_text("ترکیب پیامدهای ثبت‌شده" if persian else "Recorded outcome composition", persian))
    fig.tight_layout()
    outcome_path = chart_dir / "outcome_composition.png"
    fig.savefig(outcome_path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    paths["outcome"] = outcome_path.name

    fig, axes = plt.subplots(2, 2, figsize=(14.5, 10.2))
    latency = [
        row["mean_legitimate_latency_p95_ms"]
        if row["mean_legitimate_latency_p95_ms"] is not None
        else float("nan")
        for row in policy_rows
    ]
    cpu = [
        row["mean_process_cpu_p95"]
        if row["mean_process_cpu_p95"] is not None
        else float("nan")
        for row in policy_rows
    ]
    colors = [COLORS[row["policy"]] for row in policy_rows]
    auth_latency = [
        row["mean_valid_authentication_latency_ms"]
        if row["mean_valid_authentication_latency_ms"] is not None
        else float("nan")
        for row in policy_rows
    ]
    auth_cpu = [
        row["mean_valid_authentication_cpu_percent"]
        if row["mean_valid_authentication_cpu_percent"] is not None
        else float("nan")
        for row in policy_rows
    ]
    axes[0, 0].bar(labels, auth_latency, color=colors)
    axes[0, 0].set_title(_chart_text("میانگین تأخیر راستی‌آزمای MFA معتبر" if persian else "Mean valid-control MFA verifier latency", persian))
    axes[0, 0].set_ylabel(_chart_text("میلی‌ثانیه" if persian else "Milliseconds", persian))
    axes[0, 1].bar(labels, auth_cpu, color=colors)
    axes[0, 1].set_title(_chart_text("میانگین مصرف معادل CPU در MFA" if persian else "Mean MFA verifier CPU equivalent", persian))
    axes[0, 1].set_ylabel(_chart_text("درصد CPU" if persian else "CPU percent", persian))
    axes[1, 0].bar(labels, latency, color=colors)
    axes[1, 0].set_title(_chart_text("میانگین تأخیر P95 درخواست مجاز HTTP" if persian else "Mean legitimate-control HTTP p95 latency", persian))
    axes[1, 0].set_ylabel(_chart_text("میلی‌ثانیه" if persian else "Milliseconds", persian))
    axes[1, 1].bar(labels, cpu, color=colors)
    axes[1, 1].set_title(_chart_text("میانگین مصرف P95 پردازنده کنترلر Ryu" if persian else "Mean Ryu controller CPU p95", persian))
    axes[1, 1].set_ylabel(_chart_text("درصد CPU" if persian else "CPU percent", persian))
    for axis in axes.flat:
        axis.tick_params(axis="x", rotation=18)
    fig.tight_layout()
    performance_path = chart_dir / "performance_profile.png"
    fig.savefig(performance_path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    paths["performance"] = performance_path.name

    fig, axis = plt.subplots(figsize=(12.5, 6.5))
    matrix = []
    for scenario in AUTH_SCENARIO_ORDER:
        row_values = []
        for policy in POLICY_ORDER:
            match = next(
                row
                for row in summary["authentication_rows"]
                if row["scenario"] == scenario and row["policy"] == policy
            )
            value = match["authentication_success_percent"]
            row_values.append(float(value) if value is not None else float("nan"))
        matrix.append(row_values)
    image = axis.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=100, aspect="auto")
    axis.set_xticks(range(len(POLICY_ORDER)), [policy_labels[item] for item in POLICY_ORDER], rotation=14)
    axis.set_yticks(
        range(len(AUTH_SCENARIO_ORDER)),
        [
            _chart_text(
                PERSIAN_AUTH_SCENARIO_LABELS[item]
                if persian
                else AUTH_SCENARIO_SPECS[item]["label"],
                persian,
            )
            for item in AUTH_SCENARIO_ORDER
        ],
    )
    axis.set_title(_chart_text("انطباق راستی‌آزمای نرم‌افزاری با دسترس‌پذیری کنترل‌شده عوامل" if persian else "Software verifier conformance under controlled factor availability", persian))
    for row_index, row in enumerate(matrix):
        for column_index, value in enumerate(row):
            label = "—" if value != value else "%.0f%%" % value
            axis.text(column_index, row_index, label, ha="center", va="center", fontweight="bold", color="#0f172a")
    fig.colorbar(
        image,
        ax=axis,
        label=_chart_text("موفقیت احراز هویت (درصد)" if persian else "Authentication success (%)", persian),
    )
    fig.tight_layout()
    auth_path = chart_dir / "factor_availability_matrix.png"
    fig.savefig(auth_path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    paths["authentication"] = auth_path.name
    return paths


def _write_csv(
    output_dir: Path,
    summary: Dict[str, Any],
    runs: List[Dict[str, Any]],
) -> List[Path]:
    """Write single-campaign tables and return the exact generated files."""
    data_dir = output_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    written_paths: List[Path] = []
    policy_path = data_dir / "policy_summary.csv"
    with policy_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary["policy_rows"][0]))
        writer.writeheader()
        writer.writerows(summary["policy_rows"])
    written_paths.append(policy_path)
    curve_path = data_dir / "intensity_curve.csv"
    with curve_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary["curve_rows"][0]))
        writer.writeheader()
        writer.writerows(summary["curve_rows"])
    written_paths.append(curve_path)
    if summary["paired_policy_rows"]:
        paired_path = data_dir / "paired_policy_comparison.csv"
        with paired_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=list(summary["paired_policy_rows"][0]),
            )
            writer.writeheader()
            writer.writerows(summary["paired_policy_rows"])
        written_paths.append(paired_path)
    if summary["authentication_rows"]:
        authentication_path = data_dir / "authentication_factor_matrix.csv"
        with authentication_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(summary["authentication_rows"][0]))
            writer.writeheader()
            writer.writerows(summary["authentication_rows"])
        written_paths.append(authentication_path)
    detail_rows = []
    for run in runs:
        params = _dict(run.get("sampled_parameters"))
        detail_rows.append(
            {
                "task_id": run.get("task_id"),
                "sample_id": run.get("sample_id"),
                "repetition": run.get("repetition"),
                "intensity": run.get("intensity_level"),
                "policy": run.get("mfa_mode"),
                "duration_seconds": params.get("duration_seconds"),
                "rate_pps": params.get("rate_pps"),
                "request_count": params.get("request_count"),
                "payload_size_bytes": params.get("payload_size_bytes"),
                "source_count": params.get("source_count"),
                "offered_load_ratio": params.get("offered_load_ratio"),
                "outcome": _outcome(run),
                "task_level_valid": _valid(run),
                "campaign_analysis_eligible": summary["analysis_eligible"],
                "valid": summary["analysis_eligible"] and _valid(run),
                "legitimate_latency_p95_ms": _extract_legitimate_latency_p95(run),
                "attack_latency_p95_ms": _extract_attack_latency_p95(run),
                "process_cpu_p95": _extract_cpu_p95(run),
                "pcap_sha256": _dict(run.get("pcap_evidence")).get("sha256"),
            }
        )
    if detail_rows:
        details_path = data_dir / "run_details.csv"
        with details_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(detail_rows[0]))
            writer.writeheader()
            writer.writerows(detail_rows)
        written_paths.append(details_path)
    summary_path = data_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, default=str), encoding="utf-8"
    )
    written_paths.append(summary_path)
    return written_paths


def _write_dict_rows(
    path: Path,
    rows: Sequence[Dict[str, Any]],
    fieldnames: Sequence[str],
) -> Path:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        writer.writerows(rows)
    return path


def _aggregate_run_detail_rows(
    campaign_observations: Sequence[Tuple[Dict[str, Any], List[Dict[str, Any]]]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for campaign, runs in campaign_observations:
        campaign_id = str(campaign["campaign_id"])
        for run in runs:
            params = _dict(run.get("sampled_parameters"))
            result_metrics = _dict(_dict(run.get("observed_result")).get("metrics"))
            classification = _task_classification(run)
            evaluable = classification == "valid_evaluable"
            rows.append(
                {
                    "campaign_id": campaign_id,
                    "task_id": run.get("task_id"),
                    "sample_id": run.get("sample_id"),
                    "scenario": run.get("scenario"),
                    "repetition": run.get("repetition"),
                    "intensity": run.get("intensity_level"),
                    "policy": run.get("mfa_mode"),
                    "execution_status": run.get("execution_status"),
                    "task_classification": classification,
                    "is_valid": run.get("is_valid"),
                    "outcome": _outcome(run),
                    "resisted": _is_resisted(_outcome(run)) if evaluable else None,
                    "error_type": result_metrics.get("error_type"),
                    "duration_seconds": params.get("duration_seconds"),
                    "rate_pps": params.get("rate_pps"),
                    "request_count": params.get("request_count"),
                    "payload_size_bytes": params.get("payload_size_bytes"),
                    "source_count": params.get("source_count"),
                    "offered_load_ratio": params.get("offered_load_ratio"),
                    "legitimate_latency_p95_ms": _extract_legitimate_latency_p95(run),
                    "attack_latency_p95_ms": _extract_attack_latency_p95(run),
                    "process_cpu_p95": _extract_cpu_p95(run),
                    "pcap_sha256": _dict(run.get("pcap_evidence")).get("sha256"),
                }
            )
    return rows


def _write_aggregate_csv(
    output_dir: Path,
    summary: Dict[str, Any],
    campaign_observations: Sequence[Tuple[Dict[str, Any], List[Dict[str, Any]]]],
) -> List[Path]:
    """Write the structured multi-campaign evidence bundle."""
    data_dir = output_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    written_paths: List[Path] = []
    descriptive_metrics = [
        "campaign_n",
        "block_n",
        "recorded_n",
        "valid_n",
        "technical_error_n",
        "incomplete_n",
        "invalid_nontechnical_n",
        "excluded_campaign_evidence_n",
        "resisted_n",
        "adverse_outcome_n",
        "resistance_percent",
        "resistance_ci95_low",
        "resistance_ci95_high",
        "mean_legitimate_latency_p95_ms",
        "mean_attack_latency_p95_ms",
        "mean_process_cpu_p95",
    ]
    empty_fields = {
        "aggregate_campaigns.csv": [
            "campaign_id", "protocol_id", "implementation_revision", "scenario",
            "topology_id", "binding_profile", "seed", "repetitions", "status",
            "planned_n", "recorded_n",
            "completed_n", "valid_n", "technical_error_n", "incomplete_n",
            "invalid_nontechnical_n", "campaign_complete",
            "manifest_integrity_valid", "run_manifest_alignment_valid",
            "authentication_observations", "authentication_complete",
            "authentication_evidence_valid", "analysis_eligible",
            "outcome_evaluable", "strictly_complete",
            "manifest_payload_checksum_valid", "manifest_file_checksum_valid",
            "pcap_expected_n",
            "pcap_verified_n", "pcap_missing_n", "pcap_mismatch_n",
            "pcap_unverified_n", "pcap_evidence_complete",
            "evidence_integrity_valid",
        ],
        "aggregate_scenarios.csv": ["scenario"] + descriptive_metrics,
        "aggregate_policies.csv": ["policy"] + descriptive_metrics,
        "aggregate_scenario_intensity.csv": ["scenario", "intensity"] + descriptive_metrics,
        "aggregate_scenario_policy.csv": ["scenario", "policy"] + descriptive_metrics,
        "aggregate_scenario_intensity_policy.csv": [
            "scenario", "intensity", "policy"
        ] + descriptive_metrics,
        "aggregate_block_details.csv": [
            "campaign_id", "sample_id", "scenario", "intensity", "repetition",
            "recorded_policy_n", "valid_policy_n", "technical_error_n",
            "incomplete_n", "invalid_nontechnical_n", "complete_recorded_block",
            "campaign_evidence_valid", "metadata_consistent",
            "paired_parameters_consistent",
            "comparable_valid_block", "valid_resisted_policy_n", "outcome_pattern",
        ],
        "aggregate_block_summary.csv": [
            "scenario", "intensity", "campaign_n", "block_n",
            "complete_recorded_block_n", "comparable_valid_block_n",
            "not_comparable_block_n", "unanimous_resisted_block_n",
            "unanimous_adverse_block_n", "mixed_policy_outcome_block_n",
        ],
        "aggregate_paired_policy_descriptive.csv": [
            "scenario", "intensity", "left_policy", "right_policy",
            "paired_valid_block_n", "both_resisted_n", "both_adverse_n",
            "left_only_resisted_n", "right_only_resisted_n", "discordant_n",
            "interpretation",
        ],
        "aggregate_software_verifier_conformance.csv": [
            "scenario", "scenario_label", "policy", "policy_label", "campaign_n",
            "observation_n", "authentication_success_n",
            "authentication_success_percent", "mean_latency_ms", "sd_latency_ms",
            "ci95_latency_low_ms", "ci95_latency_high_ms", "mean_cpu_percent",
            "sd_cpu_percent", "ci95_cpu_low_percent", "ci95_cpu_high_percent",
            "evidence_scope",
        ],
        "aggregate_factor_compromise_resistance.csv": [
            "policy", "policy_label", "compromise_state_n",
            "fully_resisted_state_n", "exposed_state_n", "observation_n",
            "blocked_authentication_n", "successful_authentication_n",
            "resistance_percent", "resistance_ci95_low",
            "resistance_ci95_high", "evidence_scope",
        ],
        "aggregate_data_quality.csv": [
            "scenario", "recorded_n", "valid_evaluable_n",
            "technical_error_n", "incomplete_n", "invalid_nontechnical_n",
            "excluded_campaign_evidence_n",
        ],
        "aggregate_technical_errors.csv": [
            "scenario", "error_type", "task_n", "affected_block_n",
            "campaign_n",
        ],
        "aggregate_availability_phases.csv": [
            "scenario", "intensity", "phase", "block_n",
            "mean_availability_percent", "sd_availability_percent",
            "ci95_availability_low_percent",
            "ci95_availability_high_percent", "analysis_unit",
        ],
        "aggregate_block_metrics.csv": [
            "scenario", "intensity", "metric", "unit", "block_n", "mean",
            "standard_deviation", "ci95_low", "ci95_high", "analysis_unit",
        ],
    }
    tables = (
        ("aggregate_campaigns.csv", summary["campaign_rows"]),
        ("aggregate_scenarios.csv", summary["scenario_rows"]),
        ("aggregate_policies.csv", summary["policy_rows"]),
        ("aggregate_scenario_intensity.csv", summary["scenario_intensity_rows"]),
        ("aggregate_scenario_policy.csv", summary["scenario_policy_rows"]),
        (
            "aggregate_scenario_intensity_policy.csv",
            summary["scenario_intensity_policy_rows"],
        ),
        ("aggregate_block_details.csv", summary["block_rows"]),
        ("aggregate_block_summary.csv", summary["block_summary_rows"]),
        (
            "aggregate_paired_policy_descriptive.csv",
            summary["paired_policy_descriptive_rows"],
        ),
        (
            "aggregate_software_verifier_conformance.csv",
            summary["software_verifier_conformance_rows"],
        ),
        (
            "aggregate_factor_compromise_resistance.csv",
            summary.get("factor_compromise_resistance_rows", []),
        ),
        ("aggregate_data_quality.csv", summary.get("quality_rows", [])),
        (
            "aggregate_technical_errors.csv",
            summary.get("technical_error_rows", []),
        ),
        (
            "aggregate_availability_phases.csv",
            summary.get("availability_phase_rows", []),
        ),
        ("aggregate_block_metrics.csv", summary.get("block_metric_rows", [])),
    )
    for filename, rows in tables:
        written_paths.append(
            _write_dict_rows(
                data_dir / filename,
                rows,
                list(rows[0]) if rows else empty_fields[filename],
            )
        )

    manifest_dir = data_dir / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_index: List[Dict[str, Any]] = []
    campaign_summary_by_id = {
        row["campaign_id"]: row for row in summary["campaign_rows"]
    }
    for campaign, _ in campaign_observations:
        campaign_id = str(campaign["campaign_id"])
        original_manifest = _dict(campaign.get("manifest"))
        filename = "%s.json" % campaign_id
        manifest_output = manifest_dir / filename
        manifest_output.write_text(
            json.dumps(original_manifest, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        written_paths.append(manifest_output)
        stored_digest = str(
            campaign.get("manifest_sha256")
            or original_manifest.get("manifest_sha256")
            or ""
        )
        manifest_index.append(
            {
                "campaign_id": campaign_id,
                "manifest_file": "manifests/%s" % filename,
                "stored_manifest_sha256": stored_digest,
                "computed_manifest_sha256": (
                    manifest_digest(original_manifest) if original_manifest else ""
                ),
                "manifest_integrity_valid": campaign_summary_by_id[campaign_id][
                    "manifest_integrity_valid"
                ],
                "seed_serialization": "canonical_manifest_type_preserved",
            }
        )
    written_paths.append(
        _write_dict_rows(
            data_dir / "aggregate_manifest_index.csv",
            manifest_index,
            list(manifest_index[0]),
        )
    )

    run_rows = _aggregate_run_detail_rows(campaign_observations)
    if run_rows:
        written_paths.append(
            _write_dict_rows(
                data_dir / "aggregate_run_details.csv",
                run_rows,
                list(run_rows[0]),
            )
        )
    else:
        written_paths.append(
            _write_dict_rows(
                data_dir / "aggregate_run_details.csv",
                [],
                [
                    "campaign_id", "task_id", "sample_id", "scenario", "repetition",
                    "intensity", "policy", "execution_status", "task_classification",
                    "is_valid", "outcome", "resisted", "error_type", "duration_seconds",
                    "rate_pps", "request_count", "payload_size_bytes", "source_count",
                    "offered_load_ratio", "legitimate_latency_p95_ms",
                    "attack_latency_p95_ms", "process_cpu_p95", "pcap_sha256",
                ],
            )
        )
    evidence_index: List[Dict[str, Any]] = []
    for campaign, runs in campaign_observations:
        campaign_id = str(campaign["campaign_id"])
        evidence_directory = data_dir / "evidence" / campaign_id
        paths = export_evidence_package(
            campaign,
            runs,
            evidence_directory,
            manifest_path=_manifest_artifact_path(campaign),
            artifact_root=PROJECT_ROOT,
        )
        written_paths.extend(paths.values())
        integrity = campaign_summary_by_id[campaign_id]
        evidence_index.append(
            {
                "campaign_id": campaign_id,
                "evidence_directory": str(
                    evidence_directory.relative_to(data_dir)
                ),
                "exported_file_n": len(paths),
                "manifest_payload_checksum_valid": integrity.get(
                    "manifest_payload_checksum_valid"
                ),
                "manifest_file_checksum_valid": integrity.get(
                    "manifest_file_checksum_valid"
                ),
                "pcap_expected_n": integrity.get("pcap_expected_n"),
                "pcap_verified_n": integrity.get("pcap_verified_n"),
                "pcap_missing_n": integrity.get("pcap_missing_n"),
                "pcap_mismatch_n": integrity.get("pcap_mismatch_n"),
                "pcap_unverified_n": integrity.get("pcap_unverified_n"),
                "evidence_integrity_valid": integrity.get(
                    "evidence_integrity_valid"
                ),
            }
        )
    written_paths.append(
        _write_dict_rows(
            data_dir / "aggregate_evidence_index.csv",
            evidence_index,
            list(evidence_index[0]) if evidence_index else [
                "campaign_id",
                "evidence_directory",
                "exported_file_n",
                "manifest_payload_checksum_valid",
                "manifest_file_checksum_valid",
                "pcap_expected_n",
                "pcap_verified_n",
                "pcap_missing_n",
                "pcap_mismatch_n",
                "pcap_unverified_n",
                "evidence_integrity_valid",
            ],
        )
    )
    summary_output = data_dir / "aggregate_summary.json"
    summary_output.write_text(
        json.dumps(summary, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    written_paths.append(summary_output)
    return written_paths


def _percent(value: Optional[float]) -> str:
    return "—" if value is None else "%.1f%%" % value


def _percent_interval(value: Optional[float], low: Optional[float], high: Optional[float]) -> str:
    if value is None or low is None or high is None:
        return "—"
    return "%.1f%% [%.1f–%.1f]" % (value, low, high)


def _numeric_interval(
    value: Optional[float],
    low: Optional[float],
    high: Optional[float],
    unit: str = "",
) -> str:
    if value is None:
        return "—"
    if low is None or high is None:
        return "%.2f%s" % (value, unit)
    return "%.2f%s [%.2f–%.2f]" % (value, unit, low, high)


def _p_value(value: Optional[float]) -> str:
    return "—" if value is None else "%.4f" % value


def _render_html(
    campaign: Dict[str, Any],
    runs: List[Dict[str, Any]],
    summary: Dict[str, Any],
    charts: Dict[str, str],
    persian: bool,
) -> str:
    direction = "rtl" if persian else "ltr"
    lang = "fa" if persian else "en"
    scenario = SCENARIO_SPECS.get(str(summary["scenario"]), {})
    protocol_parameters = _dict(summary.get("protocol_parameters"))
    minimum_control_percent = 100.0 * float(
        protocol_parameters.get("minimum_control_availability", 0.80)
    )
    degradation_margin_points = 100.0 * float(
        protocol_parameters.get("availability_degradation_margin", 0.10)
    )
    if persian:
        title = "نتایج سنجش امنیت و کارایی سامانه SDN-MFA"
        subtitle = "مقاومت دسترسی، تداوم خدمت، سهم عوامل احراز هویت و هزینهٔ منابع"
        overview = "خلاصهٔ اندازه‌گیری سامانه"
        curve_title = "پاسخ امنیت/دسترس‌پذیری در سه سطح شدت"
        evidence_title = "شواهد کمی و جزئیات اجرا"
        paired_title = "مقایسهٔ آماری سیاست‌ها با حفظ جفت‌ها"
        methods_title = "روش آزمایش و حدود اعتبار"
        auth_title = "انطباق راستی‌آزمای نرم‌افزاری با دسترس‌پذیری کنترل‌شدهٔ عوامل"
        observed_label = "مشاهدات معتبر"
        resisted_label = "مسدود/پایدار"
        topology_label = "توپولوژی"
        design_label = "طرح آزمایش"
        design_value = "بلوک کامل تصادفی با ورودی‌های جفت‌شده"
        interpretation_equal = (
            "در این سناریوی شبکه‌ای تفاوت مشاهده‌شده‌ای میان چهار سیاست وجود نداشت؛ این الگو با اتصال شبکه و زمان مجوز "
            "یکسان سازگار است، اما هم‌ارزی سیاست‌ها را اثبات نمی‌کند. این نتیجه نباید به‌عنوان بی‌فایده بودن عامل اضافی تفسیر شود؛ "
            "اثر عامل اضافی باید در آزمایش کنترل‌شدهٔ دسترس‌پذیری عوامل احراز هویت سنجیده شود."
        )
        interpretation_diff = (
            "میان نرخ‌های مشاهده‌شدهٔ سیاست‌ها تفاوت وجود دارد؛ پیش از نتیجه‌گیری، بازه‌های اطمینان "
            "و آزمون‌های دقیق جفت‌شده باید بررسی شوند."
        )
        interpretation_insufficient = (
            "برای مقایسهٔ سیاست‌ها دست‌کم دو سیاست با زوج‌های معتبر لازم است؛ دادهٔ ثبت‌شده برای "
            "استنتاج مقایسه‌ای کافی نیست."
        )
        limitations = (
            "نتایج فقط برای توپولوژی، ظرفیت پیوند، نسخهٔ پروتکل، نمونه‌های شدت و سناریوی ثبت‌شده معتبر است. "
            "OTP و نمونهٔ بایومتریک هر دو شبیه‌سازی نرم‌افزاری هستند و هیچ ادعایی دربارهٔ حسگر زیستی یا توکن سخت‌افزاری مطرح نمی‌شود."
        )
        table_headers = ["سیاست", "تعداد معتبر", "نرخ مقاومت (بازهٔ اطمینان ۹۵٪)", "میانگین تأخیر احراز [بازهٔ ۹۵٪]", "میانگین CPU احراز [بازهٔ ۹۵٪]", "تأخیر مجاز HTTP P95", "CPU کنترلر P95"]
        paired_headers = ["دو سیاست", "زوج معتبر", "فقط سیاست اول", "فقط سیاست دوم", "p دقیق", "p اصلاح‌شدهٔ Holm"]
        detail_headers = ["تکرار", "شدت", "سیاست", "نرخ", "پیامد", "معتبر"]
        meta_line = "شناسهٔ کارزار %s · پروتکل %s · سناریو %s" % (
            summary["campaign_id"],
            summary["protocol_id"],
            PERSIAN_SCENARIO_LABELS.get(str(summary["scenario"]), summary["scenario"]),
        )
        methodology = (
            "بذر تصادفی %s؛ %s تکرار؛ در هر بلوک یک ورودی یکسان از سطوح کم، متوسط و زیاد برای "
            "هر چهار سیاست استفاده شد؛ ترتیب سیاست‌ها تصادفی بود؛ اتصال شبکه برای همه %s بود؛ "
            "حداقل دسترس‌پذیری کنترل %.0f٪ و آستانهٔ افت خدمت %.0f واحد درصد بود؛ "
            "آزمایش عوامل احراز هویت %s از %s مشاهده را ثبت کرد؛ تطابق هش مانیفست: %s؛ "
            "تطابق اجراها با مانیفست: %s؛ اعتبار شواهد احراز هویت: %s؛ تمامیت شواهد: %s (PCAP تأییدشده %s از %s)؛ "
            "خطاهای فنی از نرخ‌ها حذف شدند؛ بازه‌های اطمینان ۹۵٪ با روش ویلسون و اختلاف‌های جفت‌شده "
            "با آزمون دقیق McNemar و اصلاح Holm محاسبه شدند."
            % (
                summary["seed"],
                summary["repetitions"],
                summary["binding_profile"],
                minimum_control_percent,
                degradation_margin_points,
                summary["authentication_observations"],
                summary["expected_authentication_observations"],
                "تأیید" if summary["manifest_integrity_valid"] else "نامعتبر",
                "تأیید" if summary["run_manifest_alignment_valid"] else "نامعتبر",
                "تأیید" if summary["authentication_evidence_valid"] else "نامعتبر؛ از تحلیل حذف شد",
                "تأیید" if summary.get("evidence_integrity_valid") else "نامعتبر",
                summary.get("pcap_verified_n", 0),
                summary.get("pcap_expected_n", 0),
            )
        )
        footer = "این گزارش فقط از مشاهدات پایگاه داده تولید شده است؛ فایل‌های CSV و JSON در پوشهٔ data قرار دارند."
    else:
        title = "SDN-MFA Security and Performance Results"
        subtitle = "Measured access resistance, service continuity, factor contribution, and resource cost"
        overview = "Measured system outcome"
        curve_title = "Security/availability response across three intensity levels"
        evidence_title = "Quantitative evidence and execution details"
        paired_title = "Paired statistical policy comparisons"
        methods_title = "Method and scope of validity"
        auth_title = "Software verifier conformance under controlled factor availability"
        observed_label = "Valid observations"
        resisted_label = "Blocked/preserved"
        topology_label = "Topology"
        design_label = "Experimental design"
        design_value = "Randomized complete blocks with paired inputs"
        interpretation_equal = (
            "This network scenario produced no observed separation among MFA policies. That pattern is consistent with "
            "the common network binding and authorization lifetime, but it does not establish policy equivalence or make "
            "an additional authentication factor redundant; factor value is evaluated separately in the controlled "
            "factor-availability experiment."
        )
        interpretation_diff = (
            "Observed policy rates differ; inspect the confidence intervals and exact paired tests before drawing a conclusion."
        )
        interpretation_insufficient = (
            "At least two policies with valid paired observations are required; the recorded data are insufficient for comparative inference."
        )
        limitations = (
            "Results are valid for the recorded topology, link capacity, protocol version, sampled intensities, and scenario. "
            "OTP and the biometric sample are software simulations; no physical biometric sensor or hardware token is claimed."
        )
        table_headers = ["Policy", "Valid n", "Resistance (95% CI)", "Mean valid-auth latency [95% CI]", "Mean valid-auth CPU [95% CI]", "Legitimate HTTP p95", "Controller CPU p95"]
        paired_headers = ["Policy pair", "Valid pairs", "Left only", "Right only", "Exact p", "Holm-adjusted p"]
        detail_headers = ["Rep.", "Intensity", "Policy", "Rate", "Outcome", "Valid"]
        meta_line = "Campaign %s · Protocol %s · Scenario %s" % (
            summary["campaign_id"],
            summary["protocol_id"],
            scenario.get("display_name", summary["scenario"]),
        )
        methodology = (
            "Seed %s; %s repetition(s); one sampled low/medium/high input reused across all policies in each block; "
            "policy order randomized; common binding %s; minimum control availability %.0f%%; service-degradation "
            "margin %.0f percentage points; authentication observations %s/%s; manifest digest match %s; "
            "run-to-manifest alignment %s; authentication evidence %s; evidence integrity %s (verified PCAP %s/%s); "
            "technical errors excluded from rates; 95%% intervals use the Wilson method; paired differences use "
            "the two-sided exact McNemar test with Holm adjustment."
            % (
                summary["seed"],
                summary["repetitions"],
                summary["binding_profile"],
                minimum_control_percent,
                degradation_margin_points,
                summary["authentication_observations"],
                summary["expected_authentication_observations"],
                "yes" if summary["manifest_integrity_valid"] else "no",
                "yes" if summary["run_manifest_alignment_valid"] else "no",
                "valid" if summary["authentication_evidence_valid"] else "invalid; excluded from analysis",
                "yes" if summary.get("evidence_integrity_valid") else "no",
                summary.get("pcap_verified_n", 0),
                summary.get("pcap_expected_n", 0),
            )
        )
        footer = "Generated only from database observations. Adjacent CSV and JSON files provide the underlying evidence."

    total_resisted = sum(
        count
        for outcome, count in summary["valid_outcome_counts"].items()
        if _is_resisted(outcome)
    )
    resistance_overall = 100.0 * total_resisted / summary["valid"] if summary["valid"] else None
    overall_low, overall_high = wilson_interval(total_resisted, summary["valid"])
    rows_html = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s ms</td><td>%s%%</td></tr>"
        % (
            html.escape(
                PERSIAN_POLICY_LABELS.get(str(row["policy"]), str(row["label"]))
                if persian else str(row["label"])
            ),
            row["valid_n"],
            _percent_interval(
                row["resistance_percent"],
                row["resistance_ci95_low"],
                row["resistance_ci95_high"],
            ),
            _numeric_interval(
                row["mean_valid_authentication_latency_ms"],
                row.get("ci95_valid_authentication_latency_low_ms"),
                row.get("ci95_valid_authentication_latency_high_ms"),
                " ms",
            ),
            _numeric_interval(
                row["mean_valid_authentication_cpu_percent"],
                row.get("ci95_valid_authentication_cpu_low_percent"),
                row.get("ci95_valid_authentication_cpu_high_percent"),
                "%",
            ),
            "—" if row["mean_legitimate_latency_p95_ms"] is None else "%.2f" % row["mean_legitimate_latency_p95_ms"],
            "—" if row["mean_process_cpu_p95"] is None else "%.2f" % row["mean_process_cpu_p95"],
        )
        for row in summary["policy_rows"]
    )
    paired_rows_html = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (
            html.escape(
                "%s ↔ %s"
                % (
                    PERSIAN_POLICY_LABELS.get(row["left_policy"], row["left_label"])
                    if persian else row["left_label"],
                    PERSIAN_POLICY_LABELS.get(row["right_policy"], row["right_label"])
                    if persian else row["right_label"],
                )
            ),
            row["paired_n"],
            row["left_only_resisted"],
            row["right_only_resisted"],
            _p_value(row["exact_mcnemar_p"]),
            _p_value(row["holm_adjusted_p"]),
        )
        for row in summary["paired_policy_rows"]
    )
    detail_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (
            html.escape(str(run.get("repetition"))),
            html.escape(
                PERSIAN_INTENSITY_LABELS.get(str(run.get("intensity_level")), str(run.get("intensity_level")))
                if persian else str(run.get("intensity_level"))
            ),
            html.escape(
                PERSIAN_POLICY_LABELS.get(str(run.get("mfa_mode")), str(run.get("mfa_mode")))
                if persian
                else POLICY_SPECS.get(str(run.get("mfa_mode")), {}).get("label", str(run.get("mfa_mode")))
            ),
            html.escape(str(_dict(run.get("sampled_parameters")).get("rate_pps"))),
            html.escape(
                PERSIAN_OUTCOME_LABELS.get(_outcome(run), _outcome(run))
                if persian else _outcome(run).replace("_", " ")
            ),
            (
                ("بله" if summary["analysis_eligible"] and _valid(run) else "خیر")
                if persian
                else ("yes" if summary["analysis_eligible"] and _valid(run) else "no")
            ),
        )
        for run in runs
    )
    return """<!doctype html>
<html lang="%s" dir="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title><style>
:root{--navy:#0f2744;--blue:#2563eb;--teal:#059669;--amber:#d97706;--red:#dc2626;--ink:#172033;--muted:#64748b;--line:#dbe4ee;--paper:#f5f8fc}
*{box-sizing:border-box}html,body{margin:0;background:var(--paper);color:var(--ink);font-family:Segoe UI,Tahoma,Arial,sans-serif;overflow-x:hidden}
.page{max-width:1500px;margin:auto;padding:18px}.hero{background:linear-gradient(115deg,#0f2744,#173f6b);color:#fff;border-radius:16px;padding:20px 26px;box-shadow:0 10px 28px #0f274429}
.hero h1{font-size:clamp(20px,1.8vw,28px);line-height:1.2;margin:0;white-space:nowrap}.hero p{margin:7px 0 0;color:#dbeafe;font-size:15px}.meta{margin-top:10px;font-size:12px;color:#bfdbfe;word-break:break-word}
h2{font-size:22px;color:var(--navy);margin:26px 0 12px}.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card,.panel{background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:0 4px 16px #0f27440b}.card{padding:16px}.card small{display:block;color:var(--muted);font-weight:600}.card strong{display:block;color:var(--navy);font-size:25px;margin-top:6px}.chart-grid{display:grid;grid-template-columns:2fr 1fr;gap:14px}.panel{padding:14px}.panel.wide{grid-column:1/-1}.panel img{display:block;width:100%%;height:auto;border-radius:8px}.panel a{cursor:zoom-in}.note{border-inline-start:5px solid var(--blue);background:#eff6ff;padding:13px 15px;border-radius:10px;line-height:1.75;margin:14px 0}.method{border-inline-start-color:var(--teal);background:#ecfdf5}.limit{border-inline-start-color:var(--amber);background:#fff7ed}
.table-scroll{max-height:420px;overflow:auto;border:1px solid var(--line);border-radius:12px;background:#fff}table{width:100%%;border-collapse:collapse;min-width:760px}th{position:sticky;top:0;background:var(--navy);color:#fff;text-align:start;z-index:1}th,td{padding:11px 12px;border-bottom:1px solid var(--line);font-size:13px}tr:nth-child(even) td{background:#f8fafc}.footer{font-size:12px;color:var(--muted);padding:22px 2px}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.chart-grid{grid-template-columns:1fr}.hero h1{white-space:normal}}
@media print{body{background:#fff}.page{max-width:none;padding:0}.hero,.card,.panel{box-shadow:none}.table-scroll{max-height:none;overflow:visible}.panel a{cursor:default}}
</style></head><body><main class="page">
<header class="hero"><h1>%s</h1><p>%s</p><div class="meta">%s</div></header>
<h2>%s</h2><section class="cards">
<div class="card"><small>%s</small><strong>%s / %s</strong></div>
<div class="card"><small>%s</small><strong>%s</strong></div>
<div class="card"><small>%s</small><strong>%s</strong></div>
<div class="card"><small>%s</small><strong style="font-size:16px">%s</strong></div></section>
<h2>%s</h2><section class="chart-grid">
<article class="panel wide"><a target="_blank" rel="noopener" href="assets/charts/%s"><img alt="response curve" src="assets/charts/%s"></a></article>
<article class="panel"><a target="_blank" rel="noopener" href="assets/charts/%s"><img alt="policy comparison" src="assets/charts/%s"></a></article>
<article class="panel"><a target="_blank" rel="noopener" href="assets/charts/%s"><img alt="outcomes" src="assets/charts/%s"></a></article>
<article class="panel wide"><a target="_blank" rel="noopener" href="assets/charts/%s"><img alt="performance" src="assets/charts/%s"></a></article></section>
<div class="note">%s</div>
<h2>%s</h2><article class="panel"><a target="_blank" rel="noopener" href="assets/charts/%s"><img alt="factor availability matrix" src="assets/charts/%s"></a></article>
<h2>%s</h2><div class="table-scroll"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>
<h2>%s</h2><div class="table-scroll"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>
<h2>%s</h2><div class="note method">%s</div><div class="note limit">%s</div>
<div class="table-scroll"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>
<footer class="footer">%s</footer>
</main></body></html>""" % (
        lang, direction, html.escape(title), html.escape(title), html.escape(subtitle),
        html.escape(meta_line),
        html.escape(overview), html.escape(observed_label), summary["valid"], summary["planned"],
        html.escape(resisted_label), _percent_interval(resistance_overall, overall_low, overall_high), html.escape(topology_label), html.escape(str(summary["topology_id"])),
        html.escape(design_label), html.escape(design_value), html.escape(curve_title),
        charts["curve"], charts["curve"], charts["policy"], charts["policy"], charts["outcome"], charts["outcome"], charts["performance"], charts["performance"],
        html.escape(
            interpretation_insufficient
            if not summary["policy_comparison_evidence_available"]
            else (
                interpretation_equal
                if (summary["policy_spread_percentage_points"] or 0.0) < 0.01
                else interpretation_diff
            )
        ),
        html.escape(auth_title), charts["authentication"], charts["authentication"],
        html.escape(evidence_title), "".join("<th>%s</th>" % html.escape(value) for value in table_headers), rows_html,
        html.escape(paired_title), "".join("<th>%s</th>" % html.escape(value) for value in paired_headers), paired_rows_html,
        html.escape(methods_title), html.escape(methodology), html.escape(limitations),
        "".join("<th>%s</th>" % html.escape(value) for value in detail_headers), detail_rows,
        html.escape(footer),
    )


def _render_aggregate_html_legacy(summary: Dict[str, Any], persian: bool) -> str:
    """Render a bilingual descriptive dashboard for multiple campaigns."""
    direction = "rtl" if persian else "ltr"
    language = "fa" if persian else "en"

    def scenario_label(value: Any) -> str:
        key = str(value)
        if persian:
            return PERSIAN_SCENARIO_LABELS.get(key, key)
        return str(SCENARIO_SPECS.get(key, {}).get("display_name", key))

    def policy_label(value: Any) -> str:
        key = str(value)
        if persian:
            return PERSIAN_POLICY_LABELS.get(key, key)
        return str(POLICY_SPECS.get(key, {}).get("label", key))

    def intensity_label(value: Any) -> str:
        key = str(value)
        return PERSIAN_INTENSITY_LABELS.get(key, key) if persian else key.title()

    def boolean_label(value: Any) -> str:
        if persian:
            return "بله" if value else "خیر"
        return "yes" if value else "no"

    def table(headers: Sequence[str], body: Iterable[Sequence[Any]]) -> str:
        rows = list(body)
        if not rows:
            empty = "داده‌ای ثبت نشده است" if persian else "No recorded data"
            return '<div class="empty">%s</div>' % html.escape(empty)
        heading = "".join("<th>%s</th>" % html.escape(value) for value in headers)
        rendered = "".join(
            "<tr>%s</tr>"
            % "".join("<td>%s</td>" % html.escape(str(value)) for value in row)
            for row in rows
        )
        return '<div class="table-scroll"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (
            heading,
            rendered,
        )

    if persian:
        title = "گزارش تجمیعی چندکارزاری SDN-MFA"
        subtitle = "خلاصهٔ توصیفی سناریوها، شدت‌ها، سیاست‌ها و اعتبار شواهد"
        campaign_title = "اعتبار و تکمیل کارزارها"
        scenario_title = "خلاصه برحسب سناریو"
        detail_title = "سناریو × شدت × سیاست"
        block_title = "خلاصهٔ بلوک‌های جفت‌شده"
        pair_title = "شمارش توصیفی زوج سیاست‌ها"
        verifier_title = "انطباق راستی‌آزمای نرم‌افزاری عوامل"
        validity_note = (
            "نرخ‌ها فقط از وظایف معتبر و قابل‌ارزیابی محاسبه شده‌اند. خطاهای فنی، وظایف ناتمام و "
            "رکوردهای نامعتبر جداگانه باقی مانده‌اند و به موفقیت یا شکست امنیتی تبدیل نشده‌اند."
        )
        inference_note = (
            "شمارش‌های زوجی و بازه‌های اطمینان توصیفی‌اند؛ نبود اختلاف مشاهده‌شده یا p غیرمعنی‌دار، "
            "هم‌ارزی سیاست‌ها را اثبات نمی‌کند. نرخ‌های کلی نیز به ترکیب سناریو و شدت انتخاب‌شده وابسته‌اند."
        )
        verifier_note = (
            "این ماتریس فقط انطباق منطق راستی‌آزمای نرم‌افزاری با عوامل کنترل‌شده را نشان می‌دهد؛ "
            "اعتبارسنجی حسگر فیزیکی، FAR/FRR، تشخیص زنده‌بودن یا دقت بایومتریک نیست."
        )
        cards = ("کارزارها", "وظایف معتبر", "خطاهای فنی", "بلوک‌های قابل‌مقایسه")
    else:
        title = "SDN-MFA Multi-campaign Aggregate Report"
        subtitle = "Descriptive evidence by scenario, intensity, policy, block, and validity class"
        campaign_title = "Campaign validity and completion"
        scenario_title = "Scenario summary"
        detail_title = "Scenario × intensity × policy"
        block_title = "Paired-block summary"
        pair_title = "Descriptive paired-policy counts"
        verifier_title = "Software verifier conformance"
        validity_note = (
            "Rates use valid and evaluable tasks only. Technical errors, incomplete tasks, and other invalid "
            "records remain separate; none is converted into a blocked, successful, preserved, or degraded outcome."
        )
        inference_note = (
            "Paired counts and intervals are descriptive. No observed difference or non-significant result establishes "
            "policy equivalence. Overall rates also depend on the selected mix of scenarios and intensities."
        )
        verifier_note = (
            "This matrix reports software verifier conformance under controlled factor availability. It is not physical "
            "sensor validation, FAR/FRR measurement, liveness testing, or biometric accuracy evidence."
        )
        cards = ("Campaigns", "Valid tasks", "Technical errors", "Comparable blocks")

    comparable_blocks = sum(
        int(row["comparable_valid_block_n"]) for row in summary["block_summary_rows"]
    )
    campaign_table = table(
        (
            ("کارزار", "سناریو", "بذر", "وضعیت", "برنامه", "ثبت", "معتبر", "خطای فنی", "ناتمام", "نامعتبر دیگر", "مانیفست", "تطابق اجرا", "شواهد احراز", "واجد تحلیل", "تمامیت شواهد")
            if persian
            else ("Campaign", "Scenario", "Seed", "Status", "Planned", "Recorded", "Valid", "Technical", "Incomplete", "Other invalid", "Manifest", "Run alignment", "Authentication evidence", "Analysis eligible", "Evidence integrity")
        ),
        (
            (
                row["campaign_id"],
                scenario_label(row["scenario"]),
                row["seed"],
                row["status"],
                row["planned_n"],
                row["recorded_n"],
                row["valid_n"],
                row["technical_error_n"],
                row["incomplete_n"],
                row["invalid_nontechnical_n"],
                boolean_label(row["manifest_integrity_valid"]),
                boolean_label(row["run_manifest_alignment_valid"]),
                boolean_label(row["authentication_evidence_valid"]),
                boolean_label(row.get("analysis_eligible", False)),
                "%s/%s; %s"
                % (
                    row.get("pcap_verified_n", 0),
                    row.get("pcap_expected_n", 0),
                    boolean_label(row.get("evidence_integrity_valid", False)),
                ),
            )
            for row in summary["campaign_rows"]
        ),
    )
    scenario_table = table(
        (
            ("سناریو", "کارزار", "بلوک", "ثبت", "معتبر", "خطای فنی", "ناتمام", "نامعتبر دیگر", "حذف به‌علت شواهد کارزار", "پیامد مقاوم", "پیامد نامطلوب", "نرخ توصیفی")
            if persian
            else ("Scenario", "Campaigns", "Blocks", "Recorded", "Valid", "Technical", "Incomplete", "Other invalid", "Excluded campaign evidence", "Resisted", "Adverse", "Descriptive rate")
        ),
        (
            (
                scenario_label(row["scenario"]),
                row["campaign_n"],
                row["block_n"],
                row["recorded_n"],
                row["valid_n"],
                row["technical_error_n"],
                row["incomplete_n"],
                row["invalid_nontechnical_n"],
                row["excluded_campaign_evidence_n"],
                row["resisted_n"],
                row["adverse_outcome_n"],
                _percent_interval(
                    row["resistance_percent"],
                    row["resistance_ci95_low"],
                    row["resistance_ci95_high"],
                ),
            )
            for row in summary["scenario_rows"]
        ),
    )
    detail_table = table(
        (
            ("سناریو", "شدت", "سیاست", "ثبت", "معتبر", "خطای فنی", "ناتمام", "نامعتبر دیگر", "حذف به‌علت شواهد کارزار", "مقاوم", "نامطلوب", "نرخ توصیفی")
            if persian
            else ("Scenario", "Intensity", "Policy", "Recorded", "Valid", "Technical", "Incomplete", "Other invalid", "Excluded campaign evidence", "Resisted", "Adverse", "Descriptive rate")
        ),
        (
            (
                scenario_label(row["scenario"]),
                intensity_label(row["intensity"]),
                policy_label(row["policy"]),
                row["recorded_n"],
                row["valid_n"],
                row["technical_error_n"],
                row["incomplete_n"],
                row["invalid_nontechnical_n"],
                row["excluded_campaign_evidence_n"],
                row["resisted_n"],
                row["adverse_outcome_n"],
                _percent(row["resistance_percent"]),
            )
            for row in summary["scenario_intensity_policy_rows"]
        ),
    )
    block_table = table(
        (
            ("سناریو", "شدت", "بلوک", "کامل", "قابل‌مقایسه", "غیرقابل‌مقایسه", "همگی مقاوم", "همگی نامطلوب", "مختلط")
            if persian
            else ("Scenario", "Intensity", "Blocks", "Complete", "Comparable", "Not comparable", "All resisted", "All adverse", "Mixed")
        ),
        (
            (
                scenario_label(row["scenario"]),
                intensity_label(row["intensity"]),
                row["block_n"],
                row["complete_recorded_block_n"],
                row["comparable_valid_block_n"],
                row["not_comparable_block_n"],
                row["unanimous_resisted_block_n"],
                row["unanimous_adverse_block_n"],
                row["mixed_policy_outcome_block_n"],
            )
            for row in summary["block_summary_rows"]
        ),
    )
    pair_table = table(
        (
            ("سناریو", "شدت", "سیاست اول", "سیاست دوم", "زوج معتبر", "هر دو مقاوم", "هر دو نامطلوب", "فقط اول", "فقط دوم")
            if persian
            else ("Scenario", "Intensity", "Left", "Right", "Valid pairs", "Both resisted", "Both adverse", "Left only", "Right only")
        ),
        (
            (
                scenario_label(row["scenario"]),
                intensity_label(row["intensity"]),
                policy_label(row["left_policy"]),
                policy_label(row["right_policy"]),
                row["paired_valid_block_n"],
                row["both_resisted_n"],
                row["both_adverse_n"],
                row["left_only_resisted_n"],
                row["right_only_resisted_n"],
            )
            for row in summary["paired_policy_descriptive_rows"]
        ),
    )
    verifier_table = table(
        (
            ("وضعیت عوامل", "سیاست", "کارزار", "مشاهده", "موفق", "درصد موفقیت", "میانگین تأخیر [بازهٔ ۹۵٪]", "میانگین CPU [بازهٔ ۹۵٪]")
            if persian
            else ("Factor condition", "Policy", "Campaigns", "Observations", "Succeeded", "Success rate", "Mean latency [95% CI]", "Mean CPU [95% CI]")
        ),
        (
            (
                PERSIAN_AUTH_SCENARIO_LABELS.get(row["scenario"], row["scenario_label"])
                if persian
                else row["scenario_label"],
                policy_label(row["policy"]),
                row["campaign_n"],
                row["observation_n"],
                row["authentication_success_n"],
                _percent(row["authentication_success_percent"]),
                _numeric_interval(
                    row["mean_latency_ms"],
                    row.get("ci95_latency_low_ms"),
                    row.get("ci95_latency_high_ms"),
                    " ms",
                ),
                _numeric_interval(
                    row.get("mean_cpu_percent"),
                    row.get("ci95_cpu_low_percent"),
                    row.get("ci95_cpu_high_percent"),
                    "%",
                ),
            )
            for row in summary["software_verifier_conformance_rows"]
        ),
    )
    return """<!doctype html>
<html lang="%s" dir="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title><style>
:root{--navy:#0f2744;--blue:#2563eb;--teal:#0f766e;--amber:#d97706;--ink:#172033;--muted:#64748b;--line:#dbe4ee;--paper:#f5f8fc}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:Segoe UI,Tahoma,Arial,sans-serif}.page{max-width:1600px;margin:auto;padding:18px}.hero{background:linear-gradient(115deg,#0f2744,#173f6b);color:white;border-radius:16px;padding:22px 26px}.hero h1{margin:0;font-size:28px}.hero p{margin:8px 0 0;color:#dbeafe}.meta{margin-top:9px;color:#bfdbfe;font-size:12px;word-break:break-word}
h2{color:var(--navy);margin:28px 0 12px}.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card,.note,.table-scroll,.empty{background:white;border:1px solid var(--line);border-radius:13px}.card{padding:16px}.card small{display:block;color:var(--muted);font-weight:600}.card strong{display:block;color:var(--navy);font-size:25px;margin-top:5px}.note{padding:13px 15px;margin:14px 0;border-inline-start:5px solid var(--blue);line-height:1.7}.note.limit{border-inline-start-color:var(--amber);background:#fff7ed}.note.method{border-inline-start-color:var(--teal);background:#ecfdf5}.table-scroll{max-height:470px;overflow:auto}table{width:100%%;border-collapse:collapse;min-width:850px}th{position:sticky;top:0;background:var(--navy);color:white;text-align:start;z-index:1}th,td{padding:10px 11px;border-bottom:1px solid var(--line);font-size:12px}tr:nth-child(even) td{background:#f8fafc}.empty{padding:16px;color:var(--muted)}footer{padding:22px 2px;color:var(--muted);font-size:12px}@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}}
</style></head><body><main class="page">
<header class="hero"><h1>%s</h1><p>%s</p><div class="meta">%s · %s</div></header>
<section class="cards"><div class="card"><small>%s</small><strong>%s</strong></div><div class="card"><small>%s</small><strong>%s</strong></div><div class="card"><small>%s</small><strong>%s</strong></div><div class="card"><small>%s</small><strong>%s</strong></div></section>
<div class="note method">%s</div><div class="note limit">%s</div>
<h2>%s</h2>%s<h2>%s</h2>%s<h2>%s</h2>%s<h2>%s</h2>%s
<h2>%s</h2><div class="note limit">%s</div>%s
<h2>%s</h2><div class="note method">%s</div>%s
<footer>%s</footer>
</main></body></html>""" % (
        language,
        direction,
        html.escape(title),
        html.escape(title),
        html.escape(subtitle),
        html.escape(summary["aggregate_id"]),
        html.escape(
            "%s%s"
            % (
                summary["selection"],
                " · days=%s" % summary["selection_days"]
                if summary.get("selection_days") is not None
                else "",
            )
        ),
        html.escape(cards[0]),
        summary["campaign_n"],
        html.escape(cards[1]),
        summary["valid_task_n"],
        html.escape(cards[2]),
        summary["technical_error_task_n"],
        html.escape(cards[3]),
        comparable_blocks,
        html.escape(validity_note),
        html.escape(inference_note),
        html.escape(campaign_title),
        campaign_table,
        html.escape(scenario_title),
        scenario_table,
        html.escape(detail_title),
        detail_table,
        html.escape(block_title),
        block_table,
        html.escape(pair_title),
        html.escape(inference_note),
        pair_table,
        html.escape(verifier_title),
        html.escape(verifier_note),
        verifier_table,
        html.escape(
            "شواهد ساخت‌یافته در data/aggregate_summary.json، CSVهای تجمیعی و زیرپوشه‌های evidence قرار دارند."
            if persian
            else "Structured evidence is in data/aggregate_summary.json, the aggregate CSV files, and the evidence subdirectories."
        ),
    )


def _render_aggregate_html(
    summary: Dict[str, Any],
    persian: bool,
    charts: Optional[Dict[str, Dict[str, str]]] = None,
) -> str:
    """Render the executive aggregate dashboard and its scientific figures."""
    return render_aggregate_dashboard(summary, persian=persian, charts=charts)


def _validate_report_output_tree(output: Path) -> Path:
    """Reject links in a reused output tree before any report file is written."""
    output = Path(output).absolute()
    parts = output.parts
    cursor = Path(parts[0])
    for part in parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise RuntimeError(
                "Report output refuses symbolic links: %s" % cursor
            )
    if output.exists() and not output.is_dir():
        raise RuntimeError("Report output must be a directory")
    if output.exists():
        for path in output.rglob("*"):
            if path.is_symlink():
                raise RuntimeError(
                    "Report output refuses symbolic links: %s" % path
                )
    return output


def _archive_report_directory(output: Path, members: Sequence[Path]) -> Path:
    """Archive an explicit set of generated files without following links."""
    output = Path(output).absolute()
    if not output.is_dir() or output.is_symlink():
        raise RuntimeError("Report output must be a real directory")
    if not members:
        raise RuntimeError("Report archive requires at least one generated file")
    output_absolute = output
    archive_path = output.parent / (output.name + ".zip")
    if archive_path.is_symlink():
        raise RuntimeError(
            "Report archive destination must not be a symbolic link: %s"
            % archive_path
        )
    if archive_path.exists() and not archive_path.is_file():
        raise RuntimeError("Report archive destination must be a regular file")

    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    file_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    root_descriptor = os.open(output, directory_flags)
    validated: Dict[str, Tuple[int, os.stat_result]] = {}
    temporary_path: Optional[Path] = None
    try:
        for member in members:
            path_absolute = Path(member).absolute()
            try:
                relative = path_absolute.relative_to(output_absolute)
            except ValueError as exc:
                raise RuntimeError(
                    "Report archive member is outside the report directory: %s"
                    % path_absolute
                ) from exc
            if not relative.parts or any(
                part in {"", ".", ".."} for part in relative.parts
            ):
                raise RuntimeError(
                    "Report archive member has an invalid relative path: %s"
                    % path_absolute
                )
            relative_key = relative.as_posix()
            if relative_key in validated:
                continue

            # Pin every directory and the final file with no-follow descriptors.
            # The subsequent ZIP copy reads only from the pinned descriptor, so
            # replacing a validated pathname cannot redirect it outside output.
            parent_descriptor = os.dup(root_descriptor)
            member_descriptor: Optional[int] = None
            try:
                for component in relative.parts[:-1]:
                    next_descriptor = os.open(
                        component,
                        directory_flags,
                        dir_fd=parent_descriptor,
                    )
                    os.close(parent_descriptor)
                    parent_descriptor = next_descriptor
                member_descriptor = os.open(
                    relative.parts[-1],
                    file_flags,
                    dir_fd=parent_descriptor,
                )
            except OSError as exc:
                if member_descriptor is not None:
                    os.close(member_descriptor)
                raise RuntimeError(
                    "Report archive refuses symbolic links, missing files, or non-regular members: %s"
                    % path_absolute
                ) from exc
            finally:
                os.close(parent_descriptor)

            try:
                member_status = os.fstat(member_descriptor)
            except OSError as exc:
                os.close(member_descriptor)
                raise RuntimeError(
                    "Report archive could not inspect member: %s" % path_absolute
                ) from exc
            if not stat.S_ISREG(member_status.st_mode) or member_status.st_nlink != 1:
                os.close(member_descriptor)
                raise RuntimeError(
                    "Report archive member must be a singly linked regular file: %s"
                    % path_absolute
                )
            validated[relative_key] = (member_descriptor, member_status)

        with tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=".%s-" % output.name,
            suffix=".zip.tmp",
            dir=str(output.parent),
            delete=False,
        ) as archive_handle:
            temporary_path = Path(archive_handle.name)
            with zipfile.ZipFile(
                archive_handle,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                for relative, (descriptor, member_status) in sorted(
                    validated.items()
                ):
                    archive_name = (Path(output.name) / relative).as_posix()
                    archive_info = zipfile.ZipInfo(archive_name)
                    archive_info.create_system = 3
                    archive_info.compress_type = zipfile.ZIP_DEFLATED
                    archive_info.external_attr = (
                        stat.S_IFREG | stat.S_IMODE(member_status.st_mode)
                    ) << 16
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    with os.fdopen(os.dup(descriptor), "rb") as source_handle:
                        with archive.open(
                            archive_info,
                            "w",
                            force_zip64=True,
                        ) as destination_handle:
                            shutil.copyfileobj(
                                source_handle,
                                destination_handle,
                                length=1024 * 1024,
                            )
            archive_handle.flush()
            os.fsync(archive_handle.fileno())
        # A concurrently created link is replaced as a directory entry; it is
        # never opened or followed. The initial check still gives deterministic
        # rejection for a destination that was already unsafe.
        os.replace(temporary_path, archive_path)
        temporary_path = None
    finally:
        for descriptor, _member_status in validated.values():
            os.close(descriptor)
        os.close(root_descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
    return archive_path


def generate_report(
    campaign_id: Optional[str] = None,
    *,
    output_dir: Optional[Path] = None,
    persian: bool = False,
    archive: bool = False,
) -> Tuple[Path, Dict[str, Any]]:
    campaign, runs = _query(campaign_id)
    manifest_path = _manifest_artifact_path(campaign)
    inventory = compute_checksum_inventory(
        campaign,
        runs,
        manifest_path=manifest_path,
        artifact_root=PROJECT_ROOT,
    )
    integrity = _evidence_integrity_summary(inventory)
    campaign["_report_evidence_integrity_valid"] = integrity[
        "evidence_integrity_valid"
    ]
    summary = summarize(campaign, runs)
    summary.update(integrity)
    language = "fa" if persian else "en"
    output = _validate_report_output_tree(
        Path(output_dir)
        if output_dir
        else PROJECT_ROOT / "reports" / summary["campaign_id"] / language
    )
    chart_dir = output / "assets" / "charts"
    charts = _save_charts(summary, chart_dir, persian=persian)
    generated_files = _write_csv(output, summary, runs)
    evidence_paths = export_evidence_package(
        campaign,
        runs,
        output / "data" / "evidence",
        manifest_path=manifest_path,
        artifact_root=PROJECT_ROOT,
    )
    page = _render_html(campaign, runs, summary, charts, persian)
    output.mkdir(parents=True, exist_ok=True)
    index = output / "index.html"
    index.write_text(page, encoding="utf-8")
    if archive:
        archive_members = (
            [index]
            + [chart_dir / filename for filename in charts.values()]
            + generated_files
            + list(evidence_paths.values())
        )
        summary["archive_path"] = str(
            _archive_report_directory(output, archive_members)
        )
    return index, summary


def _aggregate_validation_failure_codes(summary: Dict[str, Any]) -> List[str]:
    """Return stable reasons why an aggregate is not thesis-final evidence."""
    failures: List[str] = []
    if not summary.get("complete", False):
        failures.append("suite_incomplete")
    if int(summary.get("technical_error_task_n") or 0):
        failures.append("technical_errors_present")
    if int(summary.get("incomplete_task_n") or 0):
        failures.append("tasks_incomplete")
    if int(summary.get("invalid_nontechnical_task_n") or 0):
        failures.append("invalid_tasks_present")
    if not summary.get("all_manifest_integrity_valid", False):
        failures.append("manifest_integrity_invalid")
    if not summary.get("all_authentication_evidence_complete", False):
        failures.append("authentication_evidence_incomplete")
    if not summary.get("evidence_integrity_valid", False):
        failures.append("artifact_integrity_invalid")
    return failures


def generate_aggregate_report(
    campaign_ids: Optional[Iterable[str]] = None,
    *,
    selector: Optional[str] = None,
    latest_count: int = 1,
    days: Optional[int] = None,
    output_dir: Optional[Path] = None,
    persian: bool = False,
    archive: bool = False,
) -> Tuple[Path, Dict[str, Any]]:
    """Generate a multi-campaign report from explicit or completed campaigns.

    Examples::

        generate_aggregate_report([uuid_a, uuid_b])
        generate_aggregate_report(selector="all-completed")
        generate_aggregate_report(selector="latest-completed", latest_count=6)
        generate_aggregate_report(selector="latest-suite", days=30)
    """
    if isinstance(campaign_ids, str):
        campaign_ids = [campaign_ids]
    effective_selector = selector
    if campaign_ids is None and effective_selector is None:
        effective_selector = "all-completed"
    observations = _query_campaigns(
        campaign_ids,
        selector=effective_selector,
        latest_count=latest_count,
        days=days,
    )
    campaign_integrity: Dict[str, Dict[str, Any]] = {}
    for campaign, runs in observations:
        inventory = compute_checksum_inventory(
            campaign,
            runs,
            manifest_path=_manifest_artifact_path(campaign),
            artifact_root=PROJECT_ROOT,
        )
        integrity = _evidence_integrity_summary(inventory)
        campaign_integrity[str(campaign["campaign_id"])] = integrity
        campaign["_report_evidence_integrity_valid"] = integrity[
            "evidence_integrity_valid"
        ]
    if campaign_ids is not None:
        selection = "explicit"
    else:
        normalized = str(effective_selector).replace("_", "-")
        selection = (
            "%s:%s" % (normalized, int(latest_count))
            if normalized == "latest-completed"
            else normalized
        )
    summary = summarize_aggregate(observations, selection=selection)
    summary["selection_days"] = int(days) if days is not None else None
    for row in summary["campaign_rows"]:
        row.update(campaign_integrity[row["campaign_id"]])
    summary["campaign_evidence_integrity"] = campaign_integrity
    summary["evidence_integrity_valid"] = all(
        row["evidence_integrity_valid"] for row in campaign_integrity.values()
    )
    validation_failures = _aggregate_validation_failure_codes(summary)
    summary["scientific_validation"] = {
        "passed": not validation_failures,
        "failure_codes": validation_failures,
        "technical_errors_are_security_outcomes": False,
        "non_evaluable_rates_render_as_zero": False,
    }
    language = "fa" if persian else "en"
    output = _validate_report_output_tree(
        Path(output_dir)
        if output_dir
        else PROJECT_ROOT
        / "reports"
        / "aggregate"
        / summary["aggregate_id"]
        / language
    )
    generated_files = _write_aggregate_csv(output, summary, observations)
    chart_index, chart_files = save_aggregate_charts(
        summary,
        output / "assets" / "charts",
        output / "data",
        persian=persian,
    )
    generated_files.extend(chart_files)
    output.mkdir(parents=True, exist_ok=True)
    index = output / "index.html"
    index.write_text(
        _render_aggregate_html(summary, persian, chart_index),
        encoding="utf-8",
    )
    if archive:
        summary["archive_path"] = str(
            _archive_report_directory(output, [index] + generated_files)
        )
    return index, summary


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    campaign_selection = parser.add_mutually_exclusive_group()
    campaign_selection.add_argument(
        "--campaign",
        action="append",
        help=(
            "Campaign UUID. Repeat for an aggregate report; one UUID preserves "
            "single-campaign behavior. A comma-separated list is also accepted."
        ),
    )
    campaign_selection.add_argument(
        "--all-completed",
        action="store_true",
        help="Aggregate every campaign whose stored status is completed",
    )
    campaign_selection.add_argument(
        "--latest-completed",
        type=int,
        nargs="?",
        const=1,
        metavar="N",
        help="Aggregate the latest N completed campaigns (default N=1)",
    )
    campaign_selection.add_argument(
        "--latest-suite",
        action="store_true",
        help=(
            "Aggregate the newest compatible complete six-scenario suite "
            "with one shared experiment signature"
        ),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--P", action="store_true", dest="persian", help="Generate the Persian RTL edition")
    parser.add_argument("--archive", action="store_true", help="Create a ZIP beside the generated report directory")
    parser.add_argument("--strict", action="store_true", help="Return exit status 2 if data are incomplete or contain technical errors")
    parser.add_argument(
        "--days",
        type=int,
        help="Only include broad-selector campaigns completed within the last N days",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    raw_campaigns = list(args.campaign or [])
    if args.days is not None and not (
        args.all_completed
        or args.latest_completed is not None
        or args.latest_suite
    ):
        print(
            "--days is valid only with --all-completed, --latest-completed, "
            "or --latest-suite",
            file=sys.stderr,
        )
        return 1
    aggregate_requested = (
        args.all_completed
        or args.latest_completed is not None
        or args.latest_suite
        or len(raw_campaigns) > 1
        or any("," in value for value in raw_campaigns)
    )
    try:
        if aggregate_requested:
            if raw_campaigns:
                index, summary = generate_aggregate_report(
                    raw_campaigns,
                    output_dir=args.output,
                    persian=args.persian,
                    archive=args.archive,
                )
            elif args.all_completed:
                index, summary = generate_aggregate_report(
                    selector="all-completed",
                    days=args.days,
                    output_dir=args.output,
                    persian=args.persian,
                    archive=args.archive,
                )
            elif args.latest_suite:
                index, summary = generate_aggregate_report(
                    selector="latest-suite",
                    days=args.days,
                    output_dir=args.output,
                    persian=args.persian,
                    archive=args.archive,
                )
            else:
                index, summary = generate_aggregate_report(
                    selector="latest-completed",
                    latest_count=args.latest_completed,
                    days=args.days,
                    output_dir=args.output,
                    persian=args.persian,
                    archive=args.archive,
                )
        else:
            campaign_id = raw_campaigns[0] if raw_campaigns else None
            index, summary = generate_report(
                campaign_id,
                output_dir=args.output,
                persian=args.persian,
                archive=args.archive,
            )
    except Exception as exc:
        print("Report generation failed: %s" % exc, file=sys.stderr)
        return 1
    print("Report: %s" % index)
    if summary.get("archive_path"):
        print("Archive: %s" % summary["archive_path"])
    if summary.get("report_type") == "multi_campaign_aggregate":
        print(
            "Aggregate campaigns=%s; recorded=%s; valid=%s; technical_errors=%s; incomplete=%s"
            % (
                summary["campaign_n"],
                summary["recorded_task_n"],
                summary["valid_task_n"],
                summary["technical_error_task_n"],
                summary["incomplete_task_n"],
            )
        )
        if args.strict and _aggregate_validation_failure_codes(summary):
            return 2
    else:
        print(
            "Campaign completeness: %s/%s; valid=%s; technical_errors=%s"
            % (summary["completed"], summary["planned"], summary["valid"], summary["technical_errors"])
        )
        print(
            "Authentication evidence: %s/%s; manifest_digest=%s"
            % (
                summary.get("authentication_observations", 0),
                summary.get("expected_authentication_observations", 0),
                "valid" if summary.get("manifest_integrity_valid") else "invalid",
            )
        )
        if args.strict and (
            not summary["complete"]
            or summary["technical_errors"]
            or summary.get("incomplete", 0)
            or summary.get("invalid_nontechnical", 0)
            or not summary.get("authentication_complete", False)
            or not summary.get("manifest_integrity_valid", False)
            or not summary.get("evidence_integrity_valid", False)
        ):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
