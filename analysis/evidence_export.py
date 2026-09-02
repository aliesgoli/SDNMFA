"""Deterministic exports for per-task scientific evidence and raw metrics.

The database intentionally retains nested JSON observations.  This module
provides a stable, dependency-light boundary between those records and report
generators: it preserves the nested evidence in a raw JSON export, exposes a
flat task table for audit/re-analysis, verifies recorded artifacts when they
are locally available, and summarizes the randomized complete-block design at
the ``sample_id`` level.

Missing observations remain ``None``.  The helpers only derive values from
recorded samples/counts and label those derivations with a source field.
"""

from __future__ import annotations

import csv
import fcntl
import hashlib
import hmac
import io
import json
import math
import os
import re
import statistics
import tempfile
import threading
from collections import Counter, defaultdict
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from experiments.campaign import manifest_digest


EXPORT_SCHEMA_VERSION = 1
JSON_SAFE_INTEGER_MAX = 2**53 - 1
DEFAULT_EXPECTED_POLICIES: Tuple[str, ...] = (
    "password_only",
    "password_otp",
    "password_biometric",
    "password_otp_biometric",
)
RESISTED_OUTCOMES = {"attack_blocked", "availability_preserved"}
EVALUABLE_OUTCOMES = {
    "attack_blocked",
    "attack_success",
    "availability_preserved",
    "availability_degraded",
}
SEED_KEYS = {"seed", "random_seed", "campaign_seed", "rng_seed"}
_EXPORT_LOCKS: Dict[str, threading.Lock] = {}
_EXPORT_LOCKS_GUARD = threading.Lock()


RUN_FIELDNAMES: Tuple[str, ...] = (
    "campaign_id",
    "campaign_seed",
    "task_id",
    "sample_id",
    "run_id",
    "operator_attempt_id",
    "task_auth_attempt_id",
    "attempt_id",
    "scenario",
    "intensity_level",
    "repetition",
    "policy",
    "policy_position",
    "binding_profile",
    "topology_id",
    "execution_status",
    "is_valid",
    "security_outcome",
    "result_success",
    "result_message",
    "protocol_id",
    "actual_mechanism",
    "target_host",
    "target_port",
    "configured_duration_seconds",
    "configured_rate_pps",
    "configured_request_count",
    "configured_worker_count",
    "configured_source_count",
    "configured_payload_size_bytes",
    "configured_offered_load_ratio",
    "configured_load_mbps",
    "achieved_request_rate_rps",
    "achieved_rate_pps",
    "achieved_load_mbps",
    "rate_achievement_percent",
    "rate_achievement_source",
    "packets_sent",
    "bytes_sent",
    "send_errors",
    "packets_received",
    "bytes_received",
    "packet_delivery_percent",
    "packet_loss_count",
    "attack_probe_accessible",
    "attack_probe_count",
    "attack_probe_successes",
    "attack_probe_unsuccessful_count",
    "attack_probe_unknown_count",
    "attack_probe_loss_percent",
    "attack_probe_timed_out_count",
    "attack_probe_latency_mean_ms",
    "attack_probe_latency_p95_ms",
    "attack_probe_return_code",
    "baseline_availability_rate",
    "baseline_availability_source",
    "baseline_probe_count",
    "baseline_probe_successes",
    "baseline_probe_loss_count",
    "baseline_probe_unknown_count",
    "baseline_probe_loss_percent",
    "during_availability_rate",
    "during_availability_source",
    "during_probe_count",
    "during_probe_successes",
    "during_probe_loss_count",
    "during_probe_unknown_count",
    "during_probe_loss_percent",
    "recovery_availability_rate",
    "recovery_availability_source",
    "recovery_probe_count",
    "recovery_probe_successes",
    "recovery_probe_loss_count",
    "recovery_probe_unknown_count",
    "recovery_probe_loss_percent",
    "receiver_status",
    "receiver_evidence_valid",
    "receiver_return_code",
    "receiver_duration_seconds",
    "receiver_actual_rate_pps",
    "receiver_packets_received",
    "receiver_bytes_received",
    "receiver_stderr",
    "deny_evidence_status",
    "deny_evidence_available",
    "deny_event_count",
    "deny_reasons_json",
    "deny_error",
    "error_type",
    "error_message",
    "execution_error",
    "restoration_error",
    "cleanup_errors_json",
    "resource_sample_count",
    "resource_interval_seconds",
    "resource_process_pid",
    "resource_process_label",
    "process_cpu_mean_percent",
    "process_cpu_p95_percent",
    "process_cpu_max_percent",
    "process_rss_mean_bytes",
    "process_rss_p95_bytes",
    "process_rss_max_bytes",
    "system_cpu_mean_percent",
    "system_cpu_p95_percent",
    "system_cpu_max_percent",
    "system_memory_mean_percent",
    "system_memory_p95_percent",
    "system_memory_max_percent",
    "legacy_cpu_percent_equivalent",
    "pcap_enabled",
    "pcap_record_status",
    "pcap_path",
    "pcap_sha256",
    "pcap_size_bytes",
    "pcap_stderr",
    "sampled_parameters_present",
    "sampled_parameters_json",
    "attack_probe_samples_json",
    "availability_samples_json",
    "deny_events_json",
    "receiver_result_json",
    "resource_metrics_json",
    "pcap_evidence_json",
    "observed_result_json",
)


INVENTORY_FIELDNAMES: Tuple[str, ...] = (
    "artifact_type",
    "artifact_id",
    "campaign_id",
    "task_id",
    "enabled",
    "recorded_path",
    "resolved_path",
    "presence_status",
    "declared_sha256",
    "computed_sha256",
    "checksum_status",
    "checksum_source",
    "checksum_scope",
    "payload_computed_sha256",
    "payload_checksum_status",
    "file_sha256",
    "declared_size_bytes",
    "actual_size_bytes",
    "size_status",
    "error",
)


BLOCK_FIELDNAMES: Tuple[str, ...] = (
    "sample_id",
    "sample_id_missing",
    "scenario",
    "intensity_level",
    "repetition",
    "run_count",
    "expected_policy_count",
    "observed_policy_count",
    "valid_run_count",
    "invalid_run_count",
    "duplicate_policy_count",
    "complete_block",
    "fully_valid_block",
    "metadata_consistent",
    "paired_parameters_consistent",
    "resisted_valid_run_count",
    "valid_resistance_percent",
    "policies_json",
    "missing_policies_json",
    "valid_policies_json",
    "invalid_policies_json",
    "outcomes_json",
    "error_types_json",
    "mean_baseline_availability_rate",
    "mean_during_availability_rate",
    "mean_recovery_availability_rate",
    "mean_attack_probe_success_percent",
    "mean_achieved_rate_pps",
    "mean_rate_achievement_percent",
    "mean_process_cpu_p95_percent",
)


INVALID_RUN_FIELDNAMES: Tuple[str, ...] = (
    "campaign_id",
    "task_id",
    "sample_id",
    "scenario",
    "intensity_level",
    "repetition",
    "policy",
    "execution_status",
    "security_outcome",
    "error_type",
    "error_message",
    "execution_error",
    "restoration_error",
    "cleanup_errors_json",
)


METRIC_SUMMARY_FIELDNAMES: Tuple[str, ...] = (
    "population",
    "metric",
    "n_blocks",
    "mean",
    "median",
    "minimum",
    "maximum",
    "standard_deviation",
    "standard_error",
    "ci95_low",
    "ci95_high",
    "ci95_method",
)


POLICY_METRIC_SUMMARY_FIELDNAMES: Tuple[str, ...] = (
    "population",
    "policy",
    "metric",
    "n_blocks",
    "mean",
    "median",
    "minimum",
    "maximum",
    "standard_deviation",
    "standard_error",
    "ci95_low",
    "ci95_high",
    "ci95_method",
)


POLICY_SUMMARY_FIELDNAMES: Tuple[str, ...] = (
    "population",
    "policy",
    "n_blocks",
    "resisted_blocks",
    "resistance_percent",
    "resistance_ci95_low",
    "resistance_ci95_high",
    "outcomes_json",
    "mean_baseline_availability_rate",
    "mean_during_availability_rate",
    "mean_recovery_availability_rate",
    "mean_attack_probe_success_percent",
    "mean_achieved_rate_pps",
    "mean_rate_achievement_percent",
    "mean_process_cpu_p95_percent",
)


RESOURCE_SAMPLE_FIELDNAMES: Tuple[str, ...] = (
    "campaign_id",
    "task_id",
    "sample_id",
    "run_id",
    "scenario",
    "intensity_level",
    "repetition",
    "policy",
    "sample_index",
    "elapsed_seconds",
    "process_cpu_percent",
    "process_rss_bytes",
    "system_cpu_percent",
    "system_memory_percent",
)


PROBE_SAMPLE_FIELDNAMES: Tuple[str, ...] = (
    "campaign_id",
    "task_id",
    "sample_id",
    "run_id",
    "scenario",
    "intensity_level",
    "repetition",
    "policy",
    "series",
    "phase",
    "sample_index",
    "accessible",
    "http_status",
    "return_code",
    "timed_out",
    "elapsed_ms",
    "relative_time_s",
    "error",
)


AUTH_OBSERVATION_FIELDNAMES: Tuple[str, ...] = (
    "campaign_id",
    "run_id",
    "scenario",
    "policy",
    "repetition",
    "required_factors_json",
    "supplied_factors_json",
    "factor_simulation",
    "authentication_succeeded",
    "latency_ms",
    "resource_process_pid",
    "resource_process_label",
    "resource_cpu_seconds",
    "resource_cpu_percent_equivalent",
    "resource_rss_before_bytes",
    "resource_rss_after_bytes",
    "resource_rss_delta_bytes",
    "resource_metrics_json",
)


_MISSING = object()


_SENSITIVE_EXPORT_KEYS = {
    "username",
    "user_name",
    "user_id",
    "email",
    "password",
    "password_hash",
    "otp",
    "otp_code",
    "biometric",
    "biometric_data",
    "biometric_sample",
    "controller_api_token",
    "api_token",
    "access_token",
    "refresh_token",
    "token",
    "secret",
    "pepper",
    "env",
    "environment",
    "authorization",
    "proxy_authorization",
    "cookie",
    "set_cookie",
    "credential",
    "credentials",
    "session_token",
    "session_cookie",
}

_TEXT_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic)\s+)[^\s,;]+"),
    re.compile(r"(?i)\b((?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|pepper|"
        r"otp[_-]?code|biometric[_-]?(?:data|sample))\s*[:=]\s*)[^\s,;]+"
    ),
    re.compile(r"(?i)\b(cookie\s*:\s*)[^\r\n]+"),
)


def _sanitize_text(value: str) -> str:
    cleaned = str(value)
    for pattern in _TEXT_SECRET_PATTERNS:
        cleaned = pattern.sub(lambda match: match.group(1) + "[REDACTED]", cleaned)
    return cleaned


def _sensitive_export_key(key: Any) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    if normalized in _SENSITIVE_EXPORT_KEYS:
        return True
    return normalized.endswith(("_password", "_secret", "_token", "_pepper"))


def _sanitize_for_export(value: Any) -> Any:
    """Recursively omit credentials, factor values, and direct user identity."""

    if isinstance(value, Mapping):
        return {
            str(key): _sanitize_for_export(item)
            for key, item in value.items()
            if not _sensitive_export_key(key)
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize_for_export(item) for item in value]
    if isinstance(value, (set, frozenset)):
        clean = [_sanitize_for_export(item) for item in value]
        return sorted(clean, key=_canonical_json)
    if isinstance(value, str):
        return _sanitize_text(value)
    return value


_PUBLIC_PATH_KEYS = {
    "file",
    "file_path",
    "filename",
    "manifest_path",
    "path",
    "pcap_path",
    "recorded_path",
    "resolved_path",
}


def _is_public_path_key(key: Any) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in _PUBLIC_PATH_KEYS or normalized.endswith(
        ("_file_path", "_filename", "_path")
    )


def _portable_export_path(value: Any, artifact_root: Optional[Path]) -> Any:
    """Return a reproducible public name without exposing a host path.

    File verification always uses the original path before this helper is
    called.  Paths inside ``artifact_root`` are represented relative to that
    root; paths outside it are reduced to a basename.  This preserves useful
    artifact identity in exported evidence without publishing an operator's
    home directory or workstation layout.
    """

    if value in (None, ""):
        return None
    text = str(value)
    if "://" in text:
        return text

    # pathlib on POSIX does not recognize Windows drive paths.  Treat them as
    # host-local absolute paths and publish only their final component.
    if re.match(r"^[A-Za-z]:[\\/]", text) or text.startswith("\\\\"):
        return PureWindowsPath(text).name or None

    path = Path(text)
    if artifact_root is not None:
        root_absolute = Path(os.path.abspath(str(artifact_root)))
        candidate = path if path.is_absolute() else root_absolute / path
        candidate_absolute = Path(os.path.abspath(str(candidate)))
        try:
            relative = candidate_absolute.relative_to(root_absolute)
        except ValueError:
            return candidate_absolute.name or None
        if relative.parts and relative.parts[0] != "..":
            return relative.as_posix()
        return candidate_absolute.name or None

    if path.is_absolute():
        return path.name or None
    normalized = Path(os.path.normpath(text))
    if ".." in normalized.parts:
        return normalized.name or None
    return normalized.as_posix()


def _publicize_local_paths(value: Any, artifact_root: Optional[Path]) -> Any:
    """Recursively replace host-local path values with portable names."""

    if isinstance(value, Mapping):
        public: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_public_path_key(key_text) and not isinstance(
                item, (Mapping, list, tuple, set, frozenset)
            ):
                public[key_text] = _portable_export_path(item, artifact_root)
            else:
                public[key_text] = _publicize_local_paths(item, artifact_root)
        return public
    if isinstance(value, (list, tuple)):
        return [_publicize_local_paths(item, artifact_root) for item in value]
    if isinstance(value, (set, frozenset)):
        public_items = [_publicize_local_paths(item, artifact_root) for item in value]
        return sorted(public_items, key=_canonical_json)
    return value


def _publicize_flat_row_paths(
    row: Mapping[str, Any],
    artifact_root: Optional[Path],
) -> Dict[str, Any]:
    """Make direct and JSON-encoded path fields portable in one flat row."""

    public = dict(row)
    for key, value in list(public.items()):
        if _is_public_path_key(key):
            public[key] = _portable_export_path(value, artifact_root)
            continue
        if not key.endswith("_json") or not isinstance(value, str):
            continue
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError):
            continue
        public[key] = _canonical_json(
            _publicize_local_paths(decoded, artifact_root)
        )
    return public


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return dict(parsed) if isinstance(parsed, Mapping) else {}
    return {}


def _is_seed_key(key: Optional[str]) -> bool:
    if not key:
        return False
    normalized = str(key).lower()
    return normalized in SEED_KEYS or normalized.endswith("_seed")


def normalize_large_seeds(value: Any, _key: Optional[str] = None) -> Any:
    """Return JSON-ready data with unsafe integer seed values as strings.

    Counts and other large integers remain integers.  Only fields whose key is
    ``seed`` or a conventional ``*_seed`` variant are normalized, preventing
    precision loss in JavaScript/CSV consumers without changing observations.
    """

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if _is_seed_key(_key) and abs(value) > JSON_SAFE_INTEGER_MAX:
            return str(value)
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, Mapping):
        return {
            str(key): normalize_large_seeds(item, str(key))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [normalize_large_seeds(item, _key) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [normalize_large_seeds(item, _key) for item in value]
        return sorted(normalized, key=lambda item: _canonical_json(item))
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return str(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        normalize_large_seeds(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _pretty_json(value: Any) -> str:
    return (
        json.dumps(
            normalize_large_seeds(value),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    )


def _pretty_json_exact(value: Any) -> str:
    """Serialize already-normalized data without changing canonical types."""
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    )


def _first_present(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def _first_across(candidates: Sequence[Tuple[Mapping[str, Any], Sequence[str]]]) -> Any:
    for mapping, keys in candidates:
        value = _first_present(mapping, keys)
        if value is not None:
            return value
    return None


def _bool_or_none(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1", "enabled", "valid"}:
            return True
        if normalized in {"false", "no", "0", "disabled", "invalid"}:
            return False
    return None


def _number_or_none(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _int_or_none(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 10)
        except (TypeError, ValueError):
            pass
    number = _number_or_none(value)
    if number is None or not number.is_integer():
        return None
    return int(number)


def _numeric_value(value: Any) -> Any:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        integer = _int_or_none(value)
        if integer is not None:
            return integer
    number = _number_or_none(value)
    if number is None:
        return value if value is not None else None
    return int(number) if number.is_integer() else number


def _sample_probe_stats(samples: Any) -> Dict[str, Optional[float]]:
    if not isinstance(samples, list):
        return {
            "count": None,
            "successes": None,
            "losses": None,
            "unknown": None,
            "loss_percent": None,
        }
    clean = [item for item in samples if isinstance(item, Mapping)]
    known: List[bool] = []
    for item in clean:
        accessible = _bool_or_none(item.get("accessible"))
        if accessible is not None:
            known.append(accessible)
    successes = sum(1 for item in known if item)
    losses = sum(1 for item in known if not item)
    return {
        "count": len(clean),
        "successes": successes,
        "losses": losses,
        "unknown": len(clean) - len(known),
        "loss_percent": (100.0 * losses / len(known)) if known else None,
    }


def _phase_observation(
    metrics: Mapping[str, Any],
    preflight: Mapping[str, Any],
    postflight: Mapping[str, Any],
    phase: str,
) -> Dict[str, Any]:
    aliases = {
        "baseline": {"baseline", "before", "preflight", "legitimate_before"},
        "during": {"during", "attack", "traffic"},
        "recovery": {"recovery", "after", "postflight", "legitimate_after"},
    }[phase]
    samples: Any = _MISSING
    sample_source: Optional[str] = None

    availability_samples = metrics.get("availability_samples")
    if isinstance(availability_samples, list):
        matching = [
            dict(item)
            for item in availability_samples
            if isinstance(item, Mapping)
            and str(item.get("phase") or "").lower() in aliases
        ]
        if matching or any(
            isinstance(item, Mapping) and str(item.get("phase") or "").lower() in aliases
            for item in availability_samples
        ):
            samples = matching
            sample_source = "metrics.availability_samples"

    for key in ("%s_samples" % phase, "%s_probe_samples" % phase):
        if samples is _MISSING and key in metrics and isinstance(metrics.get(key), list):
            samples = metrics.get(key)
            sample_source = "metrics.%s" % key

    if samples is _MISSING and phase == "baseline":
        for key in ("legitimate_samples", "baseline_samples", "samples"):
            if key in preflight and isinstance(preflight.get(key), list):
                samples = preflight.get(key)
                sample_source = "metrics.preflight.%s" % key
                break
    if samples is _MISSING and phase == "recovery":
        for key in ("samples", "recovery_samples", "legitimate_samples"):
            if key in postflight and isinstance(postflight.get(key), list):
                samples = postflight.get(key)
                sample_source = "metrics.postflight.%s" % key
                break

    rate = None
    rate_source = None
    for key in (
        "%s_availability_rate" % phase,
        "%s_rate" % phase,
        "%s_success_rate" % phase,
    ):
        if key in metrics and metrics.get(key) is not None:
            parsed = _number_or_none(metrics.get(key))
            if parsed is not None:
                rate = parsed
                rate_source = "metrics.%s" % key
            break

    stats = _sample_probe_stats(None if samples is _MISSING else samples)
    if rate is None:
        successes = _number_or_none(stats.get("successes"))
        losses = _number_or_none(stats.get("losses"))
        if successes is not None and losses is not None and successes + losses > 0:
            rate = successes / (successes + losses)
            rate_source = "derived_from_%s" % (sample_source or "recorded_samples")

    # Pre/postflight rates are legacy fallbacks.  A phase-specific sample
    # series takes precedence so, for example, a failed flood baseline is not
    # accidentally replaced by the earlier generic preflight control rate.
    fallback_sources: List[Tuple[Mapping[str, Any], Sequence[str], str]] = []
    if phase == "baseline":
        fallback_sources.append(
            (preflight, ("legitimate_rate", "baseline_rate", "rate"), "metrics.preflight")
        )
    if phase == "recovery":
        fallback_sources.append(
            (postflight, ("rate", "recovery_rate", "legitimate_rate"), "metrics.postflight")
        )
    if rate is None:
        for mapping, keys, prefix in fallback_sources:
            for key in keys:
                if key in mapping and mapping.get(key) is not None:
                    parsed = _number_or_none(mapping.get(key))
                    if parsed is not None:
                        rate = parsed
                        rate_source = "%s.%s" % (prefix, key)
                    break
            if rate is not None:
                break

    if stats["count"] is None:
        count = _first_present(
            metrics,
            ("%s_probe_count" % phase, "%s_count" % phase),
        )
        successes = _first_present(
            metrics,
            ("%s_probe_successes" % phase, "%s_successes" % phase),
        )
        losses = _first_present(
            metrics,
            ("%s_probe_loss_count" % phase, "%s_losses" % phase),
        )
        stats["count"] = _int_or_none(count)
        stats["successes"] = _int_or_none(successes)
        stats["losses"] = _int_or_none(losses)
        stats["unknown"] = None
        if stats["count"] is not None and stats["losses"] is not None and stats["count"] > 0:
            stats["loss_percent"] = 100.0 * float(stats["losses"]) / float(stats["count"])

    return {
        "rate": rate,
        "rate_source": rate_source,
        "samples": [] if samples is _MISSING else samples,
        "sample_source": sample_source,
        **stats,
    }


def _summary_stat(resource: Mapping[str, Any], family: str, statistic: str) -> Any:
    nested = _as_dict(resource.get(family))
    value = _first_present(nested, (statistic,))
    if value is None:
        value = _first_present(
            resource,
            (
                "%s_%s" % (family, statistic),
                "%s_%s" % (statistic, family),
            ),
        )
    return _numeric_value(value)


def _cleanup_indicator_is_error(key: str, value: Any) -> bool:
    """Interpret cleanup/restoration fields without treating success as error.

    Some attack metrics include positive audit evidence such as
    ``restoration_verified=True`` and ``arp_restored_state={"verified": True}``.
    Their field names contain ``restore`` even though they document a successful
    cleanup.  Explicit failures and non-empty error/warning values remain part
    of the exported audit trail.
    """
    if value in (None, "", [], {}):
        return False
    if isinstance(value, bool):
        return value is False
    if isinstance(value, Mapping):
        for error_key in ("error", "errors", "warning", "warnings", "restore_error"):
            error_value = value.get(error_key)
            if error_value not in (None, "", [], {}):
                return True
        for status_key in (
            "verified",
            "restoration_verified",
            "cleanup_verified",
            "restored",
            "successful",
            "success",
            "ok",
        ):
            status_value = value.get(status_key)
            if isinstance(status_value, bool):
                return status_value is False
        # State snapshots are evidence, not errors, unless they explicitly
        # report a failed status or an error above.
        if "state" in key:
            return False
    return True


def _collect_cleanup_errors(value: Any, path: str = "metrics") -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if isinstance(value, Mapping):
        for key in sorted(value, key=str):
            item = value[key]
            item_path = "%s.%s" % (path, key)
            lowered = str(key).lower()
            if any(token in lowered for token in ("cleanup", "restore", "restoration")):
                if _cleanup_indicator_is_error(lowered, item):
                    rows.append({"field": item_path, "value": normalize_large_seeds(item)})
            if isinstance(item, (Mapping, list, tuple)):
                rows.extend(_collect_cleanup_errors(item, item_path))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            if isinstance(item, (Mapping, list, tuple)):
                rows.extend(_collect_cleanup_errors(item, "%s[%s]" % (path, index)))
    # A nested object can expose the same restoration field through multiple
    # paths only if the source itself duplicates it; preserve that audit fact.
    return rows


def _run_components(run: Mapping[str, Any]) -> Tuple[Dict[str, Any], ...]:
    record = dict(run)
    params_value = _first_present(record, ("sampled_parameters", "parameters", "attack_params"))
    params = _as_dict(params_value)
    observed_value = _first_present(record, ("observed_result", "attack_result", "result"))
    observed = _as_dict(observed_value)
    metrics = _as_dict(observed.get("metrics"))
    if not metrics:
        metrics = _as_dict(record.get("metrics"))
    if not metrics and any(
        key in observed
        for key in ("security_outcome", "execution_status", "attack_probe", "preflight")
    ):
        metrics = dict(observed)
    resource = _as_dict(record.get("resource_metrics"))
    if not resource:
        resource = _as_dict(metrics.get("resource_metrics"))
    pcap = _as_dict(record.get("pcap_evidence"))
    if not pcap:
        pcap = _as_dict(metrics.get("pcap_evidence"))
    return record, params, observed, metrics, resource, pcap


def flatten_experiment_run(
    run: Mapping[str, Any],
    campaign: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Flatten one persisted experiment task without inventing missing values."""

    record, params, observed, metrics, resource, pcap = _run_components(run)
    campaign_record = dict(campaign or {})
    manifest = _as_dict(campaign_record.get("manifest"))
    preflight = _as_dict(metrics.get("preflight"))
    postflight = _as_dict(metrics.get("postflight"))
    attack_probe = _as_dict(
        _first_present(metrics, ("attack_probe", "probe", "attack_observation"))
    )
    deny = _as_dict(
        _first_present(
            metrics,
            ("controller_deny_evidence", "deny_evidence", "controller_denials"),
        )
    )
    receiver = _as_dict(
        _first_present(metrics, ("receiver_result", "receiver", "target_receiver"))
    )

    baseline = _phase_observation(metrics, preflight, postflight, "baseline")
    during = _phase_observation(metrics, preflight, postflight, "during")
    recovery = _phase_observation(metrics, preflight, postflight, "recovery")

    attack_samples = attack_probe.get("samples")
    attack_sample_stats = _sample_probe_stats(attack_samples)
    attack_count = _int_or_none(
        _first_present(attack_probe, ("attempt_count", "probe_count", "count"))
    )
    if attack_count is None:
        attack_count = _int_or_none(attack_sample_stats.get("count"))
    attack_successes = _int_or_none(
        _first_present(
            attack_probe,
            ("successful_attempts", "success_count", "probe_successes", "successes"),
        )
    )
    if attack_successes is None:
        attack_successes = _int_or_none(attack_sample_stats.get("successes"))
    attack_losses = _int_or_none(
        _first_present(
            attack_probe,
            (
                "blocked_or_failed_attempts",
                "failed_attempts",
                "probe_loss_count",
                "loss_count",
            ),
        )
    )
    if attack_losses is None:
        attack_losses = _int_or_none(attack_sample_stats.get("losses"))
    attack_unknown = _int_or_none(attack_sample_stats.get("unknown"))
    attack_loss_percent = _number_or_none(
        _first_present(attack_probe, ("loss_percent", "probe_loss_percent"))
    )
    if attack_loss_percent is None and attack_count and attack_losses is not None:
        attack_loss_percent = 100.0 * attack_losses / float(attack_count)

    configured_rate = _numeric_value(
        _first_across(
            (
                (params, ("rate_pps", "target_rate_pps", "configured_rate_pps")),
                (metrics, ("target_rate_pps", "requested_rate_pps", "configured_rate_pps")),
            )
        )
    )
    achieved_rate = _numeric_value(
        _first_present(metrics, ("actual_rate_pps", "achieved_rate_pps", "measured_rate_pps"))
    )
    rate_achievement = _number_or_none(
        _first_present(metrics, ("rate_achievement_percent", "rate_achieved_percent"))
    )
    rate_achievement_source = "metrics.rate_achievement_percent" if rate_achievement is not None else None
    configured_rate_number = _number_or_none(configured_rate)
    achieved_rate_number = _number_or_none(achieved_rate)
    if (
        rate_achievement is None
        and configured_rate_number is not None
        and achieved_rate_number is not None
        and configured_rate_number > 0
    ):
        rate_achievement = 100.0 * achieved_rate_number / configured_rate_number
        rate_achievement_source = "derived_from_configured_and_achieved_rate"

    receiver_valid = _bool_or_none(
        _first_across(
            (
                (metrics, ("receiver_evidence_valid", "receiver_valid")),
                (receiver, ("valid",)),
            )
        )
    )
    if receiver_valid is True:
        receiver_status = "valid"
    elif receiver_valid is False:
        receiver_status = "invalid"
    elif receiver:
        receiver_status = "unverified"
    else:
        receiver_status = None

    deny_available = _bool_or_none(deny.get("available"))
    deny_events = deny.get("events") if isinstance(deny.get("events"), list) else []
    deny_count = _int_or_none(_first_present(deny, ("count", "event_count", "deny_count")))
    if deny_count is None and deny_events:
        deny_count = len([item for item in deny_events if isinstance(item, Mapping)])
    if deny_available is True:
        deny_status = "available"
    elif deny_available is False:
        deny_status = "unavailable"
    else:
        deny_status = "unverified"
    deny_reasons = sorted(
        {
            str(item.get("reason"))
            for item in deny_events
            if isinstance(item, Mapping) and item.get("reason") is not None
        }
    )

    valid = _bool_or_none(_first_across(((record, ("is_valid",)), (metrics, ("is_valid",)))))
    error_type = _first_present(metrics, ("error_type", "technical_error_type"))
    result_message = _first_present(observed, ("message", "result_message"))
    error_message = _first_present(metrics, ("error_message", "error", "exception"))
    if error_message is None and (error_type is not None or valid is False):
        error_message = result_message
    execution_error = _first_across(
        (
            (attack_probe, ("setup_or_execution_error", "execution_error", "error")),
            (metrics, ("monitor_error", "worker_launch_error", "receiver_launch_error", "exception")),
            (_as_dict(metrics.get("network_diagnostics")), ("setup_or_execution_error", "error")),
        )
    )
    restoration_error = _first_present(
        metrics, ("restore_error", "restoration_error", "identity_restore_error")
    )
    cleanup_errors = _collect_cleanup_errors(metrics)

    pcap_enabled = _bool_or_none(_first_present(pcap, ("enabled", "capture_enabled")))
    pcap_path = _first_present(pcap, ("path", "file_path", "filename", "file"))
    pcap_sha256 = _first_present(pcap, ("sha256", "checksum_sha256", "checksum", "hash"))
    pcap_size = _numeric_value(_first_present(pcap, ("size_bytes", "bytes", "size")))
    if pcap_enabled is False:
        pcap_record_status = "disabled"
    elif pcap_path or pcap_sha256 or pcap_size is not None:
        pcap_record_status = "recorded"
    elif pcap_enabled is True:
        pcap_record_status = "missing_metadata"
    else:
        pcap_record_status = "unverified"

    seed_value = _first_across(
        (
            (campaign_record, ("seed", "random_seed")),
            (manifest, ("seed", "random_seed")),
            (record, ("campaign_seed", "seed", "random_seed")),
            (metrics, ("campaign_seed", "seed", "random_seed")),
        )
    )
    normalized_seed = normalize_large_seeds(seed_value, "campaign_seed")

    configured_request_count = _numeric_value(
        _first_across(
            (
                (params, ("request_count", "configured_request_count")),
                (metrics, ("requested_request_count", "target_request_count")),
            )
        )
    )
    availability_samples = metrics.get("availability_samples")
    if not isinstance(availability_samples, list):
        combined_samples: List[Any] = []
        for observation in (baseline, during, recovery):
            if isinstance(observation.get("samples"), list):
                combined_samples.extend(observation["samples"])
        availability_samples = combined_samples

    row: Dict[str, Any] = {
        "campaign_id": _first_across(((record, ("campaign_id",)), (campaign_record, ("campaign_id",)))),
        "campaign_seed": normalized_seed,
        "task_id": record.get("task_id") or metrics.get("task_id"),
        "sample_id": record.get("sample_id") or metrics.get("sample_id"),
        "run_id": record.get("run_id") or metrics.get("run_id"),
        "operator_attempt_id": record.get("operator_attempt_id"),
        "task_auth_attempt_id": record.get("task_auth_attempt_id"),
        "attempt_id": metrics.get("attempt_id") or record.get("attempt_id"),
        "scenario": record.get("scenario") or metrics.get("attack_type") or metrics.get("scenario"),
        "intensity_level": record.get("intensity_level") or metrics.get("intensity_level") or record.get("intensity"),
        "repetition": _numeric_value(record.get("repetition") if record.get("repetition") is not None else metrics.get("repetition")),
        "policy": record.get("mfa_mode") or record.get("policy") or metrics.get("mode") or metrics.get("mfa_mode"),
        "policy_position": _numeric_value(record.get("policy_position")),
        "binding_profile": record.get("binding_profile") or metrics.get("binding_profile"),
        "topology_id": record.get("topology_id") or metrics.get("topology_id"),
        "execution_status": record.get("execution_status") or metrics.get("execution_status"),
        "is_valid": valid,
        "security_outcome": metrics.get("security_outcome") or record.get("security_outcome"),
        "result_success": _bool_or_none(observed.get("success")),
        "result_message": result_message,
        "protocol_id": metrics.get("protocol_id") or campaign_record.get("protocol_id"),
        "actual_mechanism": metrics.get("actual_mechanism"),
        "target_host": _first_across(((params, ("target_host", "target_ip")), (metrics, ("target_host", "target_ip")))),
        "target_port": _numeric_value(_first_across(((params, ("target_port",)), (metrics, ("target_port",))))),
        "configured_duration_seconds": _numeric_value(_first_across(((params, ("duration_seconds", "duration_s")), (metrics, ("requested_duration_seconds", "configured_duration_seconds"))))),
        "configured_rate_pps": configured_rate,
        "configured_request_count": configured_request_count,
        "configured_worker_count": _numeric_value(_first_across(((params, ("worker_count", "threads")), (metrics, ("requested_threads", "worker_count"))))),
        "configured_source_count": _numeric_value(_first_across(((params, ("source_count",)), (metrics, ("distinct_source_count", "source_count"))))),
        "configured_payload_size_bytes": _numeric_value(_first_across(((params, ("payload_size_bytes", "payload_bytes")), (metrics, ("payload_size_bytes",))))),
        "configured_offered_load_ratio": _numeric_value(_first_present(params, ("offered_load_ratio", "target_load_ratio"))),
        "configured_load_mbps": _numeric_value(_first_across(((params, ("offered_load_mbps", "configured_load_mbps", "target_load_mbps")), (metrics, ("configured_load_mbps", "target_load_mbps"))))),
        "achieved_request_rate_rps": _numeric_value(_first_present(attack_probe, ("actual_request_rate", "achieved_request_rate", "request_rate_rps"))),
        "achieved_rate_pps": achieved_rate,
        "achieved_load_mbps": _numeric_value(_first_present(metrics, ("actual_load_mbps", "achieved_load_mbps", "measured_load_mbps"))),
        "rate_achievement_percent": rate_achievement,
        "rate_achievement_source": rate_achievement_source,
        "packets_sent": _numeric_value(metrics.get("packets_sent")),
        "bytes_sent": _numeric_value(metrics.get("bytes_sent")),
        "send_errors": _numeric_value(metrics.get("send_errors")),
        "packets_received": _numeric_value(_first_across(((metrics, ("packets_received",)), (receiver, ("packets_received",))))),
        "bytes_received": _numeric_value(_first_across(((metrics, ("bytes_received",)), (receiver, ("bytes_received",))))),
        "packet_delivery_percent": _numeric_value(_first_present(metrics, ("packet_delivery_percent", "delivery_percent"))),
        "packet_loss_count": _numeric_value(_first_present(metrics, ("packet_loss_count", "lost_packets", "packets_lost"))),
        "attack_probe_accessible": _bool_or_none(attack_probe.get("accessible")),
        "attack_probe_count": attack_count,
        "attack_probe_successes": attack_successes,
        "attack_probe_unsuccessful_count": attack_losses,
        "attack_probe_unknown_count": attack_unknown,
        "attack_probe_loss_percent": attack_loss_percent,
        "attack_probe_timed_out_count": _numeric_value(_first_present(attack_probe, ("timed_out_attempts", "timeout_count"))),
        "attack_probe_latency_mean_ms": _numeric_value(_first_present(attack_probe, ("latency_mean_ms", "mean_latency_ms"))),
        "attack_probe_latency_p95_ms": _numeric_value(_first_present(attack_probe, ("latency_p95_ms", "p95_latency_ms"))),
        "attack_probe_return_code": _numeric_value(attack_probe.get("return_code")),
        "receiver_status": receiver_status,
        "receiver_evidence_valid": receiver_valid,
        "receiver_return_code": _numeric_value(receiver.get("return_code")),
        "receiver_duration_seconds": _numeric_value(receiver.get("duration_seconds")),
        "receiver_actual_rate_pps": _numeric_value(_first_across(((metrics, ("actual_receive_rate_pps",)), (receiver, ("actual_receive_rate_pps", "actual_rate_pps"))))),
        "receiver_packets_received": _numeric_value(receiver.get("packets_received")),
        "receiver_bytes_received": _numeric_value(receiver.get("bytes_received")),
        "receiver_stderr": receiver.get("stderr"),
        "deny_evidence_status": deny_status,
        "deny_evidence_available": deny_available,
        "deny_event_count": deny_count,
        "deny_reasons_json": _canonical_json(deny_reasons),
        "deny_error": deny.get("error"),
        "error_type": error_type,
        "error_message": error_message,
        "execution_error": execution_error,
        "restoration_error": restoration_error,
        "cleanup_errors_json": _canonical_json(cleanup_errors),
        "resource_sample_count": _numeric_value(resource.get("sample_count")),
        "resource_interval_seconds": _numeric_value(resource.get("interval_seconds")),
        "resource_process_pid": _numeric_value(resource.get("process_pid")),
        "resource_process_label": resource.get("process_label"),
        "process_cpu_mean_percent": _summary_stat(resource, "process_cpu_percent", "mean"),
        "process_cpu_p95_percent": _summary_stat(resource, "process_cpu_percent", "p95"),
        "process_cpu_max_percent": _summary_stat(resource, "process_cpu_percent", "max"),
        "process_rss_mean_bytes": _summary_stat(resource, "process_rss_bytes", "mean"),
        "process_rss_p95_bytes": _summary_stat(resource, "process_rss_bytes", "p95"),
        "process_rss_max_bytes": _summary_stat(resource, "process_rss_bytes", "max"),
        "system_cpu_mean_percent": _summary_stat(resource, "system_cpu_percent", "mean"),
        "system_cpu_p95_percent": _summary_stat(resource, "system_cpu_percent", "p95"),
        "system_cpu_max_percent": _summary_stat(resource, "system_cpu_percent", "max"),
        "system_memory_mean_percent": _summary_stat(resource, "system_memory_percent", "mean"),
        "system_memory_p95_percent": _summary_stat(resource, "system_memory_percent", "p95"),
        "system_memory_max_percent": _summary_stat(resource, "system_memory_percent", "max"),
        "legacy_cpu_percent_equivalent": _numeric_value(resource.get("cpu_percent_equivalent")),
        "pcap_enabled": pcap_enabled,
        "pcap_record_status": pcap_record_status,
        "pcap_path": pcap_path,
        "pcap_sha256": pcap_sha256,
        "pcap_size_bytes": pcap_size,
        "pcap_stderr": _first_present(pcap, ("stderr", "error")),
        "sampled_parameters_present": bool(params),
        "sampled_parameters_json": _canonical_json(_sanitize_for_export(params)),
        "attack_probe_samples_json": _canonical_json(
            _sanitize_for_export(attack_samples if isinstance(attack_samples, list) else [])
        ),
        "availability_samples_json": _canonical_json(_sanitize_for_export(availability_samples)),
        "deny_events_json": _canonical_json(_sanitize_for_export(deny_events)),
        "receiver_result_json": _canonical_json(_sanitize_for_export(receiver)),
        "resource_metrics_json": _canonical_json(_sanitize_for_export(resource)),
        "pcap_evidence_json": _canonical_json(_sanitize_for_export(pcap)),
        "observed_result_json": _canonical_json(_sanitize_for_export(observed)),
    }

    for phase, observation in (
        ("baseline", baseline),
        ("during", during),
        ("recovery", recovery),
    ):
        row["%s_availability_rate" % phase] = observation["rate"]
        row["%s_availability_source" % phase] = observation["rate_source"]
        row["%s_probe_count" % phase] = observation["count"]
        row["%s_probe_successes" % phase] = observation["successes"]
        row["%s_probe_loss_count" % phase] = observation["losses"]
        row["%s_probe_unknown_count" % phase] = observation["unknown"]
        row["%s_probe_loss_percent" % phase] = observation["loss_percent"]

    return {
        field: normalize_large_seeds(_sanitize_for_export(row.get(field)), field)
        for field in RUN_FIELDNAMES
    }


def _run_sort_key(run: Mapping[str, Any]) -> Tuple[str, ...]:
    return (
        str(run.get("campaign_id") or ""),
        str(run.get("sample_id") or ""),
        "%012d" % (_int_or_none(run.get("policy_position")) or 0),
        str(run.get("policy") or run.get("mfa_mode") or ""),
        str(run.get("task_id") or ""),
    )


def flatten_experiment_runs(
    runs: Iterable[Mapping[str, Any]],
    campaign: Optional[Mapping[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Flatten and deterministically order experiment tasks."""

    rows = [flatten_experiment_run(run, campaign=campaign) for run in runs]
    return sorted(rows, key=_run_sort_key)


def _sample_identity(flat: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "campaign_id": flat.get("campaign_id"),
        "task_id": flat.get("task_id"),
        "sample_id": flat.get("sample_id"),
        "run_id": flat.get("run_id"),
        "scenario": flat.get("scenario"),
        "intensity_level": flat.get("intensity_level"),
        "repetition": flat.get("repetition"),
        "policy": flat.get("policy"),
    }


def flatten_resource_samples(
    runs: Iterable[Mapping[str, Any]],
    campaign: Optional[Mapping[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Return long-form controller resource time-series samples when recorded."""

    rows: List[Dict[str, Any]] = []
    for run in runs:
        _record, _params, _observed, _metrics, resource, _pcap = _run_components(run)
        samples = resource.get("samples")
        if not isinstance(samples, list):
            continue
        identity = _sample_identity(flatten_experiment_run(run, campaign=campaign))
        for index, sample in enumerate(samples, start=1):
            if not isinstance(sample, Mapping):
                continue
            row = dict(identity)
            row.update(
                {
                    "sample_index": _numeric_value(sample.get("sample_index")) or index,
                    "elapsed_seconds": _numeric_value(sample.get("elapsed_seconds")),
                    "process_cpu_percent": _numeric_value(sample.get("process_cpu_percent")),
                    "process_rss_bytes": _numeric_value(sample.get("process_rss_bytes")),
                    "system_cpu_percent": _numeric_value(sample.get("system_cpu_percent")),
                    "system_memory_percent": _numeric_value(sample.get("system_memory_percent")),
                }
            )
            rows.append({field: row.get(field) for field in RESOURCE_SAMPLE_FIELDNAMES})
    return sorted(
        rows,
        key=lambda row: (
            str(row.get("campaign_id") or ""),
            str(row.get("sample_id") or ""),
            str(row.get("task_id") or ""),
            _int_or_none(row.get("sample_index")) or 0,
        ),
    )


def _probe_sample_row(
    identity: Mapping[str, Any],
    sample: Mapping[str, Any],
    series: str,
    default_phase: str,
    index: int,
) -> Dict[str, Any]:
    row = dict(identity)
    row.update(
        {
            "series": series,
            "phase": sample.get("phase") or default_phase,
            "sample_index": _numeric_value(sample.get("sample_index")) or index,
            "accessible": _bool_or_none(sample.get("accessible")),
            "http_status": _numeric_value(sample.get("http_status")),
            "return_code": _numeric_value(sample.get("return_code")),
            "timed_out": _bool_or_none(sample.get("timed_out")),
            "elapsed_ms": _numeric_value(sample.get("elapsed_ms")),
            "relative_time_s": _numeric_value(
                _first_present(sample, ("relative_time_s", "elapsed_seconds"))
            ),
            "error": sample.get("error") or sample.get("stderr"),
        }
    )
    return {field: row.get(field) for field in PROBE_SAMPLE_FIELDNAMES}


def flatten_probe_samples(
    runs: Iterable[Mapping[str, Any]],
    campaign: Optional[Mapping[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Return attack, availability, preflight, and recovery probes in long form."""

    rows: List[Dict[str, Any]] = []
    for run in runs:
        _record, _params, _observed, metrics, _resource, _pcap = _run_components(run)
        identity = _sample_identity(flatten_experiment_run(run, campaign=campaign))
        attack_probe = _as_dict(
            _first_present(metrics, ("attack_probe", "probe", "attack_observation"))
        )
        attack_samples = attack_probe.get("samples")
        if isinstance(attack_samples, list):
            for index, sample in enumerate(attack_samples, start=1):
                if isinstance(sample, Mapping):
                    rows.append(_probe_sample_row(identity, sample, "attack_probe", "attack", index))

        availability_samples = metrics.get("availability_samples")
        availability_phases = set()
        if isinstance(availability_samples, list):
            for index, sample in enumerate(availability_samples, start=1):
                if not isinstance(sample, Mapping):
                    continue
                phase = str(sample.get("phase") or "availability")
                availability_phases.add(phase.lower())
                rows.append(_probe_sample_row(identity, sample, "availability", phase, index))

        preflight = _as_dict(metrics.get("preflight"))
        for key, series, phase in (
            ("local_service_samples", "preflight_local_service", "local_service"),
            ("legitimate_samples", "preflight_legitimate", "legitimate_before"),
            (
                "attack_source_control_samples",
                "preflight_attack_source_control",
                "attack_source_network_control",
            ),
        ):
            samples = preflight.get(key)
            if isinstance(samples, list):
                for index, sample in enumerate(samples, start=1):
                    if isinstance(sample, Mapping):
                        rows.append(_probe_sample_row(identity, sample, series, phase, index))

        postflight = _as_dict(metrics.get("postflight"))
        postflight_samples = postflight.get("samples")
        if "recovery" not in availability_phases and isinstance(postflight_samples, list):
            for index, sample in enumerate(postflight_samples, start=1):
                if isinstance(sample, Mapping):
                    rows.append(
                        _probe_sample_row(
                            identity,
                            sample,
                            "postflight_legitimate",
                            "legitimate_after",
                            index,
                        )
                    )

        for phase in ("baseline", "during", "recovery"):
            if phase in availability_phases:
                continue
            samples = metrics.get("%s_samples" % phase)
            if not isinstance(samples, list):
                continue
            if phase == "recovery" and isinstance(postflight_samples, list):
                continue
            for index, sample in enumerate(samples, start=1):
                if isinstance(sample, Mapping):
                    rows.append(
                        _probe_sample_row(
                            identity,
                            sample,
                            "%s_availability" % phase,
                            phase,
                            index,
                        )
                    )

    return sorted(
        rows,
        key=lambda row: (
            str(row.get("campaign_id") or ""),
            str(row.get("sample_id") or ""),
            str(row.get("task_id") or ""),
            str(row.get("series") or ""),
            str(row.get("phase") or ""),
            _int_or_none(row.get("sample_index")) or 0,
        ),
    )


def flatten_authentication_observations(
    campaign: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    """Export privacy-minimal factor-availability observations.

    Usernames, messages, attempt identifiers, credentials, and factor values
    are deliberately outside this contract.  Only factor *names* are retained.
    """

    rows: List[Dict[str, Any]] = []
    campaign_id = campaign.get("campaign_id")
    observations = campaign.get("authentication_runs")
    if not isinstance(observations, list):
        return rows
    for observation in observations:
        if not isinstance(observation, Mapping):
            continue
        supplied_payload = _as_dict(observation.get("supplied_factors"))
        required = observation.get("required_factors")
        if not isinstance(required, list):
            required = supplied_payload.get("required")
        supplied = supplied_payload.get("supplied")
        if not isinstance(supplied, list):
            supplied = observation.get("supplied_factors")
        if not isinstance(required, list):
            required = []
        if not isinstance(supplied, list):
            supplied = []
        resource = _as_dict(observation.get("resource_metrics"))
        row = {
            "campaign_id": observation.get("campaign_id") or campaign_id,
            "run_id": observation.get("run_id"),
            "scenario": observation.get("scenario"),
            "policy": observation.get("mfa_mode") or observation.get("policy"),
            "repetition": _numeric_value(observation.get("repetition")),
            "required_factors_json": _canonical_json(sorted(str(item) for item in required)),
            "supplied_factors_json": _canonical_json(sorted(str(item) for item in supplied)),
            "factor_simulation": supplied_payload.get("simulation") or observation.get("factor_simulation"),
            "authentication_succeeded": _bool_or_none(observation.get("authentication_succeeded")),
            "latency_ms": _numeric_value(observation.get("latency_ms")),
            "resource_process_pid": _numeric_value(resource.get("process_pid")),
            "resource_process_label": resource.get("process_label"),
            "resource_cpu_seconds": _numeric_value(resource.get("cpu_seconds")),
            "resource_cpu_percent_equivalent": _numeric_value(resource.get("cpu_percent_equivalent")),
            "resource_rss_before_bytes": _numeric_value(resource.get("rss_before_bytes")),
            "resource_rss_after_bytes": _numeric_value(resource.get("rss_after_bytes")),
            "resource_rss_delta_bytes": _numeric_value(resource.get("rss_delta_bytes")),
            "resource_metrics_json": _canonical_json(_sanitize_for_export(resource)),
        }
        rows.append({field: row.get(field) for field in AUTH_OBSERVATION_FIELDNAMES})
    return sorted(
        rows,
        key=lambda row: (
            str(row.get("campaign_id") or ""),
            _int_or_none(row.get("repetition")) or 0,
            str(row.get("scenario") or ""),
            str(row.get("policy") or ""),
            str(row.get("run_id") or ""),
        ),
    )


def _valid_flat_row(row: Mapping[str, Any]) -> bool:
    return (
        str(row.get("execution_status") or "").strip().lower() == "completed"
        and row.get("is_valid") is True
        and str(row.get("security_outcome") or "") in EVALUABLE_OUTCOMES
    )


def _finite_values(rows: Iterable[Mapping[str, Any]], field: str) -> List[float]:
    values = []
    for row in rows:
        value = _number_or_none(row.get(field))
        if value is not None:
            values.append(value)
    return values


def _mean_or_none(values: Iterable[Any]) -> Optional[float]:
    clean = [value for value in (_number_or_none(item) for item in values) if value is not None]
    return statistics.fmean(clean) if clean else None


def _common_value(rows: Sequence[Mapping[str, Any]], field: str) -> Tuple[Any, bool]:
    values = [row.get(field) for row in rows]
    serialized = {_canonical_json(value) for value in values}
    return (values[0] if len(serialized) == 1 and values else None, len(serialized) <= 1)


def student_t_summary(values: Iterable[Any]) -> Dict[str, Any]:
    """Return descriptive statistics and a two-sided 95% t interval."""
    clean = [
        value
        for value in (_number_or_none(item) for item in values)
        if value is not None
    ]
    mean = statistics.fmean(clean) if clean else None
    standard_deviation = statistics.stdev(clean) if len(clean) >= 2 else None
    standard_error = (
        standard_deviation / math.sqrt(len(clean))
        if standard_deviation is not None
        else None
    )
    # Two-sided 95% Student-t critical values.  For larger samples, a value
    # from the next smaller tabulated degrees of freedom is used.  Because the
    # t critical value decreases with df, this is conservative rather than the
    # anti-conservative normal approximation.
    critical_values = {
        1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
        6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
        11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
        16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
        21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
        26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
    }
    degrees_of_freedom = len(clean) - 1
    if degrees_of_freedom in critical_values:
        critical = critical_values[degrees_of_freedom]
        method = "student_t"
    elif degrees_of_freedom > 30:
        if degrees_of_freedom <= 40:
            critical = critical_values[30]
        elif degrees_of_freedom <= 60:
            critical = 2.021
        elif degrees_of_freedom <= 120:
            critical = 2.000
        else:
            critical = 1.980
        method = "student_t_conservative_table"
    else:
        critical = None
        method = None
    margin = (
        critical * standard_error
        if critical is not None and mean is not None and standard_error is not None
        else None
    )
    return {
        "n": len(clean),
        "mean": mean,
        "median": statistics.median(clean) if clean else None,
        "minimum": min(clean) if clean else None,
        "maximum": max(clean) if clean else None,
        "standard_deviation": standard_deviation,
        "standard_error": standard_error,
        "ci95_low": mean - margin if margin is not None else None,
        "ci95_high": mean + margin if margin is not None else None,
        "ci95_method": method if margin is not None else None,
    }


def _descriptive_row(metric: str, values: Sequence[float]) -> Dict[str, Any]:
    statistics_row = student_t_summary(values)
    base_method = statistics_row["ci95_method"]
    statistics_row["ci95_method"] = (
        "%s_on_block_means" % base_method if base_method else None
    )
    return {
        "population": "complete_fully_valid_sample_id_blocks",
        "metric": metric,
        "n_blocks": statistics_row.pop("n"),
        **statistics_row,
    }


def _wilson_percent(successes: int, total: int) -> Tuple[Optional[float], Optional[float]]:
    if total <= 0:
        return None, None
    z = 1.959963984540054
    proportion = float(successes) / float(total)
    denominator = 1.0 + z * z / total
    centre = (proportion + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(
        proportion * (1.0 - proportion) / total
        + z * z / (4.0 * total * total)
    ) / denominator
    return 100.0 * max(0.0, centre - margin), 100.0 * min(1.0, centre + margin)


def summarize_sample_blocks(
    runs_or_rows: Iterable[Mapping[str, Any]],
    campaign: Optional[Mapping[str, Any]] = None,
    expected_policies: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Describe data using randomized ``sample_id`` blocks as the unit.

    The primary metric and policy summaries include only complete blocks whose
    expected policy tasks are all valid.  Every excluded run remains available
    in ``invalid_run_rows`` and every incomplete/partially invalid block remains
    in ``block_rows``.
    """

    supplied = [dict(item) for item in runs_or_rows]
    if supplied and all("observed_result_json" in item for item in supplied):
        rows = sorted(supplied, key=_run_sort_key)
    else:
        rows = flatten_experiment_runs(supplied, campaign=campaign)
    expected = tuple(expected_policies or DEFAULT_EXPECTED_POLICIES)
    expected_set = set(expected)

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    display_ids: Dict[str, Optional[str]] = {}
    for index, row in enumerate(rows):
        sample_id = str(row.get("sample_id") or "").strip()
        key = sample_id or "__missing_sample_id__:%s:%s" % (
            row.get("task_id") or "task",
            index,
        )
        grouped[key].append(row)
        display_ids[key] = sample_id or None

    block_rows: List[Dict[str, Any]] = []
    fully_valid_groups: List[List[Dict[str, Any]]] = []
    invalid_run_rows: List[Dict[str, Any]] = []

    numeric_block_metrics = (
        "baseline_availability_rate",
        "during_availability_rate",
        "recovery_availability_rate",
        "attack_probe_success_percent",
        "achieved_rate_pps",
        "rate_achievement_percent",
        "process_cpu_p95_percent",
    )

    for key in sorted(grouped):
        block = sorted(grouped[key], key=_run_sort_key)
        policy_counts = Counter(str(row.get("policy") or "") for row in block)
        observed_policies = {item for item in policy_counts if item}
        duplicate_count = sum(max(0, count - 1) for count in policy_counts.values())
        valid_rows = [row for row in block if _valid_flat_row(row)]
        invalid_rows = [row for row in block if not _valid_flat_row(row)]
        complete = (
            bool(expected_set)
            and observed_policies == expected_set
            and duplicate_count == 0
            and len(block) == len(expected)
            and display_ids[key] is not None
        )
        scenario, scenario_ok = _common_value(block, "scenario")
        intensity, intensity_ok = _common_value(block, "intensity_level")
        repetition, repetition_ok = _common_value(block, "repetition")
        metadata_consistent = scenario_ok and intensity_ok and repetition_ok
        params_present = [row for row in block if row.get("sampled_parameters_present")]
        params_signatures = {row.get("sampled_parameters_json") for row in params_present}
        paired_parameters_consistent: Optional[bool]
        if not params_present:
            paired_parameters_consistent = None
        else:
            paired_parameters_consistent = (
                len(params_present) == len(block) and len(params_signatures) == 1
            )
        fully_valid = (
            complete
            and not invalid_rows
            and metadata_consistent
            and paired_parameters_consistent is True
        )
        if fully_valid:
            fully_valid_groups.append(block)

        for row in invalid_rows:
            invalid_run_rows.append(
                {field: row.get(field) for field in INVALID_RUN_FIELDNAMES}
            )

        successes = [
            100.0 * float(row["attack_probe_successes"]) / float(row["attack_probe_count"])
            for row in valid_rows
            if _number_or_none(row.get("attack_probe_successes")) is not None
            and _number_or_none(row.get("attack_probe_count")) is not None
            and float(row["attack_probe_count"]) > 0
        ]
        outcomes = Counter(str(row.get("security_outcome") or "unknown") for row in block)
        error_types = Counter(
            str(row.get("error_type") or row.get("execution_status") or "unspecified")
            for row in invalid_rows
        )
        block_row = {
            "sample_id": display_ids[key],
            "sample_id_missing": display_ids[key] is None,
            "scenario": scenario,
            "intensity_level": intensity,
            "repetition": repetition,
            "run_count": len(block),
            "expected_policy_count": len(expected),
            "observed_policy_count": len(observed_policies),
            "valid_run_count": len(valid_rows),
            "invalid_run_count": len(invalid_rows),
            "duplicate_policy_count": duplicate_count,
            "complete_block": complete,
            "fully_valid_block": fully_valid,
            "metadata_consistent": metadata_consistent,
            "paired_parameters_consistent": paired_parameters_consistent,
            "resisted_valid_run_count": sum(
                1 for row in valid_rows if row.get("security_outcome") in RESISTED_OUTCOMES
            ),
            "valid_resistance_percent": (
                100.0
                * sum(1 for row in valid_rows if row.get("security_outcome") in RESISTED_OUTCOMES)
                / len(valid_rows)
                if valid_rows
                else None
            ),
            "policies_json": _canonical_json(sorted(observed_policies)),
            "missing_policies_json": _canonical_json(sorted(expected_set - observed_policies)),
            "valid_policies_json": _canonical_json(sorted(str(row.get("policy") or "") for row in valid_rows)),
            "invalid_policies_json": _canonical_json(sorted(str(row.get("policy") or "") for row in invalid_rows)),
            "outcomes_json": _canonical_json(dict(sorted(outcomes.items()))),
            "error_types_json": _canonical_json(dict(sorted(error_types.items()))),
            "mean_baseline_availability_rate": _mean_or_none(row.get("baseline_availability_rate") for row in valid_rows),
            "mean_during_availability_rate": _mean_or_none(row.get("during_availability_rate") for row in valid_rows),
            "mean_recovery_availability_rate": _mean_or_none(row.get("recovery_availability_rate") for row in valid_rows),
            "mean_attack_probe_success_percent": _mean_or_none(successes),
            "mean_achieved_rate_pps": _mean_or_none(row.get("achieved_rate_pps") for row in valid_rows),
            "mean_rate_achievement_percent": _mean_or_none(row.get("rate_achievement_percent") for row in valid_rows),
            "mean_process_cpu_p95_percent": _mean_or_none(row.get("process_cpu_p95_percent") for row in valid_rows),
        }
        block_rows.append({field: block_row.get(field) for field in BLOCK_FIELDNAMES})

    metric_rows: List[Dict[str, Any]] = []
    metric_fields = (
        "baseline_availability_rate",
        "during_availability_rate",
        "recovery_availability_rate",
        "achieved_rate_pps",
        "rate_achievement_percent",
        "packet_delivery_percent",
        "process_cpu_p95_percent",
    )
    for metric in metric_fields:
        block_values = []
        for block in fully_valid_groups:
            mean = _mean_or_none(row.get(metric) for row in block)
            if mean is not None:
                block_values.append(mean)
        metric_rows.append(_descriptive_row(metric, block_values))

    attack_success_block_values = []
    for block in fully_valid_groups:
        values = [
            100.0 * float(row["attack_probe_successes"]) / float(row["attack_probe_count"])
            for row in block
            if _number_or_none(row.get("attack_probe_successes")) is not None
            and _number_or_none(row.get("attack_probe_count")) is not None
            and float(row["attack_probe_count"]) > 0
        ]
        mean = _mean_or_none(values)
        if mean is not None:
            attack_success_block_values.append(mean)
    metric_rows.append(_descriptive_row("attack_probe_success_percent", attack_success_block_values))

    policy_rows: List[Dict[str, Any]] = []
    policy_metric_rows: List[Dict[str, Any]] = []
    for policy in expected:
        observations = [
            next(row for row in block if row.get("policy") == policy)
            for block in fully_valid_groups
        ]
        outcomes = Counter(str(row.get("security_outcome") or "unknown") for row in observations)
        attack_successes = [
            100.0 * float(row["attack_probe_successes"]) / float(row["attack_probe_count"])
            for row in observations
            if _number_or_none(row.get("attack_probe_successes")) is not None
            and _number_or_none(row.get("attack_probe_count")) is not None
            and float(row["attack_probe_count"]) > 0
        ]
        resisted = sum(1 for row in observations if row.get("security_outcome") in RESISTED_OUTCOMES)
        resistance_low, resistance_high = _wilson_percent(resisted, len(observations))
        policy_rows.append(
            {
                "population": "complete_fully_valid_sample_id_blocks",
                "policy": policy,
                "n_blocks": len(observations),
                "resisted_blocks": resisted,
                "resistance_percent": 100.0 * resisted / len(observations) if observations else None,
                "resistance_ci95_low": resistance_low,
                "resistance_ci95_high": resistance_high,
                "outcomes_json": _canonical_json(dict(sorted(outcomes.items()))),
                "mean_baseline_availability_rate": _mean_or_none(row.get("baseline_availability_rate") for row in observations),
                "mean_during_availability_rate": _mean_or_none(row.get("during_availability_rate") for row in observations),
                "mean_recovery_availability_rate": _mean_or_none(row.get("recovery_availability_rate") for row in observations),
                "mean_attack_probe_success_percent": _mean_or_none(attack_successes),
                "mean_achieved_rate_pps": _mean_or_none(row.get("achieved_rate_pps") for row in observations),
                "mean_rate_achievement_percent": _mean_or_none(row.get("rate_achievement_percent") for row in observations),
                "mean_process_cpu_p95_percent": _mean_or_none(row.get("process_cpu_p95_percent") for row in observations),
            }
        )
        for metric in metric_fields:
            values = _finite_values(observations, metric)
            descriptive = _descriptive_row(metric, values)
            descriptive["policy"] = policy
            policy_metric_rows.append(descriptive)
        policy_attack_successes = [
            100.0 * float(row["attack_probe_successes"]) / float(row["attack_probe_count"])
            for row in observations
            if _number_or_none(row.get("attack_probe_successes")) is not None
            and _number_or_none(row.get("attack_probe_count")) is not None
            and float(row["attack_probe_count"]) > 0
        ]
        descriptive = _descriptive_row(
            "attack_probe_success_percent", policy_attack_successes
        )
        descriptive["policy"] = policy
        policy_metric_rows.append(descriptive)

    invalid_counts = Counter(
        str(row.get("error_type") or row.get("execution_status") or "unspecified")
        for row in invalid_run_rows
    )
    return {
        "unit": "sample_id",
        "primary_population": "complete_fully_valid_sample_id_blocks",
        "expected_policies": list(expected),
        "total_blocks": len(block_rows),
        "complete_blocks": sum(1 for row in block_rows if row["complete_block"]),
        "fully_valid_blocks": sum(1 for row in block_rows if row["fully_valid_block"]),
        "incomplete_blocks": sum(1 for row in block_rows if not row["complete_block"]),
        "blocks_with_invalid_runs": sum(1 for row in block_rows if row["invalid_run_count"]),
        "blocks_with_inconsistent_metadata": sum(
            1 for row in block_rows if not row["metadata_consistent"]
        ),
        "blocks_with_inconsistent_parameters": sum(
            1 for row in block_rows
            if row["paired_parameters_consistent"] is not True
        ),
        "valid_runs": sum(1 for row in rows if _valid_flat_row(row)),
        "invalid_runs": len(invalid_run_rows),
        "invalid_runs_by_error_type": dict(sorted(invalid_counts.items())),
        "block_rows": block_rows,
        "metric_rows": metric_rows,
        "policy_rows": policy_rows,
        "policy_metric_rows": policy_metric_rows,
        "invalid_run_rows": sorted(invalid_run_rows, key=_run_sort_key),
    }


def _valid_sha256(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _checksum_status(declared: Any, computed: Any, presence: str) -> str:
    if presence == "missing":
        return "missing"
    if not _valid_sha256(declared) or not _valid_sha256(computed):
        return "unverified"
    return "verified" if hmac.compare_digest(str(declared).lower(), str(computed).lower()) else "mismatch"


def _resolve_path(value: Any, artifact_root: Optional[Path]) -> Optional[Path]:
    if value in (None, ""):
        return None
    text = str(value)
    if "://" in text:
        return None
    path = Path(text)
    if not path.is_absolute() and artifact_root is not None:
        path = Path(artifact_root) / path
    return path


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _manifest_inventory_row(
    campaign: Mapping[str, Any],
    manifest_path: Optional[Path],
    artifact_root: Optional[Path],
) -> Dict[str, Any]:
    manifest = _as_dict(campaign.get("manifest"))
    declared = _first_across(
        ((campaign, ("manifest_sha256",)), (manifest, ("manifest_sha256",)))
    )
    payload_digest = None
    payload_error = None
    if manifest:
        try:
            payload_digest = manifest_digest(manifest)
        except (TypeError, ValueError, OverflowError) as exc:
            payload_error = "manifest payload checksum failed: %s" % exc
    payload_status = _checksum_status(declared, payload_digest, "present" if manifest else "unverified")

    recorded_path = manifest_path or campaign.get("manifest_path")
    resolved = _resolve_path(recorded_path, artifact_root)
    presence = "unverified"
    computed = payload_digest
    checksum_source = "database_manifest_payload" if payload_digest else None
    file_sha256 = None
    actual_size = None
    error = payload_error
    if recorded_path not in (None, "") and resolved is None:
        error = "manifest path is not a local filesystem path"
    elif resolved is not None:
        if not resolved.exists():
            presence = "missing"
        elif not resolved.is_file():
            presence = "unverified"
            error = "manifest path is not a regular file"
        else:
            presence = "present"
            try:
                actual_size = resolved.stat().st_size
                file_sha256 = _sha256_file(resolved)
                file_payload = json.loads(resolved.read_text(encoding="utf-8"))
                if not isinstance(file_payload, dict):
                    raise ValueError("manifest JSON root is not an object")
                computed = manifest_digest(file_payload)
                checksum_source = "manifest_file_canonical_content"
            except (OSError, UnicodeError, ValueError, TypeError) as exc:
                computed = None
                checksum_source = None
                error = "manifest verification failed: %s" % exc

    public_recorded_path = _portable_export_path(recorded_path, artifact_root)
    public_resolved_path = _portable_export_path(resolved, artifact_root)
    row = {
        "artifact_type": "manifest",
        "artifact_id": campaign.get("campaign_id") or manifest.get("campaign_id") or "manifest",
        "campaign_id": campaign.get("campaign_id") or manifest.get("campaign_id"),
        "task_id": None,
        "enabled": True,
        "recorded_path": public_recorded_path,
        "resolved_path": public_resolved_path,
        "presence_status": presence,
        "declared_sha256": declared,
        "computed_sha256": computed,
        "checksum_status": _checksum_status(declared, computed, presence),
        "checksum_source": checksum_source,
        "checksum_scope": "canonical_manifest_content",
        "payload_computed_sha256": payload_digest,
        "payload_checksum_status": payload_status,
        "file_sha256": file_sha256,
        "declared_size_bytes": None,
        "actual_size_bytes": actual_size,
        "size_status": "unverified" if presence != "missing" else "missing",
        "error": error,
    }
    return {field: row.get(field) for field in INVENTORY_FIELDNAMES}


def _pcap_inventory_row(
    run: Mapping[str, Any],
    artifact_root: Optional[Path],
) -> Dict[str, Any]:
    record, _params, _observed, metrics, _resource, pcap = _run_components(run)
    enabled = _bool_or_none(_first_present(pcap, ("enabled", "capture_enabled")))
    recorded_path = _first_present(pcap, ("path", "file_path", "filename", "file"))
    declared = _first_present(pcap, ("sha256", "checksum_sha256", "checksum", "hash"))
    declared_size = _int_or_none(_first_present(pcap, ("size_bytes", "bytes", "size")))
    resolved = _resolve_path(recorded_path, artifact_root)
    presence = "unverified"
    computed = None
    actual_size = None
    error = None
    if recorded_path in (None, ""):
        if enabled is True:
            presence = "missing"
    elif resolved is None:
        error = "PCAP path is not a local filesystem path"
    elif not resolved.exists():
        presence = "missing"
    elif not resolved.is_file():
        error = "PCAP path is not a regular file"
    else:
        presence = "present"
        try:
            actual_size = resolved.stat().st_size
            computed = _sha256_file(resolved)
        except OSError as exc:
            presence = "unverified"
            error = "PCAP verification failed: %s" % exc

    if presence == "missing":
        size_status = "missing"
    elif presence != "present" or declared_size is None or actual_size is None:
        size_status = "unverified"
    else:
        size_status = "verified" if declared_size == actual_size else "mismatch"

    task_id = record.get("task_id") or metrics.get("task_id")
    public_recorded_path = _portable_export_path(recorded_path, artifact_root)
    public_resolved_path = _portable_export_path(resolved, artifact_root)
    row = {
        "artifact_type": "pcap",
        "artifact_id": task_id or public_recorded_path or "unidentified_pcap",
        "campaign_id": record.get("campaign_id") or metrics.get("campaign_id"),
        "task_id": task_id,
        "enabled": enabled,
        "recorded_path": public_recorded_path,
        "resolved_path": public_resolved_path,
        "presence_status": presence,
        "declared_sha256": declared,
        "computed_sha256": computed,
        "checksum_status": _checksum_status(declared, computed, presence),
        "checksum_source": "pcap_file_bytes" if computed else None,
        "checksum_scope": "file_bytes",
        "payload_computed_sha256": None,
        "payload_checksum_status": "unverified",
        "file_sha256": computed,
        "declared_size_bytes": declared_size,
        "actual_size_bytes": actual_size,
        "size_status": size_status,
        "error": error,
    }
    return {field: row.get(field) for field in INVENTORY_FIELDNAMES}


def compute_checksum_inventory(
    campaign: Mapping[str, Any],
    runs: Iterable[Mapping[str, Any]],
    manifest_path: Optional[Path] = None,
    artifact_root: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Inventory the manifest and every per-task PCAP with explicit statuses."""

    root = Path(artifact_root) if artifact_root is not None else None
    rows = [_manifest_inventory_row(campaign, manifest_path, root)]
    rows.extend(_pcap_inventory_row(run, root) for run in runs)
    return sorted(
        rows,
        key=lambda row: (
            0 if row.get("artifact_type") == "manifest" else 1,
            str(row.get("task_id") or ""),
            str(row.get("recorded_path") or ""),
        ),
    )


def _csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (Mapping, list, tuple, set, frozenset)):
        return _canonical_json(value)
    return value


def _csv_text(rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=list(fieldnames),
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({field: _csv_value(row.get(field)) for field in fieldnames})
    return output.getvalue()


def _atomic_write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    return path


def _export_evidence_package_unlocked(
    campaign: Mapping[str, Any],
    runs: Iterable[Mapping[str, Any]],
    target_dir: Path,
    manifest_path: Optional[Path] = None,
    artifact_root: Optional[Path] = None,
    expected_policies: Optional[Sequence[str]] = None,
) -> Dict[str, Path]:
    """Write deterministic raw/flat/block/checksum JSON and CSV evidence.

    The return mapping is designed for direct use by ``scientific_report`` or
    another report root.  No timestamp is added, so identical inputs and local
    artifact contents produce byte-identical exports.
    """

    destination = Path(target_dir)
    public_path_root = Path(artifact_root) if artifact_root is not None else None
    run_records = [dict(run) for run in runs]
    sorted_raw_runs = sorted(run_records, key=_run_sort_key)
    flat_rows = [
        _publicize_flat_row_paths(row, public_path_root)
        for row in flatten_experiment_runs(run_records, campaign=campaign)
    ]
    resource_sample_rows = flatten_resource_samples(run_records, campaign=campaign)
    probe_sample_rows = flatten_probe_samples(run_records, campaign=campaign)
    authentication_rows = [
        _publicize_flat_row_paths(row, public_path_root)
        for row in flatten_authentication_observations(campaign)
    ]
    block_summary = summarize_sample_blocks(
        flat_rows,
        campaign=campaign,
        expected_policies=expected_policies,
    )
    inventory = compute_checksum_inventory(
        campaign,
        run_records,
        manifest_path=manifest_path,
        artifact_root=artifact_root,
    )

    public_campaign = dict(campaign)
    public_campaign.pop("_report_evidence_integrity_valid", None)
    canonical_manifest = _as_dict(public_campaign.pop("manifest", None))
    # Authentication rows have a deliberately narrower privacy contract below.
    # Do not duplicate unconstrained database rows (which may contain username)
    # inside the general raw-metrics document.
    public_campaign.pop("authentication_runs", None)
    normalized_campaign = normalize_large_seeds(
        _publicize_local_paths(
            _sanitize_for_export(public_campaign),
            public_path_root,
        )
    )
    if canonical_manifest:
        # A canonical manifest is cryptographic evidence.  Its JSON value
        # types must remain unchanged or the stored manifest digest no longer
        # verifies.  Summary/table seed fields are normalized separately.
        normalized_campaign["manifest"] = canonical_manifest
    raw_payload = {
        "export_schema_version": EXPORT_SCHEMA_VERSION,
        "campaign": normalized_campaign,
        "runs": normalize_large_seeds(
            _publicize_local_paths(
                _sanitize_for_export(sorted_raw_runs),
                public_path_root,
            )
        ),
    }
    task_payload = {
        "export_schema_version": EXPORT_SCHEMA_VERSION,
        "fieldnames": list(RUN_FIELDNAMES),
        "rows": flat_rows,
    }
    inventory_payload = {
        "export_schema_version": EXPORT_SCHEMA_VERSION,
        "statuses": {
            "presence": ["present", "missing", "unverified"],
            "checksum": ["verified", "mismatch", "missing", "unverified"],
        },
        "rows": inventory,
    }

    paths = {
        "raw_metrics_json": destination / "raw_metrics.json",
        "task_evidence_json": destination / "task_evidence.json",
        "task_evidence_csv": destination / "task_evidence.csv",
        "block_summary_json": destination / "block_summary.json",
        "block_summary_csv": destination / "block_summary.csv",
        "block_metric_summary_csv": destination / "block_metric_summary.csv",
        "policy_block_summary_csv": destination / "policy_block_summary.csv",
        "policy_metric_summary_csv": destination / "policy_metric_summary.csv",
        "invalid_runs_csv": destination / "invalid_runs.csv",
        "resource_samples_csv": destination / "resource_samples.csv",
        "probe_samples_csv": destination / "probe_samples.csv",
        "authentication_observations_json": destination / "authentication_observations.json",
        "authentication_observations_csv": destination / "authentication_observations.csv",
        "checksum_inventory_json": destination / "checksum_inventory.json",
        "checksum_inventory_csv": destination / "checksum_inventory.csv",
    }
    _atomic_write(paths["raw_metrics_json"], _pretty_json_exact(raw_payload))
    _atomic_write(paths["task_evidence_json"], _pretty_json(task_payload))
    _atomic_write(paths["task_evidence_csv"], _csv_text(flat_rows, RUN_FIELDNAMES))
    _atomic_write(paths["block_summary_json"], _pretty_json(block_summary))
    _atomic_write(
        paths["block_summary_csv"],
        _csv_text(block_summary["block_rows"], BLOCK_FIELDNAMES),
    )
    _atomic_write(
        paths["block_metric_summary_csv"],
        _csv_text(block_summary["metric_rows"], METRIC_SUMMARY_FIELDNAMES),
    )
    _atomic_write(
        paths["policy_block_summary_csv"],
        _csv_text(block_summary["policy_rows"], POLICY_SUMMARY_FIELDNAMES),
    )
    _atomic_write(
        paths["policy_metric_summary_csv"],
        _csv_text(
            block_summary["policy_metric_rows"],
            POLICY_METRIC_SUMMARY_FIELDNAMES,
        ),
    )
    _atomic_write(
        paths["invalid_runs_csv"],
        _csv_text(block_summary["invalid_run_rows"], INVALID_RUN_FIELDNAMES),
    )
    _atomic_write(
        paths["resource_samples_csv"],
        _csv_text(resource_sample_rows, RESOURCE_SAMPLE_FIELDNAMES),
    )
    _atomic_write(
        paths["probe_samples_csv"],
        _csv_text(probe_sample_rows, PROBE_SAMPLE_FIELDNAMES),
    )
    _atomic_write(
        paths["authentication_observations_json"],
        _pretty_json(
            {
                "export_schema_version": EXPORT_SCHEMA_VERSION,
                "fieldnames": list(AUTH_OBSERVATION_FIELDNAMES),
                "rows": authentication_rows,
            }
        ),
    )
    _atomic_write(
        paths["authentication_observations_csv"],
        _csv_text(authentication_rows, AUTH_OBSERVATION_FIELDNAMES),
    )
    _atomic_write(paths["checksum_inventory_json"], _pretty_json(inventory_payload))
    _atomic_write(
        paths["checksum_inventory_csv"],
        _csv_text(inventory, INVENTORY_FIELDNAMES),
    )
    return paths


def export_evidence_package(
    campaign: Mapping[str, Any],
    runs: Iterable[Mapping[str, Any]],
    target_dir: Path,
    manifest_path: Optional[Path] = None,
    artifact_root: Optional[Path] = None,
    expected_policies: Optional[Sequence[str]] = None,
) -> Dict[str, Path]:
    """Write one coherent evidence package, serialized per destination.

    A process-local lock and a Linux advisory lock prevent concurrent report
    workers from interleaving files belonging to different package snapshots.
    Individual files are also replaced atomically.
    """

    destination = Path(target_dir)
    destination.mkdir(parents=True, exist_ok=True)
    destination_key = str(destination.resolve())
    with _EXPORT_LOCKS_GUARD:
        process_lock = _EXPORT_LOCKS.setdefault(destination_key, threading.Lock())
    lock_name = "sdnmfa-evidence-%s.lock" % hashlib.sha256(
        destination_key.encode("utf-8")
    ).hexdigest()
    lock_path = Path(tempfile.gettempdir()) / lock_name
    with process_lock:
        with lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                return _export_evidence_package_unlocked(
                    campaign,
                    runs,
                    destination,
                    manifest_path=manifest_path,
                    artifact_root=artifact_root,
                    expected_policies=expected_policies,
                )
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


__all__ = [
    "AUTH_OBSERVATION_FIELDNAMES",
    "BLOCK_FIELDNAMES",
    "DEFAULT_EXPECTED_POLICIES",
    "EXPORT_SCHEMA_VERSION",
    "INVENTORY_FIELDNAMES",
    "PROBE_SAMPLE_FIELDNAMES",
    "POLICY_METRIC_SUMMARY_FIELDNAMES",
    "RESOURCE_SAMPLE_FIELDNAMES",
    "RUN_FIELDNAMES",
    "compute_checksum_inventory",
    "export_evidence_package",
    "flatten_authentication_observations",
    "flatten_experiment_run",
    "flatten_experiment_runs",
    "flatten_probe_samples",
    "flatten_resource_samples",
    "normalize_large_seeds",
    "summarize_sample_blocks",
    "student_t_summary",
]
