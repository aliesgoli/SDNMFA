from __future__ import annotations

import argparse
import hashlib
import json
import getpass
import logging
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, is_dataclass
from datetime import date, datetime, time as datetime_time, timezone
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency is checked by preflight
    def load_dotenv(*_args: Any, **_kwargs: Any) -> bool:
        return False


CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
project_root_text = str(PROJECT_ROOT)
while project_root_text in sys.path:
    sys.path.remove(project_root_text)
sys.path.insert(0, project_root_text)
load_dotenv(PROJECT_ROOT / ".env")

from database.db_config import close_all_connections, get_db_connection, release_db_connection
from attacks.attack_manager import AttackManager, AttackConfig
from attacks.base_attack import AttackResult
from security.mfa_manager import authenticate_user, prepare_mfa_authentication
from config.experiment_protocol import (
    AUTHORIZATION_TTL_SECONDS,
    BINDING_ORDER,
    BINDING_SPECS,
    DEFAULT_BINDING_PROFILE,
    DEFAULT_REPETITIONS,
    DISPLAY_SCENARIO_ORDER,
    POLICY_SELECTION,
    POLICY_SPECS,
    PROTOCOL_ID,
    PROTECTED_HOST,
    PROTECTED_PORT,
    SCENARIO_SPECS,
)
from experiments.campaign import (
    CampaignManifest,
    CampaignTask,
    build_campaign,
    build_thesis_suite,
)
from experiments.synthetic_users import ExperimentUser, build_user_profiles, user_for_task
from security.simulated_biometric_v2 import simulated_probe
from experiments.metrics import PacketCapture, ResourceSampler
from experiments.storage import CampaignStore
from config.runtime_security import strong_secret_or_none
from utils.input_normalization import normalize_digits


LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_DIR / "mfa_controller.log", encoding="utf-8")
    ],
)
logger = logging.getLogger(__name__)


MN_INFO_PATH = "/tmp/sdnmfa_mn.json"
MAX_AUTH_ATTEMPTS = 3
POLICY_MAP = dict(POLICY_SELECTION)
POLICY_LABELS = {
    mode: str(spec["label"]) for mode, spec in POLICY_SPECS.items()
}
TTL_MAP = {
    mode: AUTHORIZATION_TTL_SECONDS for mode in POLICY_SPECS
}
PORT_BOUND_BINDINGS = {
    name for name, spec in BINDING_SPECS.items() if spec["need_port"]
}
MAC_BOUND_BINDINGS = {
    name for name, spec in BINDING_SPECS.items() if spec["need_mac"]
}
FLOOD_TYPES = {"dos_udp_flood", "ddos_udp_flood"}


ATTACK_DEFAULTS = {
    attack_type: {
        "description": str(spec["display_description"]),
    }
    for attack_type, spec in SCENARIO_SPECS.items()
}


def _ryu_request(
    path: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    timeout: float = 3.0,
) -> Tuple[bool, Dict[str, Any]]:
    api_token = strong_secret_or_none(os.getenv("CONTROLLER_API_TOKEN"))
    if api_token is None:
        return False, {"error": "controller_api_token_not_configured"}
    url = "http://127.0.0.1:8080%s" % path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-SDNMFA-Token": api_token,
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8").strip()
            parsed = json.loads(body) if body else {}
            return bool(parsed.get("ok", True)), parsed
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8").strip()
            parsed = json.loads(body) if body else {}
        except Exception:
            parsed = {}
        parsed.setdefault("http_status", int(exc.code))
        return False, parsed
    except Exception as exc:
        return False, {"error": str(exc)}


def _load_mininet_ctx() -> Dict[str, Any]:
    try:
        with open(MN_INFO_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _wait_for_sdn_ready(
    mn: Optional[Dict[str, Any]] = None,
    timeout_s: float = 30.0,
) -> Tuple[bool, Dict[str, Any]]:
    mn = mn or {}
    expected_datapaths = max(1, int(mn.get("switch_count") or 1))
    active_link_count = mn.get("expected_active_switch_link_count")
    if active_link_count is None:
        active_link_count = mn.get("switch_link_count") or 0
    expected_transit_endpoints = max(0, int(active_link_count) * 2)
    deadline = time.monotonic() + timeout_s
    last_status: Dict[str, Any] = {}
    while time.monotonic() < deadline:
        ok, status = _ryu_request("/sdnmfa/status", "GET", timeout=2.0)
        last_status = status
        datapaths = status.get("datapaths") if isinstance(status, dict) else []
        transit = status.get("inter_switch_ports") if isinstance(status, dict) else []
        if (
            ok
            and isinstance(datapaths, list)
            and len(datapaths) >= expected_datapaths
            and isinstance(transit, list)
            and len(transit) >= expected_transit_endpoints
        ):
            return True, status
        time.sleep(0.25)
    return False, last_status


def _build_authorization_payload(
    mn: Dict[str, Any],
    mfa_mode: str,
    binding_profile: str = DEFAULT_BINDING_PROFILE,
    run_id: Optional[str] = None,
    attempt_id: Optional[str] = None,
) -> Dict[str, Any]:
    h1 = mn.get("h1") if isinstance(mn, dict) else None
    if not isinstance(h1, dict):
        raise RuntimeError("h1 is missing from %s" % MN_INFO_PATH)
    src_ip = str(h1.get("ip") or "").strip()
    src_mac = str(h1.get("mac") or "").lower().strip()
    in_port = h1.get("in_port")
    ingress_dpid = h1.get("switch_dpid")
    if not src_ip:
        raise RuntimeError("h1 IP address is missing from the Mininet context")
    if binding_profile not in BINDING_SPECS:
        raise RuntimeError("Unsupported network-binding profile: %s" % binding_profile)
    if binding_profile in MAC_BOUND_BINDINGS and not src_mac:
        raise RuntimeError("h1 MAC address is required for binding %s" % binding_profile)
    if binding_profile in PORT_BOUND_BINDINGS and (in_port is None or ingress_dpid is None):
        raise RuntimeError(
            "h1 ingress DPID/port is required for binding %s; restart topology.py from this package"
            % binding_profile
        )
    payload = {
        "src_ip": src_ip,
        "src_mac": src_mac or None,
        "mode": mfa_mode,
        "binding_profile": binding_profile,
        "ttl": AUTHORIZATION_TTL_SECONDS,
        "ingress_dpid": int(ingress_dpid) if ingress_dpid is not None else None,
        "in_port": int(in_port) if in_port is not None else None,
    }
    if run_id is not None:
        payload["run_id"] = str(run_id)
    if attempt_id is not None:
        payload["attempt_id"] = str(attempt_id)
    return payload


def _authorize_user(
    mn: Dict[str, Any],
    mfa_mode: str,
    binding_profile: str = DEFAULT_BINDING_PROFILE,
    run_id: Optional[str] = None,
    attempt_id: Optional[str] = None,
) -> Dict[str, Any]:
    if run_id is None or attempt_id is None:
        raise ValueError("run_id and attempt_id are required for network authorization")
    try:
        run_id = str(uuid.UUID(str(run_id)))
        attempt_id = str(uuid.UUID(str(attempt_id)))
    except (ValueError, AttributeError, TypeError):
        raise ValueError("run_id and attempt_id must be valid UUIDs")
    request_payload = _build_authorization_payload(
        mn,
        mfa_mode,
        binding_profile,
        run_id=run_id,
        attempt_id=attempt_id,
    )
    ok, response = _ryu_request(
        "/sdnmfa/authorize", "POST", request_payload, timeout=3.0
    )
    if not ok or not response.get("authorized"):
        raise RuntimeError(
            "Ryu authorization failed: %s"
            % (response.get("error") or response)
        )
    if str(response.get("src_ip")) != request_payload["src_ip"]:
        raise RuntimeError("Ryu returned an authorization for an unexpected IP")
    if str(response.get("mode")) != mfa_mode:
        raise RuntimeError("Ryu returned an authorization for an unexpected policy")
    for identifier in ("run_id", "attempt_id"):
        if request_payload.get(identifier) is not None and str(
            response.get(identifier) or ""
        ) != str(request_payload[identifier]):
            raise RuntimeError(
                "Ryu returned an authorization with an unexpected %s" % identifier
            )
    if str(response.get("binding_profile")) != binding_profile:
        raise RuntimeError("Ryu returned an authorization for an unexpected binding profile")
    try:
        response_ttl = int(response.get("ttl"))
        authorized_at = float(response.get("authorized_at"))
        expires_at = float(response.get("exp"))
    except (TypeError, ValueError):
        raise RuntimeError("Ryu returned an incomplete authorization window")
    if response_ttl != int(request_payload["ttl"]):
        raise RuntimeError("Ryu returned an unexpected authorization TTL")
    if expires_at <= authorized_at or abs((expires_at - authorized_at) - response_ttl) > 1.0:
        raise RuntimeError("Ryu returned an inconsistent authorization window")
    if expires_at <= time.time():
        raise RuntimeError("Ryu returned an already-expired authorization")
    if binding_profile in MAC_BOUND_BINDINGS and str(response.get("src_mac") or "").lower() != str(
        request_payload["src_mac"]
    ).lower():
        raise RuntimeError("Ryu returned an authorization for an unexpected MAC")
    if binding_profile in PORT_BOUND_BINDINGS:
        try:
            response_in_port = int(response.get("in_port"))
            response_dpid = int(response.get("ingress_dpid"))
        except (TypeError, ValueError):
            raise RuntimeError("Ryu returned an incomplete ingress location")
        if response_in_port != int(request_payload["in_port"]):
            raise RuntimeError("Ryu returned an unexpected ingress port")
        if response_dpid != int(request_payload["ingress_dpid"]):
            raise RuntimeError("Ryu returned an unexpected ingress DPID")
    response["request"] = request_payload
    return response


def _epoch_datetime(value: Any) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


class MFAController:
    def __init__(self):
        self.attack_manager = AttackManager()
        self.last_biometric_sample: Optional[str] = None

    def _to_jsonable(self, obj: Any) -> Any:
        if obj is None or isinstance(obj, (str, int, float, bool)):
            return obj
        if isinstance(obj, (bytes, bytearray)):
            return obj.decode("utf-8", errors="replace")
        if isinstance(obj, (datetime, date, datetime_time)):
            return obj.isoformat()
        if is_dataclass(obj):
            return {key: self._to_jsonable(value) for key, value in asdict(obj).items()}
        if isinstance(obj, dict):
            return {str(key): self._to_jsonable(value) for key, value in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [self._to_jsonable(value) for value in obj]
        if hasattr(obj, "__dict__"):
            return self._to_jsonable(vars(obj))
        return str(obj)

    def _safe_json(self, obj: Any) -> Any:
        cleaned = self._to_jsonable(obj)
        json.dumps(cleaned, ensure_ascii=False)
        return cleaned

    def execute_attack(
        self,
        username: str,
        attack_type: str,
        target_host: str,
        target_port: int,
        duration_s: int,
        rate_pps: int,
        threads: int,
        payload_size_bytes: Optional[int],
        mfa_mode: str,
        run_id: str,
        attempt_id: str,
        authorization_context: Dict[str, Any],
        gateway_ip: Optional[str] = None,
        campaign_id: Optional[str] = None,
        task_id: Optional[str] = None,
        sample_id: Optional[str] = None,
        repetition: Optional[int] = None,
        intensity_level: Optional[str] = None,
        binding_profile: str = DEFAULT_BINDING_PROFILE,
        topology_id: Optional[str] = None,
        request_count: Optional[int] = None,
        source_count: Optional[int] = None,
    ) -> AttackResult:
        config = AttackConfig(
            username=username,
            target_host=target_host,
            target_port=target_port,
            duration_s=duration_s,
            rate_pps=rate_pps,
            threads=threads,
            payload_size_bytes=payload_size_bytes,
            mfa_mode=mfa_mode,
            attack_type=attack_type,
            gateway_ip=gateway_ip,
            run_id=run_id,
            attempt_id=attempt_id,
            authorization_context=authorization_context,
            campaign_id=campaign_id,
            task_id=task_id,
            sample_id=sample_id,
            repetition=repetition,
            intensity_level=intensity_level,
            binding_profile=binding_profile,
            topology_id=topology_id,
            request_count=request_count,
            source_count=source_count,
        )
        attack_params = {
            "protocol_id": PROTOCOL_ID,
            "attack_type": attack_type,
            "target_host": target_host,
            "target_port": target_port,
            "duration_s": duration_s,
            "rate_pps": rate_pps,
            "threads": threads,
            "payload_size_bytes": payload_size_bytes,
            "mfa_mode": mfa_mode,
            "gateway_ip": gateway_ip,
            "run_id": run_id,
            "attempt_id": attempt_id,
            "authorization": authorization_context,
            "campaign_id": campaign_id,
            "task_id": task_id,
            "sample_id": sample_id,
            "repetition": repetition,
            "intensity_level": intensity_level,
            "binding_profile": binding_profile,
            "topology_id": topology_id,
            "request_count": request_count,
            "source_count": source_count,
        }
        start_ts = datetime.now(timezone.utc)
        print("\n⚡ Starting validated scenario: %s" % attack_type)
        print("🎯 Isolated target: %s:%s" % (target_host, target_port))
        result = self.attack_manager.execute_attack(config.attack_type, config)
        end_ts = datetime.now(timezone.utc)
        try:
            self._log_attack_attempt(
                username=username,
                mfa_mode=mfa_mode,
                attack_type=attack_type,
                target_host=target_host,
                target_port=target_port,
                duration_s=duration_s,
                rate_pps=rate_pps,
                threads=threads,
                attack_params=self._safe_json(attack_params),
                result=self._safe_json(result),
                start_ts=start_ts,
                end_ts=end_ts,
                run_id=run_id,
                attempt_id=attempt_id,
                authorization_context=authorization_context,
            )
        except Exception as exc:
            logger.exception("Could not persist attack log")
            print("WARNING: Attack completed, but its database log could not be written: %s" % exc)
        return result

    def _log_attack_attempt(
        self,
        *,
        username: str,
        mfa_mode: str,
        attack_type: str,
        target_host: str,
        target_port: int,
        duration_s: int,
        rate_pps: int,
        threads: int,
        attack_params: Dict[str, Any],
        result: Dict[str, Any],
        start_ts: datetime,
        end_ts: datetime,
        run_id: str,
        attempt_id: str,
        authorization_context: Dict[str, Any],
    ) -> None:
        conn = get_db_connection()
        if conn is None:
            raise RuntimeError("Database connection is not available")
        try:
            metrics = result.get("metrics") if isinstance(result, dict) else {}
            if not isinstance(metrics, dict):
                metrics = {}
            preflight = metrics.get("preflight") if isinstance(metrics.get("preflight"), dict) else {}
            postflight = metrics.get("postflight") if isinstance(metrics.get("postflight"), dict) else {}
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema='public' AND table_name='attack_logs'
                    """
                )
                available = {row[0] for row in cursor.fetchall()}
                values: Dict[str, Any] = {
                    "username": username,
                    "attack_type": attack_type,
                    "target_host": target_host,
                    "target_port": int(target_port),
                    "duration_seconds": int(duration_s),
                    "rate_pps": int(rate_pps),
                    "threads": int(threads),
                    "mfa_mode": mfa_mode,
                    "attack_params": json.dumps(attack_params, ensure_ascii=False),
                    "attack_result": json.dumps(result, ensure_ascii=False),
                    "packets_sent": metrics.get("packets_sent"),
                    "bytes_sent": metrics.get("bytes_sent"),
                    "actual_rate_pps": metrics.get("actual_rate_pps"),
                    "success": bool(result.get("success")),
                    "message": result.get("message"),
                    "start_time": start_ts,
                    "end_time": end_ts,
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                    "actual_mechanism": metrics.get("actual_mechanism"),
                    "is_valid": metrics.get("is_valid"),
                    "execution_status": metrics.get("execution_status"),
                    "security_outcome": metrics.get("security_outcome"),
                    "error_type": metrics.get("error_type"),
                    "authorized_at": _epoch_datetime(authorization_context.get("authorized_at")),
                    "authorization_expires_at": _epoch_datetime(authorization_context.get("exp")),
                    "authorization_in_port": authorization_context.get("in_port"),
                    "authorization_dpid": authorization_context.get("ingress_dpid"),
                    "legitimate_before": (
                        float(preflight.get("legitimate_rate", 0.0)) >= (2.0 / 3.0)
                        if preflight
                        else None
                    ),
                    "legitimate_after": postflight.get("valid") if postflight else None,
                    "campaign_id": metrics.get("campaign_id"),
                    "task_id": metrics.get("task_id"),
                    "sample_id": metrics.get("sample_id"),
                    "repetition": metrics.get("repetition"),
                    "intensity_level": metrics.get("intensity_level"),
                    "binding_profile": metrics.get("binding_profile"),
                    "topology_id": metrics.get("topology_id"),
                }
                columns = [name for name in values if name in available]
                if not columns:
                    raise RuntimeError("attack_logs has no compatible columns")
                placeholders = [
                    "%s::jsonb" if name in {"attack_params", "attack_result"} else "%s"
                    for name in columns
                ]
                query = "INSERT INTO attack_logs (%s) VALUES (%s)" % (
                    ", ".join(columns),
                    ", ".join(placeholders),
                )
                cursor.execute(query, [values[name] for name in columns])
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            release_db_connection(conn)

    def login(
        self,
        username: str,
        password: str,
        policy_key: str,
        run_id: str,
        attempt_id: str,
    ) -> Tuple[bool, str]:
        otp_code = None
        biometric_data = None
        if policy_key in {"2", "4"}:
            ready, message, _ = prepare_mfa_authentication(
                username,
                policy_key,
                run_id=run_id,
                attempt_id=attempt_id,
            )
            if not ready:
                print("Authentication unavailable: %s" % message)
                return False, "database_error" if "connection" in message.lower() else message
            # prepare_mfa_authentication intentionally generates, stores, and
            # delivers one fresh code. The returned code is not used here.
            otp_code = input("Enter the software OTP code: ").strip()
        if policy_key in {"3", "4"}:
            biometric_data = getpass.getpass(
                "Simulated biometric sample ('test' is allowed): "
            ).strip()
        success, message = authenticate_user(
            username=username,
            password=password,
            otp_code=otp_code,
            biometric_data=biometric_data,
            policy_key=policy_key,
            run_id=run_id,
            attempt_id=attempt_id,
        )
        if success:
            self.last_biometric_sample = biometric_data
            print("Authentication successful")
            return True, "success"
        if "connection" in str(message).lower():
            return False, "database_error"
        print("Authentication failed: %s" % message)
        return False, str(message)

    def run_campaign(
        self,
        *,
        manifest: CampaignManifest,
        username: str,
        password: str,
        operator_attempt_id: str,
        mn: Dict[str, Any],
        capture_pcap: bool = False,
        cooldown_seconds: float = 1.0,
        experiment_users: Optional[List[ExperimentUser]] = None,
        study_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute all paired policy tasks after one Full-MFA operator login."""
        if str(mn.get("topology_id") or "") != manifest.topology_id:
            raise RuntimeError(
                "Active topology is %s but the campaign requires %s"
                % (mn.get("topology_id") or "unknown", manifest.topology_id)
            )
        if capture_pcap and not PacketCapture.available():
            raise RuntimeError("Packet capture was requested, but mnexec/tcpdump is unavailable")

        evidence_root = PROJECT_ROOT / "evidence"
        manifest_path = evidence_root / "manifests" / (manifest.campaign_id + ".json")
        manifest.write_json(manifest_path)
        store = CampaignStore()
        store.register(manifest, study_id=study_id)
        completed = store.completed_task_ids(manifest.campaign_id)
        store.set_campaign_status(manifest.campaign_id, "running")

        summary = {
            "campaign_id": manifest.campaign_id,
            "manifest_path": str(manifest_path),
            "planned": len(manifest.tasks),
            "completed": 0,
            "skipped": 0,
            "valid": 0,
            "technical_errors": 0,
            "outcomes": {},
            "authentication_study": {"status": "separate_study"},
        }
        try:
            if not experiment_users and not self.last_biometric_sample:
                raise RuntimeError("The Full-MFA operator session has no simulated biometric sample")
            for index, task in enumerate(manifest.tasks, start=1):
                if task.task_id in completed:
                    summary["skipped"] += 1
                    continue
                print(
                    "\n[%s/%s] %s | %s | repetition %s | %s"
                    % (
                        index,
                        len(manifest.tasks),
                        task.intensity.upper(),
                        POLICY_LABELS[task.policy],
                        task.repetition,
                        task.topology_id,
                    )
                )
                reset_ok, reset_payload = _ryu_request("/sdnmfa/reset", "POST", {})
                if not reset_ok:
                    raise RuntimeError("Controller state reset failed: %s" % reset_payload)
                time.sleep(0.2)
                status_ok, status_payload = _ryu_request("/sdnmfa/status", "GET")
                try:
                    controller_pid = int(status_payload.get("controller_pid"))
                except (TypeError, ValueError):
                    controller_pid = 0
                if not status_ok or controller_pid <= 0:
                    raise RuntimeError(
                        "Controller process identity is unavailable: %s" % status_payload
                    )

                run_id = str(uuid.uuid4())
                task_attempt_id = str(uuid.uuid4())
                if experiment_users:
                    paired_user_key = "%s|%s|%s|%s" % (
                        task.topology_id,
                        task.scenario,
                        task.intensity,
                        task.repetition,
                    )
                    task_user = user_for_task(paired_user_key, experiment_users)
                    task_username = task_user.username
                    task_password = task_user.password
                    task_biometric = simulated_probe(
                        task_username,
                        probe_index=int.from_bytes(
                            hashlib.sha256(
                                paired_user_key.encode("utf-8")
                            ).digest()[:4],
                            "big",
                        ),
                        genuine=True,
                    )
                else:
                    task_username = username
                    task_password = password
                    task_biometric = self.last_biometric_sample
                policy_key = next(
                    key for key, mode in POLICY_MAP.items() if mode == task.policy
                )
                otp_code = None
                if "otp" in POLICY_SPECS[task.policy]["factor_keys"]:
                    from otp.otp_service import generate_otp, store_otp
                    otp_code = generate_otp()
                    stored, otp_message = store_otp(
                        task_username,
                        otp_code,
                        run_id=run_id,
                        attempt_id=task_attempt_id,
                    )
                    if not stored:
                        raise RuntimeError("Could not stage the task OTP: %s" % otp_message)
                task_authenticated, task_auth_message = authenticate_user(
                    username=task_username,
                    password=task_password,
                    otp_code=otp_code,
                    biometric_data=(
                        task_biometric
                        if "biometric" in POLICY_SPECS[task.policy]["factor_keys"]
                        else None
                    ),
                    policy_key=policy_key,
                    run_id=run_id,
                    attempt_id=task_attempt_id,
                )
                if not task_authenticated:
                    raise RuntimeError(
                        "Automated valid-control authentication failed for %s: %s"
                        % (task.policy, task_auth_message)
                    )
                store.start_task(
                    task,
                    run_id,
                    operator_attempt_id,
                    task_attempt_id,
                    task_username,
                )
                authorization = _authorize_user(
                    mn,
                    task.policy,
                    task.binding_profile,
                    run_id=run_id,
                    attempt_id=task_attempt_id,
                )

                pcap: Optional[PacketCapture] = None
                pcap_evidence: Dict[str, Any] = {"enabled": False}
                if capture_pcap:
                    pcap_path = (
                        evidence_root
                        / "pcap"
                        / manifest.campaign_id
                        / (task.task_id + ".pcap")
                    )
                    pcap = PacketCapture(
                        int(mn["h2"]["pid"]),
                        pcap_path,
                        str(task.parameters["target_host"]),
                        int(task.parameters["target_port"]),
                    ).start()

                sampler = ResourceSampler(
                    interval_seconds=0.2,
                    pid=controller_pid,
                    process_label="ryu_controller",
                ).start()
                result: Optional[AttackResult] = None
                try:
                    parameters = task.parameters
                    result = self.execute_attack(
                        username=task_username,
                        attack_type=task.scenario,
                        target_host=str(parameters["target_host"]),
                        target_port=int(parameters["target_port"]),
                        duration_s=int(parameters["duration_seconds"]),
                        rate_pps=int(parameters["rate_pps"]),
                        threads=int(parameters["worker_count"]),
                        payload_size_bytes=parameters.get("payload_size_bytes"),
                        mfa_mode=task.policy,
                        run_id=run_id,
                        attempt_id=task_attempt_id,
                        authorization_context=authorization,
                        campaign_id=task.campaign_id,
                        task_id=task.task_id,
                        sample_id=task.sample_id,
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
                    _ryu_request(
                        "/sdnmfa/revoke",
                        "POST",
                        {"src_ip": str(mn["h1"]["ip"])},
                    )

                if result is None:
                    raise RuntimeError("Scenario returned no result")
                result.metrics["resource_metrics"] = resource_metrics
                result.metrics["pcap_evidence"] = pcap_evidence
                serialized = self._safe_json(result)
                store.finish_task(
                    task.task_id,
                    serialized,
                    resource_metrics,
                    pcap_evidence,
                )
                summary["completed"] += 1
                outcome = str(result.metrics.get("security_outcome") or "not_evaluable")
                summary["outcomes"][outcome] = summary["outcomes"].get(outcome, 0) + 1
                if result.metrics.get("is_valid"):
                    summary["valid"] += 1
                else:
                    summary["technical_errors"] += 1
                print("Outcome: %s" % outcome)
                if cooldown_seconds > 0 and index < len(manifest.tasks):
                    time.sleep(min(10.0, float(cooldown_seconds)))

            remaining = len(manifest.tasks) - summary["skipped"] - summary["completed"]
            if remaining == 0:
                store.set_campaign_status(manifest.campaign_id, "completed")
            else:
                store.set_campaign_status(manifest.campaign_id, "interrupted")
            return summary
        except KeyboardInterrupt:
            store.set_campaign_status(manifest.campaign_id, "interrupted")
            raise
        except Exception:
            store.set_campaign_status(manifest.campaign_id, "failed")
            raise


class CLIInterface:
    @staticmethod
    def print_header(title: str) -> None:
        print("\n%s" % ("=" * 72))
        print((" %s " % title).center(72))
        print("=" * 72)

    @staticmethod
    def print_section(title: str) -> None:
        print("\n%s" % title)
        print("-" * 72)

    def get_authentication_parameters(self) -> Tuple[str, str, str]:
        self.print_header("Operator Authentication")
        print("One Full-MFA login authorizes this laboratory campaign.")
        username = input("Username: ").strip()
        # Whitespace is a valid password character and must be passed to the
        # verifier exactly as it was entered during enrollment.
        password = getpass.getpass("Password: ")
        return username, password, "4"

    def display_available_attacks(self, controller: MFAController) -> None:
        self.print_section("Available isolated scenarios")
        for key, (display_name, attack_key) in sorted(
            controller.attack_manager.get_available_attacks_display().items()
        ):
            print("%s. %s" % (key, display_name))
            description = ATTACK_DEFAULTS.get(attack_key, {}).get("description")
            if description:
                print("   %s" % description)

    def get_attack_choice(self, controller: MFAController) -> str:
        attack_info = controller.attack_manager.get_available_attacks_display()
        while True:
            raw = normalize_digits(input("\nSelect scenario number: ").strip())
            try:
                choice = int(raw)
            except ValueError:
                choice = -1
            if choice in attack_info:
                return attack_info[choice][1]
            print("Invalid scenario")

    def display_attack_results(self, result: AttackResult) -> None:
        self.print_header("Validated Scenario Result")
        metrics = result.metrics if isinstance(result.metrics, dict) else {}
        valid = bool(metrics.get("is_valid"))
        outcome = str(metrics.get("security_outcome") or "not_evaluable")
        if not valid:
            print("STATUS: TECHNICAL ERROR — EXCLUDED FROM SECURITY RATES")
            print("Error type: %s" % (metrics.get("error_type") or "unknown"))
        elif outcome == "attack_success":
            print("🔴 STATUS: ATTACK SUCCEEDED")
        elif outcome == "attack_blocked":
            print("🟢 STATUS: ATTACK BLOCKED")
        elif outcome == "availability_degraded":
            print("STATUS: SERVICE AVAILABILITY DEGRADED")
        elif outcome == "availability_preserved":
            print("STATUS: SERVICE AVAILABILITY PRESERVED")
        else:
            print("STATUS: NOT EVALUABLE")
        print("Message: %s" % result.message)
        for key, label in (
            ("actual_mechanism", "Actual mechanism"),
            ("packets_sent", "Packets sent"),
            ("bytes_sent", "Bytes sent"),
            ("actual_rate_pps", "Actual rate (pps)"),
            ("baseline_availability_rate", "Baseline availability"),
            ("during_availability_rate", "Availability during traffic"),
            ("recovery_availability_rate", "Recovery availability"),
        ):
            if metrics.get(key) is not None:
                print("%s: %s" % (label, metrics[key]))
        print("Result stored with run_id=%s" % (metrics.get("run_id") or "not available"))


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a paired, reproducible SDN-MFA experiment campaign"
    )
    scenario_group = parser.add_mutually_exclusive_group()
    scenario_group.add_argument(
        "--scenario", choices=list(SCENARIO_SPECS), help="Skip the scenario menu"
    )
    scenario_group.add_argument(
        "--all-scenarios",
        action="store_true",
        help="Run the six declared scenarios as one reproducible suite",
    )
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    binding_group = parser.add_mutually_exclusive_group()
    binding_group.add_argument(
        "--binding", choices=BINDING_ORDER, default=DEFAULT_BINDING_PROFILE
    )
    binding_group.add_argument(
        "--all-bindings", action="store_true",
        help="Cross all four network bindings with every selected scenario",
    )
    parser.add_argument("--seed", type=int, help="Integer random seed; generated and recorded when omitted")
    parser.add_argument("--capture-pcap", action="store_true", help="Capture per-task PCAP evidence")
    parser.add_argument("--cooldown", type=float, default=1.0, help="Seconds between tasks (0-10)")
    parser.add_argument("--yes", action="store_true", help="Start after validation without a confirmation prompt")
    parser.add_argument("--study-id", help="UUID of the registered thesis study")
    args = parser.parse_args(argv)
    if not 1 <= args.repetitions <= 30:
        parser.error("--repetitions must be between 1 and 30")
    if args.seed is not None and not 0 <= args.seed <= 2**63 - 1:
        parser.error("--seed must be between 0 and 2^63-1")
    if not 0.0 <= args.cooldown <= 10.0:
        parser.error("--cooldown must be between 0 and 10 seconds")
    if args.study_id is not None:
        try:
            args.study_id = str(uuid.UUID(args.study_id))
        except ValueError:
            parser.error("--study-id must be a UUID")
    return args


def main(argv=None) -> int:
    args = _parse_args(argv)
    mn: Dict[str, Any] = {}
    try:
        cli = CLIInterface()
        controller = MFAController()
        run_id = str(uuid.uuid4())
        successful_attempt_id: Optional[str] = None
        authenticated = False
        username = ""

        cli.print_header("SDN-MFA Scientific Experiment")
        print("Operator session ID: %s" % run_id)
        for attempt_number in range(1, MAX_AUTH_ATTEMPTS + 1):
            attempt_id = str(uuid.uuid4())
            username, password, policy = cli.get_authentication_parameters()
            success, error_code = controller.login(
                username,
                password,
                policy,
                run_id=run_id,
                attempt_id=attempt_id,
            )
            if success:
                authenticated = True
                successful_attempt_id = attempt_id
                break
            remaining = MAX_AUTH_ATTEMPTS - attempt_number
            if error_code == "database_error":
                print("Database connection failed; verify .env and PostgreSQL")
            if remaining:
                print("%s authentication attempt(s) remaining" % remaining)
        if not authenticated or successful_attempt_id is None:
            print("Access denied")
            return 1

        mn = _load_mininet_ctx()
        if not mn:
            raise RuntimeError("%s was not found; start config/topology.py first" % MN_INFO_PATH)
        ready, status = _wait_for_sdn_ready(mn)
        if not ready:
            raise RuntimeError(
                "Ryu has not discovered every switch/link declared by the active topology. "
                "Start it with: ryu-manager config/security_controller.py --observe-links. "
                "Last status: %s" % status
            )

        attack_types: List[str]
        if args.all_scenarios:
            attack_types = list(DISPLAY_SCENARIO_ORDER)
        elif args.scenario is not None:
            attack_types = [args.scenario]
        else:
            cli.display_available_attacks(controller)
            attack_types = [cli.get_attack_choice(controller)]
        seed = args.seed if args.seed is not None else time.time_ns() & (2**63 - 1)
        topology_id = str(mn.get("topology_id") or "")
        if not topology_id:
            raise RuntimeError("The Mininet context does not declare a topology_id")
        if args.all_bindings and args.all_scenarios:
            manifests = build_thesis_suite(
                topology_id=topology_id,
                base_seed=seed,
                repetitions=args.repetitions,
            )
        else:
            bindings = list(BINDING_ORDER) if args.all_bindings else [args.binding]
            manifests = [
                build_campaign(
                    attack_type,
                    seed=seed,
                    repetitions=args.repetitions,
                    topology_id=topology_id,
                    binding_profile=binding,
                )
                for binding in bindings
                for attack_type in attack_types
            ]
        estimated_scenario_seconds = sum(
            float(task.parameters["duration_seconds"])
            for manifest in manifests
            for task in manifest.tasks
        )
        cli.print_section(
            "Validated experiment suite" if len(manifests) > 1 else "Validated campaign"
        )
        print(
            "Scenarios: %s"
            % ", ".join(
                str(SCENARIO_SPECS[item.scenario]["display_name"])
                for item in manifests
            )
        )
        print("Topology: %s" % topology_id)
        print("Design: paired inputs with randomized policy order")
        print("Policies: 4 | intensity levels: 3 | repetitions: %s" % args.repetitions)
        print(
            "Campaigns: %s | tasks: %s | common random seed: %s"
            % (
                len(manifests),
                sum(len(item.tasks) for item in manifests),
                seed,
            )
        )
        print(
            "Network bindings: %s"
            % ", ".join(BINDING_SPECS[item]["label"] for item in (
                BINDING_ORDER if args.all_bindings else [args.binding]
            ))
        )
        print("Nominal traffic time: %.1f minutes (controls add runtime)" % (estimated_scenario_seconds / 60.0))
        if args.capture_pcap:
            print("Packet capture: enabled")
        if not args.yes:
            answer = input("Start the complete isolated campaign? (y/N): ").strip().lower()
            if answer not in {"y", "yes"}:
                print("Campaign cancelled before execution")
                return 0

        experiment_users = build_user_profiles(500)
        summaries = []
        for suite_index, manifest in enumerate(manifests, start=1):
            if len(manifests) > 1:
                cli.print_header(
                    "Suite campaign %s/%s: %s"
                    % (
                        suite_index,
                        len(manifests),
                        SCENARIO_SPECS[manifest.scenario]["display_name"],
                    )
                )
            summary = controller.run_campaign(
                manifest=manifest,
                username=username,
                password=password,
                operator_attempt_id=successful_attempt_id,
                mn=mn,
                capture_pcap=args.capture_pcap,
                cooldown_seconds=args.cooldown,
                experiment_users=experiment_users,
                study_id=args.study_id,
            )
            summaries.append(summary)
            print("Campaign ID: %s" % summary["campaign_id"])
            print(
                "Completed now: %s | resumed/skipped: %s"
                % (summary["completed"], summary["skipped"])
            )
            print(
                "Valid observations: %s | technical errors: %s"
                % (summary["valid"], summary["technical_errors"])
            )
            print(
                "Observed outcomes: %s"
                % json.dumps(summary["outcomes"], sort_keys=True)
            )
            print("Manifest: %s" % summary["manifest_path"])

        cli.print_header(
            "Experiment suite completed" if len(summaries) > 1 else "Campaign completed"
        )
        campaign_arguments = " ".join(
            "--campaign %s" % item["campaign_id"] for item in summaries
        )
        print(
            "English report: ./venv/bin/python analysis/thesis_report.py %s --strict"
            % campaign_arguments
        )
        print(
            "Persian report: ./venv/bin/python analysis/thesis_report.py %s --strict --P"
            % campaign_arguments
        )
        technical_errors = sum(int(item["technical_errors"]) for item in summaries)
        return 2 if technical_errors else 0
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        return 130
    except Exception as exc:
        logger.exception("Critical error")
        print("\nCritical error: %s" % exc)
        return 1
    finally:
        try:
            user_ip = mn.get("h1", {}).get("ip") if isinstance(mn, dict) else None
            if user_ip:
                _ryu_request("/sdnmfa/revoke", "POST", {"src_ip": user_ip})
        except Exception:
            pass
        try:
            close_all_connections()
        except Exception:
            logger.exception("Failed to close database connections")


if __name__ == "__main__":
    raise SystemExit(main())
