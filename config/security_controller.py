import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root_text = str(PROJECT_ROOT)
while project_root_text in sys.path:
    sys.path.remove(project_root_text)
sys.path.insert(0, project_root_text)

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency is checked by preflight
    def load_dotenv(*_args: Any, **_kwargs: Any) -> bool:
        return False

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from ryu.topology import event as topology_event
from webob import Response

from config.experiment_protocol import (
    AUTHORIZATION_TTL_SECONDS,
    AUTHORIZED_SOURCE_IP,
    BINDING_SPECS,
    DEFAULT_BINDING_PROFILE,
    IMPLEMENTATION_REVISION,
    POLICY_SPECS,
    PROTECTED_HOST,
    PROTECTED_PORT,
    PROTOCOL_ID,
)
from config.runtime_security import strong_secret_or_none
from database.db_config import get_db_connection, release_db_connection


load_dotenv(PROJECT_ROOT / ".env")

SDNMFA_INSTANCE_NAME = "sdnmfa_api"
SENSITIVE_DST_IP = PROTECTED_HOST
SENSITIVE_PORT = PROTECTED_PORT
VALID_MODES = set(POLICY_SPECS)
VALID_BINDINGS = {
    name: {
        "need_mac": bool(spec["need_mac"]),
        "need_port": bool(spec["need_port"]),
    }
    for name, spec in BINDING_SPECS.items()
}
POLICY_TTLS = {mode: AUTHORIZATION_TTL_SECONDS for mode in POLICY_SPECS}
MAC_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
API_TOKEN_HEADER = "X-SDNMFA-Token"
MAX_DENY_EVENTS = 1000


def _json_response(payload: Dict[str, Any], status: int = 200) -> Response:
    return Response(
        status=status,
        content_type="application/json",
        body=json.dumps(payload, sort_keys=True).encode("utf-8"),
    )


def _api_token_error(req) -> Optional[Response]:
    """Authenticate the local control-plane API with a constant-time check."""
    configured = strong_secret_or_none(os.getenv("CONTROLLER_API_TOKEN"))
    if configured is None:
        return _json_response(
            {"ok": False, "error": "controller_api_token_not_configured"},
            status=503,
        )
    headers = getattr(req, "headers", {}) or {}
    supplied = str(headers.get(API_TOKEN_HEADER) or "").strip()
    if not supplied or not secrets.compare_digest(
        configured.encode("utf-8"), supplied.encode("utf-8")
    ):
        return _json_response({"ok": False, "error": "unauthorized"}, status=401)
    return None


def _uuid_or_none(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


def _successful_mfa_attempt(run_id: str, attempt_id: str, mode: str) -> bool:
    """Confirm that the authorization request follows a completed MFA attempt."""
    connection = get_db_connection()
    if connection is None:
        return False
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM auth_logs
                    WHERE run_id = %s
                      AND attempt_id = %s
                      AND mfa_mode = %s
                      AND event_type = 'mfa_complete'
                      AND success IS TRUE
                )
                """,
                (run_id, attempt_id, mode),
            )
            row = cursor.fetchone()
        return bool(row and row[0])
    except Exception:
        connection.rollback()
        return False
    finally:
        release_db_connection(connection)

class SecurityController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]
        wsgi.register(SDNMFAController, {SDNMFA_INSTANCE_NAME: self})
        self.datapaths: Dict[int, Any] = {}
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.inter_switch_ports = set()
        self._sdnmfa_authorized: Dict[str, Dict[str, Any]] = {}
        self._deny_events = deque(maxlen=MAX_DENY_EVENTS)
        self._lock = threading.Lock()
        self._cleanup_thread = hub.spawn(self._expiry_worker)

    def _expiry_worker(self):
        while True:
            try:
                now = time.time()
                expired = []
                with self._lock:
                    for ip, info in list(self._sdnmfa_authorized.items()):
                        if info.get("exp", 0) <= now:
                            expired.append(ip)
                    for ip in expired:
                        self._sdnmfa_authorized.pop(ip, None)
            except Exception:
                pass
            hub.sleep(1.0)

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    def _del_flow(self, datapath, match, priority=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            priority=priority,
            match=match
        )
        datapath.send_msg(mod)

    def _install_base(self, datapath):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

        match_sensitive_tcp = parser.OFPMatch(eth_type=0x0800, ipv4_dst=SENSITIVE_DST_IP, ip_proto=6, tcp_dst=SENSITIVE_PORT)
        actions_sensitive = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 100, match_sensitive_tcp, actions_sensitive)

        # Keep protected-service replies on the controller path as well. The
        # IP+MAC scenario deliberately moves h1's identity to h3. Without
        # this rule, a previously learned reverse flow can keep sending the
        # reply to h1's old edge port until its idle timeout expires.
        match_sensitive_reply = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=SENSITIVE_DST_IP,
            ip_proto=6,
            tcp_src=SENSITIVE_PORT,
        )
        self._add_flow(datapath, 100, match_sensitive_reply, actions_sensitive)

    def _authorization_decision(
        self,
        src_ip: str,
        src_mac: str,
        dpid: int,
        in_port: Optional[int],
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        now = time.time()
        with self._lock:
            info = self._sdnmfa_authorized.get(src_ip)
            if not info:
                return False, "unauthorized_ip", None
            if info.get("exp", 0) <= now:
                self._sdnmfa_authorized.pop(src_ip, None)
                return False, "authorization_expired", dict(info)
            binding_profile = str(info.get("binding_profile", ""))
            requirements = VALID_BINDINGS.get(binding_profile)
            if requirements is None:
                return False, "unsupported_binding_profile", dict(info)
            need_mac = requirements["need_mac"]
            need_port = requirements["need_port"]
            if need_mac:
                mac_ok = str(info.get("mac", "")).lower() == str(src_mac).lower()
                if not mac_ok:
                    return False, "mac_mismatch", dict(info)

            # Port binding is evaluated on host-facing (edge) ports. A packet
            # that arrives through a discovered switch-to-switch port has
            # already passed the edge check on the preceding switch.
            is_transit = in_port is not None and (int(dpid), int(in_port)) in self.inter_switch_ports
            if need_port and not is_transit:
                auth_port = info.get("in_port")
                auth_dpid = info.get("ingress_dpid")
                if auth_port is None or auth_dpid is None or in_port is None:
                    return False, "ingress_location_missing", dict(info)
                if int(auth_dpid) != int(dpid) or int(auth_port) != int(in_port):
                    return False, "port_mismatch", dict(info)
            return True, "authorized", dict(info)

    def _is_authorized_sensitive(
        self,
        src_ip: str,
        src_mac: str,
        dpid: int,
        in_port: Optional[int],
    ) -> bool:
        allowed, _, _ = self._authorization_decision(src_ip, src_mac, dpid, in_port)
        return allowed

    def _record_deny(
        self,
        *,
        reason: str,
        src_ip: str,
        src_mac: str,
        dst_ip: str,
        dpid: int,
        in_port: Optional[int],
        tcp_src: Optional[int],
        tcp_dst: Optional[int],
        authorization: Optional[Dict[str, Any]],
    ) -> None:
        info = authorization or {}
        event = {
            "denied_at": time.time(),
            "reason": str(reason),
            "src_ip": str(src_ip),
            "src_mac": str(src_mac).lower(),
            "dst_ip": str(dst_ip),
            "dpid": int(dpid),
            "in_port": int(in_port) if in_port is not None else None,
            "tcp_src": int(tcp_src) if tcp_src is not None else None,
            "tcp_dst": int(tcp_dst) if tcp_dst is not None else None,
            "mode": info.get("mode"),
            "binding_profile": info.get("binding_profile"),
            "run_id": info.get("run_id"),
            "attempt_id": info.get("attempt_id"),
        }
        with self._lock:
            self._deny_events.append(event)

    @set_ev_cls(topology_event.EventLinkAdd)
    def _link_add_handler(self, ev):
        link = ev.link
        with self._lock:
            self.inter_switch_ports.add((int(link.src.dpid), int(link.src.port_no)))
            self.inter_switch_ports.add((int(link.dst.dpid), int(link.dst.port_no)))

    @set_ev_cls(topology_event.EventLinkDelete)
    def _link_delete_handler(self, ev):
        link = ev.link
        with self._lock:
            self.inter_switch_ports.discard((int(link.src.dpid), int(link.src.port_no)))
            self.inter_switch_ports.discard((int(link.dst.dpid), int(link.dst.port_no)))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        self._install_base(datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match.get("in_port", None)

        from ryu.lib.packet import packet
        from ryu.lib.packet import ethernet
        from ryu.lib.packet import ipv4
        from ryu.lib.packet import tcp
        from ryu.lib.packet import ether_types

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        if eth.ethertype in (
            ether_types.ETH_TYPE_LLDP,
            ether_types.ETH_TYPE_CFM,
        ):
            return

        dst = eth.dst
        src = eth.src

        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is not None:
            tcpp = pkt.get_protocol(tcp.tcp)
            if tcpp is not None:
                if str(ip4.dst) == SENSITIVE_DST_IP and int(tcpp.dst_port) == int(SENSITIVE_PORT):
                    allowed, reason, authorization = self._authorization_decision(
                        str(ip4.src), src, int(datapath.id), in_port
                    )
                    if not allowed:
                        self._record_deny(
                            reason=reason,
                            src_ip=str(ip4.src),
                            src_mac=src,
                            dst_ip=str(ip4.dst),
                            dpid=int(datapath.id),
                            in_port=in_port,
                            tcp_src=getattr(tcpp, "src_port", None),
                            tcp_dst=getattr(tcpp, "dst_port", None),
                            authorization=authorization,
                        )
                        return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        if in_port is not None:
            self.mac_to_port[dpid][src] = int(in_port)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, 10, match, actions, idle_timeout=30, hard_timeout=0)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def sdnmfa_status(self) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            auth = {
                ip: {
                    "authorized_at": info.get("authorized_at"),
                    "exp": info.get("exp", 0),
                    "expires_in": max(0.0, float(info.get("exp", 0)) - now),
                    "mode": info.get("mode", ""),
                    "binding_profile": info.get("binding_profile", ""),
                    "mac": info.get("mac"),
                    "ingress_dpid": info.get("ingress_dpid"),
                    "in_port": info.get("in_port"),
                    "run_id": info.get("run_id"),
                    "attempt_id": info.get("attempt_id"),
                }
                for ip, info in self._sdnmfa_authorized.items()
            }
            transit_ports = [
                {"dpid": dpid, "port": port}
                for dpid, port in sorted(self.inter_switch_ports)
            ]
            deny_event_count = len(self._deny_events)
        return {
            "ok": True,
            "protocol_id": PROTOCOL_ID,
            "implementation_revision": IMPLEMENTATION_REVISION,
            "binding_profiles": sorted(VALID_BINDINGS),
            "now": now,
            "controller_pid": os.getpid(),
            "authorized": auth,
            "datapaths": sorted(self.datapaths.keys()),
            "inter_switch_ports": transit_ports,
            "deny_event_count": deny_event_count,
        }

    def sdnmfa_deny_events(
        self,
        since: float = 0.0,
        limit: int = 100,
        src_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        since = max(0.0, float(since))
        limit = max(1, min(int(limit), 200))
        with self._lock:
            events = [
                dict(item)
                for item in self._deny_events
                if float(item.get("denied_at", 0.0)) >= since
                and (not src_ip or str(item.get("src_ip")) == str(src_ip))
            ]
        return {
            "ok": True,
            "since": since,
            "src_ip": src_ip,
            "count": len(events[-limit:]),
            "events": events[-limit:],
        }

    def sdnmfa_authorize(
        self,
        src_ip: str,
        mode: str,
        binding_profile: str,
        ttl: int,
        src_mac: Optional[str],
        ingress_dpid: Optional[int],
        in_port: Optional[int],
        run_id: Optional[str] = None,
        attempt_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        ttl = int(ttl)
        if mode not in VALID_MODES:
            raise ValueError("Unsupported authentication policy")
        if binding_profile not in VALID_BINDINGS:
            raise ValueError("Unsupported network-binding profile")
        if ttl != AUTHORIZATION_TTL_SECONDS:
            raise ValueError("Authorization TTL does not match the common protocol window")
        now = time.time()
        record = {
            "authorized_at": now,
            "exp": now + ttl,
            "mode": mode,
            "binding_profile": binding_profile,
            "mac": src_mac,
            "ingress_dpid": ingress_dpid,
            "in_port": in_port,
            "run_id": run_id,
            "attempt_id": attempt_id,
        }
        with self._lock:
            self._sdnmfa_authorized[src_ip] = record
        return {
            "ok": True,
            "authorized": True,
            "src_ip": src_ip,
            "src_mac": src_mac,
            "mode": mode,
            "binding_profile": binding_profile,
            "ttl": ttl,
            "authorized_at": now,
            "exp": now + ttl,
            "ingress_dpid": ingress_dpid,
            "in_port": in_port,
            "run_id": run_id,
            "attempt_id": attempt_id,
        }

    def sdnmfa_revoke(self, src_ip: str) -> Dict[str, Any]:
        with self._lock:
            self._sdnmfa_authorized.pop(src_ip, None)
        return {"ok": True, "src_ip": src_ip}

    def sdnmfa_reset(self) -> Dict[str, Any]:
        """Clear per-run state while retaining the protected-service rules."""
        with self._lock:
            self._sdnmfa_authorized.clear()
            self._deny_events.clear()
            self.mac_to_port.clear()
        for datapath in list(self.datapaths.values()):
            self._del_flow(datapath, datapath.ofproto_parser.OFPMatch())
            self._install_base(datapath)
        return {"ok": True, "reset_at": time.time(), "datapath_count": len(self.datapaths)}

    def sdnmfa_refresh_forwarding(self) -> Dict[str, Any]:
        """Discard stale learned paths without revoking the active session."""
        with self._lock:
            self.mac_to_port.clear()
        for datapath in list(self.datapaths.values()):
            self._del_flow(datapath, datapath.ofproto_parser.OFPMatch())
            self._install_base(datapath)
        return {
            "ok": True,
            "refreshed_at": time.time(),
            "datapath_count": len(self.datapaths),
        }

class SDNMFAController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SDNMFAController, self).__init__(req, link, data, **config)
        self.app: SecurityController = data[SDNMFA_INSTANCE_NAME]

    @route("sdnmfa", "/sdnmfa/status", methods=["GET"])
    def status(self, req, **kwargs):
        token_error = _api_token_error(req)
        if token_error is not None:
            return token_error
        return _json_response(self.app.sdnmfa_status())

    @route("sdnmfa", "/sdnmfa/deny-events", methods=["GET"])
    def deny_events(self, req, **kwargs):
        token_error = _api_token_error(req)
        if token_error is not None:
            return token_error
        params = getattr(req, "params", {}) or {}
        try:
            since = float(params.get("since", 0.0))
            limit = int(params.get("limit", 100))
            if since < 0.0 or not 1 <= limit <= 200:
                raise ValueError
        except (TypeError, ValueError):
            return _json_response({"ok": False, "error": "invalid_query"}, status=400)
        src_ip = str(params.get("src_ip") or "").strip() or None
        if src_ip is not None:
            try:
                if ipaddress.ip_address(src_ip).version != 4:
                    raise ValueError
            except ValueError:
                return _json_response({"ok": False, "error": "invalid_src_ip"}, status=400)
        return _json_response(
            self.app.sdnmfa_deny_events(since=since, limit=limit, src_ip=src_ip)
        )

    @route("sdnmfa", "/sdnmfa/authorize", methods=["POST"])
    def authorize(self, req, **kwargs):
        token_error = _api_token_error(req)
        if token_error is not None:
            return token_error
        try:
            payload = req.json if req.body else {}
        except Exception:
            return _json_response({"ok": False, "error": "invalid_json"}, status=400)
        if not isinstance(payload, dict):
            return _json_response({"ok": False, "error": "json_object_required"}, status=400)

        src_ip = str(payload.get("src_ip", "")).strip()
        mode = str(payload.get("mode", "")).strip()
        binding_profile = str(payload.get("binding_profile", "")).strip()
        if not src_ip:
            return _json_response({"ok": False, "error": "src_ip_required"}, status=400)
        try:
            parsed_ip = ipaddress.ip_address(src_ip)
            if parsed_ip.version != 4:
                raise ValueError("IPv4 required")
        except ValueError:
            return _json_response({"ok": False, "error": "invalid_src_ip"}, status=400)
        if src_ip != AUTHORIZED_SOURCE_IP:
            return _json_response(
                {"ok": False, "error": "source_not_authorizable_in_lab_protocol"},
                status=400,
            )
        if mode not in VALID_MODES:
            return _json_response(
                {"ok": False, "error": "unsupported_mode", "valid_modes": sorted(VALID_MODES)},
                status=400,
            )
        if binding_profile not in VALID_BINDINGS:
            return _json_response(
                {
                    "ok": False,
                    "error": "unsupported_binding_profile",
                    "valid_binding_profiles": sorted(VALID_BINDINGS),
                },
                status=400,
            )

        if "ttl" not in payload:
            return _json_response({"ok": False, "error": "ttl_required"}, status=400)
        try:
            ttl = int(payload["ttl"])
        except (TypeError, ValueError):
            return _json_response({"ok": False, "error": "invalid_ttl"}, status=400)
        if ttl != AUTHORIZATION_TTL_SECONDS:
            return _json_response(
                {
                    "ok": False,
                    "error": "ttl_does_not_match_protocol",
                    "expected_ttl": AUTHORIZATION_TTL_SECONDS,
                },
                status=400,
            )

        run_id = _uuid_or_none(payload.get("run_id"))
        attempt_id = _uuid_or_none(payload.get("attempt_id"))
        if run_id is None or attempt_id is None:
            return _json_response(
                {"ok": False, "error": "valid_run_id_and_attempt_id_required"},
                status=400,
            )
        if not _successful_mfa_attempt(run_id, attempt_id, mode):
            return _json_response(
                {"ok": False, "error": "authentication_attempt_not_verified"},
                status=403,
            )

        src_mac = payload.get("src_mac")
        if src_mac is not None:
            src_mac = str(src_mac).lower().strip()
            if not MAC_PATTERN.fullmatch(src_mac):
                return _json_response({"ok": False, "error": "invalid_src_mac"}, status=400)

        ingress_dpid = payload.get("ingress_dpid")
        in_port = payload.get("in_port")
        try:
            ingress_dpid = int(ingress_dpid) if ingress_dpid is not None else None
            in_port = int(in_port) if in_port is not None else None
            if ingress_dpid is not None and ingress_dpid <= 0:
                raise ValueError
            if in_port is not None and in_port <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return _json_response({"ok": False, "error": "invalid_ingress_location"}, status=400)

        requirements = VALID_BINDINGS[binding_profile]
        if requirements["need_mac"] and not src_mac:
            return _json_response({"ok": False, "error": "src_mac_required_for_mode"}, status=400)
        if requirements["need_port"] and (ingress_dpid is None or in_port is None):
            return _json_response(
                {"ok": False, "error": "ingress_dpid_and_in_port_required_for_mode"},
                status=400,
            )

        return _json_response(
            self.app.sdnmfa_authorize(
                src_ip,
                mode,
                binding_profile,
                ttl,
                src_mac,
                ingress_dpid,
                in_port,
                run_id,
                attempt_id,
            )
        )

    @route("sdnmfa", "/sdnmfa/reset", methods=["POST"])
    def reset(self, req, **kwargs):
        token_error = _api_token_error(req)
        if token_error is not None:
            return token_error
        return _json_response(self.app.sdnmfa_reset())

    @route("sdnmfa", "/sdnmfa/refresh-forwarding", methods=["POST"])
    def refresh_forwarding(self, req, **kwargs):
        token_error = _api_token_error(req)
        if token_error is not None:
            return token_error
        return _json_response(self.app.sdnmfa_refresh_forwarding())

    @route("sdnmfa", "/sdnmfa/revoke", methods=["POST"])
    def revoke(self, req, **kwargs):
        token_error = _api_token_error(req)
        if token_error is not None:
            return token_error
        try:
            payload = req.json if req.body else {}
        except Exception:
            payload = {}
        src_ip = str(payload.get("src_ip", "")).strip()
        if not src_ip:
            return _json_response({"ok": False, "error": "src_ip_required"}, status=400)
        try:
            if ipaddress.ip_address(src_ip).version != 4:
                raise ValueError
        except ValueError:
            return _json_response({"ok": False, "error": "invalid_src_ip"}, status=400)
        return _json_response(self.app.sdnmfa_revoke(src_ip))
