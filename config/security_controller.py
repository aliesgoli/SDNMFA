import json
import time
import threading
from typing import Dict, Any, Optional

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from webob import Response

SDNMFA_INSTANCE_NAME = "sdnmfa_api"
SENSITIVE_DST_IP = "10.0.0.2"
SENSITIVE_PORT = 18080

class SecurityController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]
        wsgi.register(SDNMFAController, {SDNMFA_INSTANCE_NAME: self})
        self.datapaths: Dict[int, Any] = {}
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self._sdnmfa_authorized: Dict[str, Dict[str, Any]] = {}
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

    def _is_authorized_sensitive(self, src_ip: str, src_mac: str, in_port: Optional[int]) -> bool:
        now = time.time()
        with self._lock:
            info = self._sdnmfa_authorized.get(src_ip)
            if not info:
                return False
            if info.get("exp", 0) <= now:
                return False
            mode = str(info.get("mode", "password_only"))
            need_mac = mode in ("password_otp", "password_biometric", "password_otp_biometric")
            need_port = mode in ("password_biometric", "password_otp_biometric")
            if need_mac:
                mac_ok = str(info.get("mac", "")).lower() == str(src_mac).lower()
                if not mac_ok:
                    return False
            if need_port:
                auth_port = info.get("in_port")
                if auth_port is None or in_port is None:
                    return False
                if int(auth_port) != int(in_port):
                    return False
        return True

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

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        dst = eth.dst
        src = eth.src

        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is not None:
            tcpp = pkt.get_protocol(tcp.tcp)
            if tcpp is not None:
                if str(ip4.dst) == SENSITIVE_DST_IP and int(tcpp.dst_port) == int(SENSITIVE_PORT):
                    if not self._is_authorized_sensitive(str(ip4.src), src, in_port):
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
            auth = {ip: {"exp": info.get("exp", 0), "mode": info.get("mode", ""), "mac": info.get("mac"), "in_port": info.get("in_port")} for ip, info in self._sdnmfa_authorized.items()}
        return {"ok": True, "now": now, "authorized": auth, "datapaths": list(self.datapaths.keys())}

    def sdnmfa_authorize(self, src_ip: str, mode: str, ttl: int, src_mac: Optional[str], in_port: Optional[int]) -> Dict[str, Any]:
        ttl = int(ttl)
        ttl = max(5, min(ttl, 3600))
        now = time.time()
        with self._lock:
            self._sdnmfa_authorized[src_ip] = {"exp": now + ttl, "mode": mode, "mac": src_mac, "in_port": in_port}
        return {"ok": True, "src_ip": src_ip, "mode": mode, "ttl": ttl, "exp": now + ttl}

    def sdnmfa_revoke(self, src_ip: str) -> Dict[str, Any]:
        with self._lock:
            self._sdnmfa_authorized.pop(src_ip, None)
        return {"ok": True, "src_ip": src_ip}

class SDNMFAController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SDNMFAController, self).__init__(req, link, data, **config)
        self.app: SecurityController = data[SDNMFA_INSTANCE_NAME]

    @route("sdnmfa", "/sdnmfa/status", methods=["GET"])
    def status(self, req, **kwargs):
        body = json.dumps(self.app.sdnmfa_status()).encode("utf-8")
        return Response(content_type="application/json", body=body)

    @route("sdnmfa", "/sdnmfa/authorize", methods=["POST"])
    def authorize(self, req, **kwargs):
        try:
            payload = req.json if req.body else {}
        except Exception:
            payload = {}
        src_ip = str(payload.get("src_ip", "")).strip()
        mode = str(payload.get("mode", "password_only")).strip()
        ttl = int(payload.get("ttl", 60))
        src_mac = payload.get("src_mac")
        if src_mac is not None:
            src_mac = str(src_mac).lower().strip()
        in_port = payload.get("in_port")
        in_port = int(in_port) if in_port is not None else None
        if not src_ip:
            return Response(status=400, content_type="application/json", body=json.dumps({"ok": False, "error": "src_ip required"}).encode("utf-8"))
        body = json.dumps(self.app.sdnmfa_authorize(src_ip, mode, ttl, src_mac, in_port)).encode("utf-8")
        return Response(content_type="application/json", body=body)

    @route("sdnmfa", "/sdnmfa/revoke", methods=["POST"])
    def revoke(self, req, **kwargs):
        try:
            payload = req.json if req.body else {}
        except Exception:
            payload = {}
        src_ip = str(payload.get("src_ip", "")).strip()
        if not src_ip:
            return Response(status=400, content_type="application/json", body=json.dumps({"ok": False, "error": "src_ip required"}).encode("utf-8"))
        body = json.dumps(self.app.sdnmfa_revoke(src_ip)).encode("utf-8")
        return Response(content_type="application/json", body=body)
