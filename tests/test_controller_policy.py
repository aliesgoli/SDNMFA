import importlib.util
import json
import os
import sys
import threading
import types
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import patch


def install_ryu_stubs():
    names = [
        "ryu", "ryu.base", "ryu.base.app_manager", "ryu.controller",
        "ryu.controller.ofp_event", "ryu.controller.handler", "ryu.ofproto",
        "ryu.ofproto.ofproto_v1_3", "ryu.lib", "ryu.lib.hub", "ryu.app",
        "ryu.lib.packet", "ryu.lib.packet.packet", "ryu.lib.packet.ethernet",
        "ryu.lib.packet.ipv4", "ryu.lib.packet.tcp",
        "ryu.lib.packet.ether_types", "ryu.app.wsgi", "ryu.topology",
        "ryu.topology.event", "webob",
    ]
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))

    class DummyRyuApp:
        def __init__(self, *args, **kwargs):
            pass

    class DummyWSGIApplication:
        def register(self, *args, **kwargs):
            pass

    class DummyControllerBase:
        def __init__(self, *args, **kwargs):
            pass

    class DummyResponse:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    def decorator(*args, **kwargs):
        def wrap(function):
            return function
        return wrap

    sys.modules["ryu.base.app_manager"].RyuApp = DummyRyuApp
    sys.modules["ryu.base"].app_manager = sys.modules["ryu.base.app_manager"]
    sys.modules["ryu.controller.handler"].CONFIG_DISPATCHER = "config"
    sys.modules["ryu.controller.handler"].MAIN_DISPATCHER = "main"
    sys.modules["ryu.controller.handler"].DEAD_DISPATCHER = "dead"
    sys.modules["ryu.controller.handler"].set_ev_cls = decorator
    sys.modules["ryu.controller"].ofp_event = sys.modules["ryu.controller.ofp_event"]
    for event in ("EventOFPStateChange", "EventOFPSwitchFeatures", "EventOFPPacketIn"):
        setattr(sys.modules["ryu.controller.ofp_event"], event, type(event, (), {}))
    sys.modules["ryu.ofproto.ofproto_v1_3"].OFP_VERSION = 4
    sys.modules["ryu.ofproto"].ofproto_v1_3 = sys.modules["ryu.ofproto.ofproto_v1_3"]
    sys.modules["ryu.lib.hub"].spawn = lambda *args, **kwargs: None
    sys.modules["ryu.lib.hub"].sleep = lambda *args, **kwargs: None
    sys.modules["ryu.lib"].hub = sys.modules["ryu.lib.hub"]

    class DummyEthernet:
        def __init__(self, dst, src, ethertype):
            self.dst = dst
            self.src = src
            self.ethertype = ethertype

    class DummyIPv4:
        pass

    class DummyTCP:
        pass

    class DummyPacket:
        def __init__(self, data):
            self.protocols = data

        def get_protocol(self, protocol_type):
            return self.protocols.get(protocol_type)

    sys.modules["ryu.lib.packet.ethernet"].ethernet = DummyEthernet
    sys.modules["ryu.lib.packet.ipv4"].ipv4 = DummyIPv4
    sys.modules["ryu.lib.packet.tcp"].tcp = DummyTCP
    sys.modules["ryu.lib.packet.packet"].Packet = DummyPacket
    sys.modules["ryu.lib.packet.ether_types"].ETH_TYPE_LLDP = 0x88CC
    sys.modules["ryu.lib.packet.ether_types"].ETH_TYPE_CFM = 0x8902
    for child in ("packet", "ethernet", "ipv4", "tcp", "ether_types"):
        setattr(
            sys.modules["ryu.lib.packet"],
            child,
            sys.modules["ryu.lib.packet.%s" % child],
        )
    sys.modules["ryu.app.wsgi"].WSGIApplication = DummyWSGIApplication
    sys.modules["ryu.app.wsgi"].ControllerBase = DummyControllerBase
    sys.modules["ryu.app.wsgi"].route = decorator
    for event in ("EventLinkAdd", "EventLinkDelete"):
        setattr(sys.modules["ryu.topology.event"], event, type(event, (), {}))
    sys.modules["webob"].Response = DummyResponse


install_ryu_stubs()
PATH = Path(__file__).resolve().parents[1] / "config" / "security_controller.py"
SPEC = importlib.util.spec_from_file_location("sdnmfa_security_controller_v2_test", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ControllerPolicyTests(unittest.TestCase):
    RUN_ID = "00000000-0000-0000-0000-000000000001"
    ATTEMPT_ID = "10000000-0000-0000-0000-000000000001"

    def setUp(self):
        self.controller = MODULE.SecurityController.__new__(MODULE.SecurityController)
        self.controller._lock = threading.Lock()
        self.controller._sdnmfa_authorized = {}
        self.controller._deny_events = deque(maxlen=MODULE.MAX_DENY_EVENTS)
        self.controller.inter_switch_ports = {(1, 9), (2, 9)}
        self.controller.mac_to_port = {}
        self.controller.datapaths = {}

    def test_database_accessors_are_bound_during_ryu_app_loading(self):
        self.assertTrue(callable(MODULE.get_db_connection))
        self.assertTrue(callable(MODULE.release_db_connection))

    def authorize(self, mode="password_only", binding="ip_mac_port", ttl=180):
        return self.controller.sdnmfa_authorize(
            "10.0.0.1",
            mode,
            binding,
            ttl,
            "00:00:00:00:00:01",
            1,
            7,
            self.RUN_ID,
            self.ATTEMPT_ID,
        )

    def test_strict_binding_checks_edge_and_allows_transit(self):
        for mode in MODULE.VALID_MODES:
            self.authorize(mode=mode)
            self.assertEqual(
                self.controller._authorization_decision(
                    "10.0.0.1", "00:00:00:00:00:01", 1, 7
                )[:2],
                (True, "authorized"),
            )
            self.assertEqual(
                self.controller._authorization_decision(
                    "10.0.0.1", "00:00:00:00:00:01", 2, 9
                )[:2],
                (True, "authorized"),
            )
            self.assertEqual(
                self.controller._authorization_decision(
                    "10.0.0.1", "00:00:00:00:00:01", 1, 8
                )[1],
                "port_mismatch",
            )

    def test_binding_not_mfa_policy_controls_mac_check(self):
        self.authorize(mode="password_otp_biometric", binding="ip_only")
        self.assertTrue(
            self.controller._authorization_decision(
                "10.0.0.1", "00:00:00:00:00:ff", 9, 99
            )[0]
        )
        self.authorize(mode="password_only", binding="ip_mac")
        self.assertEqual(
            self.controller._authorization_decision(
                "10.0.0.1", "00:00:00:00:00:ff", 1, 7
            )[1],
            "mac_mismatch",
        )

    def test_common_ttl_cannot_be_overridden(self):
        with self.assertRaisesRegex(ValueError, "common protocol"):
            self.authorize(ttl=60)

    def test_expired_authorization_is_rejected(self):
        self.authorize()
        self.controller._sdnmfa_authorized["10.0.0.1"]["exp"] = 0
        self.assertEqual(
            self.controller._authorization_decision(
                "10.0.0.1", "00:00:00:00:00:01", 1, 7
            )[1],
            "authorization_expired",
        )

    def test_deny_evidence_is_bounded_and_filterable(self):
        for index in range(MODULE.MAX_DENY_EVENTS + 10):
            self.controller._record_deny(
                reason="mac_mismatch",
                src_ip="10.0.0.1",
                src_mac="00:00:00:00:00:ff",
                dst_ip="10.0.0.2",
                dpid=1,
                in_port=8,
                tcp_src=40000 + index,
                tcp_dst=18080,
                authorization={"mode": "password_only", "binding_profile": "ip_mac_port"},
            )
        evidence = self.controller.sdnmfa_deny_events(src_ip="10.0.0.1", limit=200)
        self.assertEqual(len(self.controller._deny_events), MODULE.MAX_DENY_EVENTS)
        self.assertEqual(evidence["count"], 200)
        self.assertEqual(evidence["events"][-1]["binding_profile"], "ip_mac_port")

    def test_authorize_route_requires_explicit_binding(self):
        api = MODULE.SDNMFAController.__new__(MODULE.SDNMFAController)
        api.app = self.controller

        class Request:
            headers = {MODULE.API_TOKEN_HEADER: "A-valid-controller-token-1234567890-Z"}
            body = b"{}"
            def __init__(self, payload):
                self.json = payload

        base = {
            "src_ip": "10.0.0.1",
            "src_mac": "00:00:00:00:00:01",
            "mode": "password_only",
            "ttl": 180,
            "ingress_dpid": 1,
            "in_port": 7,
            "run_id": self.RUN_ID,
            "attempt_id": self.ATTEMPT_ID,
        }
        with patch.object(MODULE, "strong_secret_or_none", return_value=Request.headers[MODULE.API_TOKEN_HEADER]), patch.object(
            MODULE, "_successful_mfa_attempt", return_value=True
        ):
            response = api.authorize(Request(base))
            self.assertEqual(json.loads(response.body)["error"], "unsupported_binding_profile")
            base["binding_profile"] = "ip_mac_port"
            response = api.authorize(Request(base))
            self.assertTrue(json.loads(response.body)["authorized"])

    def test_authorize_route_rejects_unverified_mfa_attempt(self):
        api = MODULE.SDNMFAController.__new__(MODULE.SDNMFAController)
        api.app = self.controller

        class Request:
            headers = {MODULE.API_TOKEN_HEADER: "A-valid-controller-token-1234567890-Z"}
            body = b"{}"

            def __init__(self):
                self.json = {
                    "src_ip": "10.0.0.1",
                    "src_mac": "00:00:00:00:00:01",
                    "mode": "password_only",
                    "binding_profile": "ip_mac_port",
                    "ttl": 180,
                    "ingress_dpid": 1,
                    "in_port": 7,
                    "run_id": ControllerPolicyTests.RUN_ID,
                    "attempt_id": ControllerPolicyTests.ATTEMPT_ID,
                }

        with patch.object(
            MODULE,
            "strong_secret_or_none",
            return_value=Request.headers[MODULE.API_TOKEN_HEADER],
        ), patch.object(MODULE, "_successful_mfa_attempt", return_value=False):
            response = api.authorize(Request())
        self.assertEqual(
            json.loads(response.body)["error"],
            "authentication_attempt_not_verified",
        )

    def test_reset_clears_authorizations_and_deny_events(self):
        self.authorize()
        self.controller._deny_events.append({"denied_at": 1})
        result = self.controller.sdnmfa_reset()
        self.assertTrue(result["ok"])
        self.assertEqual(self.controller._sdnmfa_authorized, {})
        self.assertEqual(len(self.controller._deny_events), 0)

    def test_forwarding_refresh_preserves_authorization(self):
        self.authorize()
        self.controller.mac_to_port = {1: {"00:00:00:00:00:01": 7}}
        result = self.controller.sdnmfa_refresh_forwarding()
        self.assertTrue(result["ok"])
        self.assertEqual(self.controller.mac_to_port, {})
        self.assertIn("10.0.0.1", self.controller._sdnmfa_authorized)

    def test_discovery_frames_are_neither_learned_nor_flooded(self):
        ethernet_type = sys.modules["ryu.lib.packet.ethernet"].ethernet

        class Datapath:
            id = 1
            ofproto = types.SimpleNamespace(OFPP_FLOOD=0xFFFFFFFB, OFP_NO_BUFFER=0xFFFFFFFF)
            ofproto_parser = types.SimpleNamespace()

            def __init__(self):
                self.sent = []

            def send_msg(self, message):
                self.sent.append(message)

        for ethertype in (0x88CC, 0x8902):
            datapath = Datapath()
            frame = ethernet_type(
                "01:80:c2:00:00:0e",
                "00:00:00:00:00:02",
                ethertype,
            )
            message = types.SimpleNamespace(
                datapath=datapath,
                match={"in_port": 6},
                data={ethernet_type: frame},
            )
            self.controller.packet_in_handler(types.SimpleNamespace(msg=message))
            self.assertEqual(datapath.sent, [])
            self.assertNotIn("00:00:00:00:00:02", self.controller.mac_to_port.get(1, {}))


if __name__ == "__main__":
    unittest.main()
