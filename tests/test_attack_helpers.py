import unittest
from unittest.mock import patch

from attacks.attack_manager import (
    ARP_POISON_CODE,
    FLOOD_RECEIVER_CODE,
    FLOOD_WORKER_CODE,
    HTTP_ATTEMPT_CODE,
    AttackManager,
    _arp_capture_assessment,
    _classify_access_probe,
    _curl_sensitive,
)
from attacks.base_attack import AttackConfig
from config.experiment_protocol import DISPLAY_SCENARIO_ORDER


class AttackHelperTests(unittest.TestCase):
    def test_embedded_worker_programs_are_valid_python(self):
        for source in (FLOOD_WORKER_CODE, FLOOD_RECEIVER_CODE, HTTP_ATTEMPT_CODE, ARP_POISON_CODE):
            compile(source, "<embedded-worker>", "exec")

    def test_display_order_matches_real_handlers(self):
        manager = AttackManager()
        self.assertEqual(manager.get_available_attacks(), DISPLAY_SCENARIO_ORDER)
        self.assertEqual(
            manager.get_available_attacks_display()[6][1],
            "ddos_udp_flood",
        )

    @staticmethod
    def _config(**overrides):
        values = {
            "username": "alice",
            "target_host": "10.0.0.2",
            "target_port": 18080,
            "duration_s": 5,
            "rate_pps": 1,
            "threads": 1,
            "payload_size_bytes": None,
            "mfa_mode": "password_only",
            "attack_type": "unauthorized_access",
            "intensity_level": "low",
            "request_count": 4,
            "source_count": 1,
            "binding_profile": "ip_mac_port",
        }
        values.update(overrides)
        return AttackConfig(**values)

    @patch("attacks.attack_manager._read_mn")
    def test_out_of_range_parameters_stop_before_mininet(self, read_mn):
        result = AttackManager().execute_attack(
            "unauthorized_access",
            self._config(rate_pps=99),
        )
        self.assertFalse(result.metrics["is_valid"])
        self.assertEqual(result.metrics["error_type"], "protocol_parameter_mismatch")
        self.assertIn("request_rate_out_of_range", result.metrics["protocol_parameter_errors"])
        read_mn.assert_not_called()

    def test_invalid_parameter_types_are_technical_errors(self):
        result = AttackManager().execute_attack(
            "unauthorized_access",
            self._config(duration_s="five"),
        )
        self.assertEqual(result.metrics["error_type"], "invalid_parameter_type")

    def test_timeout_with_matching_controller_deny_is_classified_as_blocked(self):
        probe = {"accessible": False, "all_timed_out": True, "http_status": 0}
        diagnostics = {"neighbor_state": "REACHABLE"}
        self.assertEqual(
            _classify_access_probe(
                probe,
                diagnostics,
                {"available": True, "count": 1, "events": [{"reason": "port_mismatch"}]},
            ),
            "attack_blocked",
        )

    def test_timeout_without_controller_deny_is_indeterminate(self):
        probe = {"accessible": False, "all_timed_out": True, "http_status": 0}
        diagnostics = {"neighbor_state": "STALE"}
        self.assertEqual(
            _classify_access_probe(
                probe,
                diagnostics,
                {"available": True, "count": 0, "events": []},
            ),
            "technical_error",
        )

    def test_incomplete_neighbor_is_not_counted_as_blocked(self):
        probe = {"accessible": False, "all_timed_out": True, "http_status": 0}
        self.assertEqual(
            _classify_access_probe(probe, {"neighbor_state": "INCOMPLETE"}),
            "technical_error",
        )

    def test_arp_capture_absence_is_not_treated_as_a_block_when_endpoint_succeeds(self):
        assessment = _arp_capture_assessment(
            {"accessible": True},
            "HTTP traffic without the protected response body",
        )
        self.assertTrue(assessment["legitimate_request_accessible"])
        self.assertFalse(assessment["confidentiality_exposed"])
        self.assertTrue(assessment["capture_inconclusive"])

    def test_arp_capture_detects_the_declared_protected_payload(self):
        assessment = _arp_capture_assessment(
            {"accessible": True},
            "headers\r\n\r\nThis is a sensitive resource.",
        )
        self.assertTrue(assessment["confidentiality_exposed"])
        self.assertFalse(assessment["capture_inconclusive"])

    @patch("attacks.attack_manager._ns_exec")
    def test_curl_requires_expected_body(self, execute):
        execute.return_value = {
            "return_code": 0,
            "stdout": "wrong body\n__SDNMFA_HTTP__:200\n",
            "stderr": "",
            "timed_out": False,
            "elapsed_ms": 1.2,
        }
        result = _curl_sensitive(123, "http://10.0.0.2:18080/sensitive.txt")
        self.assertFalse(result["accessible"])


if __name__ == "__main__":
    unittest.main()
