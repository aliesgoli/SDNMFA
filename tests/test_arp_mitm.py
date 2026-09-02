import json
import types
import unittest
from unittest.mock import Mock, call, patch

from attacks.attack_manager import (
    AttackManager,
    POISONABLE_NEIGHBOR_STATES,
    _flush_neigh,
    _neighbor_observation,
    _observe_arp_pair,
    _prime_arp_pair,
    _wait_for_arp_pair,
)
from attacks.base_attack import AttackConfig


class ArpMitmTests(unittest.TestCase):
    def test_flush_targets_all_nud_states_and_verifies_exact_removal(self):
        with patch("attacks.attack_manager._get_iface", return_value="h1-eth0"), patch(
            "attacks.attack_manager._ns_exec",
            side_effect=[
                {"return_code": 0, "stdout": "", "stderr": ""},
                {"return_code": 0, "stdout": "", "stderr": ""},
            ],
        ) as execute:
            observation = _flush_neigh(101, "10.0.0.2")

        self.assertEqual(observation["state"], "MISSING")
        self.assertEqual(
            execute.call_args_list[0].args[1],
            [
                "ip", "neigh", "flush", "to", "10.0.0.2", "dev", "h1-eth0",
                "nud", "all",
            ],
        )
        self.assertEqual(
            execute.call_args_list[1].args[1],
            ["ip", "neigh", "show", "10.0.0.2", "dev", "h1-eth0"],
        )

    def test_flush_fails_closed_when_permanent_entry_remains(self):
        with patch("attacks.attack_manager._get_iface", return_value="h1-eth0"), patch(
            "attacks.attack_manager._ns_exec",
            side_effect=[
                {"return_code": 0, "stdout": "", "stderr": ""},
                {
                    "return_code": 0,
                    "stdout": (
                        "10.0.0.2 dev h1-eth0 lladdr "
                        "00:00:00:00:00:02 PERMANENT\n"
                    ),
                    "stderr": "",
                },
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "residual entry"):
                _flush_neigh(101, "10.0.0.2")

    def test_neighbor_observation_requires_an_exact_lladdr(self):
        with patch("attacks.attack_manager._get_iface", return_value="h1-eth0"), patch(
            "attacks.attack_manager._ns_exec",
            return_value={
                "return_code": 0,
                "stdout": "10.0.0.2 dev h1-eth0 lladdr 00:00:00:00:00:03 STALE\n",
                "stderr": "",
            },
        ):
            observed = _neighbor_observation(101, "10.0.0.2")

        self.assertEqual(observed["mac"], "00:00:00:00:00:03")
        self.assertEqual(observed["state"], "STALE")
        self.assertEqual(observed["interface"], "h1-eth0")

    def test_pair_verification_polls_until_both_endpoints_match(self):
        invalid = {
            "verified": False,
            "h1_to_h2": {"mac": "00:00:00:00:00:02"},
            "h2_to_h1": {"mac": "00:00:00:00:00:01"},
        }
        valid = {
            "verified": True,
            "h1_to_h2": {"mac": "00:00:00:00:00:03"},
            "h2_to_h1": {"mac": "00:00:00:00:00:03"},
        }
        with patch(
            "attacks.attack_manager._observe_arp_pair",
            side_effect=[invalid, valid],
        ) as observe, patch("attacks.attack_manager.time.sleep"):
            result = _wait_for_arp_pair(
                101,
                102,
                "10.0.0.1",
                "00:00:00:00:00:01",
                "10.0.0.2",
                "00:00:00:00:00:02",
                "00:00:00:00:00:03",
                "00:00:00:00:00:03",
                attempts=4,
                interval_s=0.01,
            )

        self.assertTrue(result["verified"])
        self.assertEqual(result["verification_attempts"], 2)
        self.assertEqual(observe.call_count, 2)

    def test_dynamic_baseline_rejects_permanent_or_noarp_states(self):
        observations = [
            {
                "return_code": 0,
                "mac": "00:00:00:00:00:02",
                "state": "PERMANENT",
            },
            {
                "return_code": 0,
                "mac": "00:00:00:00:00:01",
                "state": "NOARP",
            },
        ]
        with patch(
            "attacks.attack_manager._neighbor_observation",
            side_effect=observations,
        ):
            observed = _observe_arp_pair(
                101,
                102,
                "10.0.0.1",
                "00:00:00:00:00:01",
                "10.0.0.2",
                "00:00:00:00:00:02",
                "00:00:00:00:00:02",
                "00:00:00:00:00:01",
                accepted_states=POISONABLE_NEIGHBOR_STATES,
            )

        self.assertTrue(observed["mapping_verified"])
        self.assertFalse(observed["state_verified"])
        self.assertFalse(observed["verified"])

    def test_arp_baseline_flushes_permanent_entries_before_priming(self):
        with patch("attacks.attack_manager._flush_neigh") as flush, patch(
            "attacks.attack_manager._ns_exec",
            return_value={"return_code": 0, "stdout": "", "stderr": ""},
        ) as execute, patch(
            "attacks.attack_manager._wait_for_arp_pair",
            return_value={"verified": True},
        ) as wait_pair:
            result = _prime_arp_pair(
                101,
                102,
                "10.0.0.1",
                "00:00:00:00:00:01",
                "10.0.0.2",
                "00:00:00:00:00:02",
            )

        self.assertTrue(result["verified"])
        self.assertEqual(
            flush.call_args_list,
            [call(101, "10.0.0.2"), call(102, "10.0.0.1")],
        )
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(execute.call_args_list[0].args[1][0], "ping")
        self.assertEqual(
            wait_pair.call_args.kwargs["accepted_states"],
            POISONABLE_NEIGHBOR_STATES,
        )

    @staticmethod
    def _config():
        return AttackConfig(
            username="alice",
            target_host="10.0.0.2",
            target_port=18080,
            duration_s=5,
            rate_pps=1,
            threads=1,
            payload_size_bytes=None,
            mfa_mode="password_only",
            attack_type="arp_mitm",
            intensity_level="low",
            request_count=4,
            source_count=1,
            binding_profile="ip_mac_port",
        )

    def test_scenario_verifies_poisoning_and_restoration_with_structured_evidence(self):
        mn = {
            "h1": {"pid": 101, "ip": "10.0.0.1", "mac": "00:00:00:00:00:01"},
            "h2": {"pid": 102, "ip": "10.0.0.2", "mac": "00:00:00:00:00:02"},
            "h3": {"pid": 103, "ip": "10.0.0.3", "mac": "00:00:00:00:00:03"},
            "sensitive": {"path": "http://10.0.0.2:18080/sensitive.txt"},
        }
        baseline = {"verified": True, "phase": "baseline"}
        poisoned = {"verified": True, "phase": "poisoned"}
        restored = {"verified": True, "phase": "restored"}
        capture_process = Mock()
        capture_process.poll.return_value = None
        poison_process = Mock()
        poison_payload = json.dumps(
            {
                "arp_replies_sent": 8,
                "arp_replies_by_target": {"10.0.0.1": 4, "10.0.0.2": 4},
            }
        )

        with patch.object(
            AttackManager,
            "_prepare_with_preflight",
            return_value=(mn, {"valid": True}, None),
        ), patch(
            "attacks.attack_manager._get_iface", return_value="h3-eth0"
        ), patch(
            "attacks.attack_manager._prime_arp_pair", return_value=baseline
        ) as prime, patch(
            "attacks.attack_manager._wait_for_arp_pair", return_value=poisoned
        ) as wait_pair, patch(
            "attacks.attack_manager._restore_arp_pair", return_value=restored
        ) as restore, patch(
            "attacks.attack_manager._ns_exec",
            return_value={"return_code": 0, "stdout": "0", "stderr": ""},
        ), patch(
            "attacks.attack_manager.subprocess.Popen",
            side_effect=[capture_process, poison_process],
        ) as popen, patch(
            "attacks.attack_manager._terminate_process",
            side_effect=[
                (poison_payload, "", None),
                ("HTTP request without protected response body", "", None),
            ],
        ), patch(
            "attacks.attack_manager._http_attempt_series",
            return_value={
                "accessible": False,
                "all_timed_out": True,
                "http_status": 0,
                "samples": [{"accessible": False, "timed_out": True}],
            },
        ), patch(
            "attacks.attack_manager._controller_deny_evidence",
            return_value={
                "available": True,
                "count": 1,
                "events": [{"reason": "mac_mismatch"}],
            },
        ), patch(
            "attacks.attack_manager._network_diagnostics",
            return_value={"neighbor_state": "STALE"},
        ), patch(
            "attacks.attack_manager._postflight",
            return_value={"valid": True, "rate": 1.0, "samples": []},
        ), patch("attacks.attack_manager.time.sleep"):
            result = AttackManager()._attack_arp_mitm(self._config())

        prime.assert_called_once()
        wait_pair.assert_called_once()
        restore.assert_called_once()
        self.assertEqual(popen.call_count, 2)
        self.assertTrue(result.metrics["is_valid"])
        self.assertEqual(result.metrics["security_outcome"], "attack_blocked")
        self.assertTrue(result.metrics["arp_poisoning_verified"])
        self.assertTrue(result.metrics["arp_restoration_verified"])
        self.assertEqual(result.metrics["arp_baseline_state"], baseline)
        self.assertEqual(result.metrics["arp_poisoned_state"], poisoned)
        self.assertEqual(result.metrics["arp_restored_state"], restored)
        self.assertEqual(result.metrics["arp_replies_sent"], 8)


if __name__ == "__main__":
    unittest.main()
