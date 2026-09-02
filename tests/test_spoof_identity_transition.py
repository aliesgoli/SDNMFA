import unittest
from pathlib import Path
from unittest.mock import patch

from attacks import attack_manager


class SpoofIdentityTransitionTests(unittest.TestCase):
    def test_ipv4_suspension_never_cycles_the_host_link(self):
        responses = [
            {"return_code": 0, "stdout": "", "stderr": "", "timed_out": False},
            {"return_code": 0, "stdout": "", "stderr": "", "timed_out": False},
        ]
        with patch.object(attack_manager, "_get_iface", return_value="h1-eth0"), patch.object(
            attack_manager, "_ns_exec", side_effect=responses
        ) as execute:
            self.assertEqual(attack_manager._suspend_ipv4(101), "h1-eth0")

        commands = [call.args[1] for call in execute.call_args_list]
        self.assertEqual(commands[0][:4], ["ip", "-4", "addr", "flush"])
        self.assertFalse(any(command[:3] == ["ip", "link", "set"] for command in commands))

    def test_spoof_scenario_preserves_physical_host_links(self):
        module_source = Path(attack_manager.__file__).read_text(encoding="utf-8")
        start = module_source.index("    def _run_spoof(")
        end = module_source.index("    def _attack_ip_spoof(", start)
        source = module_source[start:end]
        self.assertIn("_suspend_ipv4(h1)", source)
        self.assertIn("_create_spoof_interface", source)
        self.assertNotIn("_set_link_state", source)
        self.assertNotIn("_set_identity(h3, ip=h1_ip, mac=", source)


if __name__ == "__main__":
    unittest.main()
