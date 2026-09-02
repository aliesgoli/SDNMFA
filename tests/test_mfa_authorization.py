import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def install_project_stubs():
    for name in ("database", "attacks", "security", "otp"):
        module = sys.modules.setdefault(name, types.ModuleType(name))
        module.__path__ = []
    modules = {}
    for name in (
        "database.db_config", "attacks.attack_manager", "attacks.base_attack",
        "security.mfa_manager", "otp.otp_service",
    ):
        modules[name] = sys.modules.setdefault(name, types.ModuleType(name))
    modules["database.db_config"].close_all_connections = lambda: None
    modules["database.db_config"].get_db_connection = lambda: None
    modules["database.db_config"].release_db_connection = lambda conn: None

    class DummyAttackManager:
        pass

    class DummyAttackConfig:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class DummyAttackResult:
        def __init__(self, success, message, metrics):
            self.success = success
            self.message = message
            self.metrics = metrics

    modules["attacks.attack_manager"].AttackManager = DummyAttackManager
    modules["attacks.attack_manager"].AttackConfig = DummyAttackConfig
    modules["attacks.base_attack"].AttackResult = DummyAttackResult
    modules["security.mfa_manager"].authenticate_user = lambda **kwargs: (True, "ok")
    modules["security.mfa_manager"].prepare_mfa_authentication = lambda *args, **kwargs: (True, "ok", "123456")
    modules["otp.otp_service"].generate_otp = lambda: "123456"
    modules["otp.otp_service"].store_otp = lambda *args, **kwargs: (True, "ok")


install_project_stubs()
CONTROLLER_PATH = Path(__file__).resolve().parents[1] / "controller" / "mfa_controller.py"
SPEC = importlib.util.spec_from_file_location("sdnmfa_mfa_controller_v2_test", CONTROLLER_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MFAAuthorizationTests(unittest.TestCase):
    RUN_ID = "00000000-0000-0000-0000-000000000001"
    ATTEMPT_ID = "10000000-0000-0000-0000-000000000001"

    def setUp(self):
        self.mn = {
            "h1": {
                "ip": "10.0.0.1",
                "mac": "00:00:00:00:00:01",
                "switch_dpid": 1,
                "in_port": 7,
            }
        }

    def test_project_root_is_pathlike_for_evidence_directories(self):
        self.assertIsInstance(MODULE.PROJECT_ROOT, Path)
        self.assertEqual((MODULE.PROJECT_ROOT / "evidence").name, "evidence")

    def test_all_policies_use_same_default_binding_and_ttl(self):
        payloads = [
            MODULE._build_authorization_payload(self.mn, mode)
            for mode in MODULE.POLICY_SPECS
        ]
        self.assertEqual({item["ttl"] for item in payloads}, {180})
        self.assertEqual({item["binding_profile"] for item in payloads}, {"ip_mac_port"})
        self.assertEqual({item["in_port"] for item in payloads}, {7})

    def test_explicit_ip_only_binding_is_independent_of_policy(self):
        payload = MODULE._build_authorization_payload(
            self.mn,
            "password_otp_biometric",
            "ip_only",
        )
        self.assertEqual(payload["binding_profile"], "ip_only")
        self.assertEqual(payload["mode"], "password_otp_biometric")

    @patch.object(MODULE.getpass, "getpass", return_value="secret-value")
    @patch("builtins.input", return_value="alice")
    def test_operator_cli_always_selects_full_mfa(self, _input, hidden_input):
        username, password, policy = MODULE.CLIInterface().get_authentication_parameters()
        self.assertEqual((username, password, policy), ("alice", "secret-value", "4"))
        hidden_input.assert_called_once_with("Password: ")

    @patch.object(MODULE.getpass, "getpass", return_value="  spaced secret  ")
    @patch("builtins.input", return_value="alice")
    def test_operator_password_is_not_silently_trimmed(self, _input, _hidden_input):
        _username, password, _policy = (
            MODULE.CLIInterface().get_authentication_parameters()
        )
        self.assertEqual(password, "  spaced secret  ")

    @patch.object(MODULE, "authenticate_user", return_value=(True, "ok"))
    @patch.object(MODULE, "prepare_mfa_authentication", return_value=(True, "ok", "123456"))
    @patch.object(MODULE.getpass, "getpass", return_value="test")
    @patch("builtins.input", return_value="123456")
    def test_full_login_hides_and_retains_simulated_biometric(
        self, _input, hidden_input, _prepare, authenticate
    ):
        controller = MODULE.MFAController()
        success, message = controller.login(
            "alice", "password-value", "4", self.RUN_ID, self.ATTEMPT_ID
        )
        self.assertTrue(success, message)
        self.assertEqual(controller.last_biometric_sample, "test")
        self.assertEqual(authenticate.call_args.kwargs["biometric_data"], "test")

    @patch.object(MODULE, "_ryu_request")
    def test_authorization_response_checks_binding_and_common_window(self, request):
        now = MODULE.time.time()
        request.return_value = (
            True,
            {
                "ok": True,
                "authorized": True,
                "src_ip": "10.0.0.1",
                "src_mac": "00:00:00:00:00:01",
                "mode": "password_biometric",
                "binding_profile": "ip_mac_port",
                "ttl": 180,
                "authorized_at": now,
                "exp": now + 180,
                "ingress_dpid": 1,
                "in_port": 7,
                "run_id": self.RUN_ID,
                "attempt_id": self.ATTEMPT_ID,
            },
        )
        response = MODULE._authorize_user(
            self.mn,
            "password_biometric",
            "ip_mac_port",
            run_id=self.RUN_ID,
            attempt_id=self.ATTEMPT_ID,
        )
        self.assertEqual(response["request"]["binding_profile"], "ip_mac_port")

    @patch.object(MODULE, "_ryu_request")
    def test_ready_check_uses_active_topology_counts(self, request):
        request.return_value = (
            True,
            {"datapaths": [1, 2, 3], "inter_switch_ports": [{}, {}, {}, {}]},
        )
        ready, _ = MODULE._wait_for_sdn_ready(
            {"switch_count": 3, "switch_link_count": 2}, timeout_s=0.1
        )
        self.assertTrue(ready)

    def test_authorization_requires_uuid_linkage(self):
        with self.assertRaisesRegex(ValueError, "required"):
            MODULE._authorize_user(self.mn, "password_only")
        with self.assertRaisesRegex(ValueError, "valid UUIDs"):
            MODULE._authorize_user(
                self.mn,
                "password_only",
                run_id="bad",
                attempt_id=self.ATTEMPT_ID,
            )

    def test_all_scenarios_is_explicit_and_mutually_exclusive(self):
        args = MODULE._parse_args(["--all-scenarios", "--repetitions", "2"])
        self.assertTrue(args.all_scenarios)
        self.assertEqual(args.repetitions, 2)
        with self.assertRaises(SystemExit):
            MODULE._parse_args(
                ["--all-scenarios", "--scenario", "unauthorized_access"]
            )


if __name__ == "__main__":
    unittest.main()
