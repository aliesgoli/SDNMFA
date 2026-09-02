import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


for package in ("database", "otp", "security"):
    module = sys.modules.setdefault(package, types.ModuleType(package))
    module.__path__ = []
for name in (
    "database.login_user", "database.db_config", "database.audit_log",
    "otp.otp_service", "security.biometric_service",
):
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["database.login_user"].login_user = lambda *args, **kwargs: (True, None, "")
sys.modules["database.db_config"].get_db_connection = lambda: None
sys.modules["database.db_config"].release_db_connection = lambda conn: None
sys.modules["database.audit_log"].insert_auth_log = lambda *args, **kwargs: None
sys.modules["otp.otp_service"].validate_otp = lambda *args, **kwargs: (True, "ok")
sys.modules["otp.otp_service"].generate_otp = lambda: "123456"
sys.modules["otp.otp_service"].store_otp = lambda *args, **kwargs: (True, "ok")
sys.modules["otp.otp_service"].deliver_otp = lambda *args, **kwargs: True
sys.modules["security.biometric_service"].verify_biometric = lambda *args, **kwargs: (True, "ok")

PATH = Path(__file__).resolve().parents[1] / "security" / "mfa_manager.py"
SPEC = importlib.util.spec_from_file_location("sdnmfa_mfa_manager_v2_test", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MFAManagerTests(unittest.TestCase):
    def test_otp_policy_requires_explicit_enrollment(self):
        with patch.object(
            MODULE,
            "get_user_factor_status",
            return_value=(
                True,
                {"is_active": True, "otp_enabled": False, "biometric_enrolled": True},
                "ok",
            ),
        ):
            ready, message = MODULE.policy_readiness("alice", "2")
        self.assertFalse(ready)
        self.assertIn("not enabled", message)

    def test_biometric_policy_requires_enrollment(self):
        with patch.object(
            MODULE,
            "get_user_factor_status",
            return_value=(
                True,
                {"is_active": True, "otp_enabled": True, "biometric_enrolled": False},
                "ok",
            ),
        ):
            ready, message = MODULE.policy_readiness("alice", "3")
        self.assertFalse(ready)
        self.assertIn("not enrolled", message)

    def test_legacy_biometric_template_requires_current_reenrollment(self):
        with patch.object(
            MODULE,
            "get_user_factor_status",
            return_value=(
                True,
                {
                    "is_active": True,
                    "otp_enabled": True,
                    "biometric_enrolled": True,
                    "biometric_mode": None,
                },
                "ok",
            ),
        ):
            ready, message = MODULE.policy_readiness("alice", "3")
        self.assertFalse(ready)
        self.assertIn("re-enrolled", message)

    @patch.object(MODULE, "store_otp", return_value=(True, "ok"))
    @patch.object(MODULE, "generate_otp", return_value="654321")
    @patch.object(MODULE, "deliver_otp", return_value=True)
    @patch.object(MODULE, "policy_readiness", return_value=(True, "ok"))
    def test_preparation_links_fresh_otp_to_attempt(
        self, _ready, _deliver, _generate, store
    ):
        success, _, code = MODULE.prepare_mfa_authentication(
            "alice", "2", run_id="run-id", attempt_id="attempt-id"
        )
        self.assertTrue(success)
        self.assertEqual(code, "654321")
        store.assert_called_once_with(
            "alice", "654321", run_id="run-id", attempt_id="attempt-id"
        )

    @patch.object(MODULE, "login_user")
    @patch.object(MODULE, "policy_readiness", return_value=(False, "OTP not enabled"))
    def test_authentication_stops_before_password_when_policy_not_ready(self, _ready, login):
        success, message = MODULE.authenticate_user("alice", "password", policy_key="2")
        self.assertFalse(success)
        self.assertIn("not enabled", message)
        login.assert_not_called()

    @patch.object(MODULE, "_log_event")
    @patch.object(MODULE, "verify_biometric")
    @patch.object(MODULE, "validate_otp")
    @patch.object(MODULE, "login_user", return_value=(True, None, ""))
    @patch.object(MODULE, "policy_readiness", return_value=(True, "ok"))
    def test_password_only_does_not_invoke_unused_factors(
        self, _ready, _login, otp, biometric, _log
    ):
        with patch.object(MODULE, "_mark_successful_login") as mark_login:
            success, _ = MODULE.authenticate_user("alice", "password", policy_key="1")
        self.assertTrue(success)
        mark_login.assert_called_once_with("alice")
        otp.assert_not_called()
        biometric.assert_not_called()

    @patch.object(MODULE, "_mark_successful_login")
    @patch.object(MODULE, "_log_event")
    @patch.object(MODULE, "validate_otp", return_value=(False, "invalid"))
    @patch.object(MODULE, "login_user", return_value=(True, None, ""))
    @patch.object(MODULE, "policy_readiness", return_value=(True, "ok"))
    def test_failed_second_factor_does_not_update_last_login(
        self, _ready, _login, _otp, _log, mark_login
    ):
        success, _ = MODULE.authenticate_user(
            "alice", "password", otp_code="000000", policy_key="2"
        )
        self.assertFalse(success)
        mark_login.assert_not_called()


if __name__ == "__main__":
    unittest.main()
