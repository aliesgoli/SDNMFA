import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.preflight_check import (
    AUTH_COLUMNS,
    AUTH_EXPERIMENT_COLUMNS,
    CAMPAIGN_COLUMNS,
    EXPERIMENT_RUN_COLUMNS,
    OTP_COLUMNS,
    REQUIRED_COMMANDS,
    REQUIRED_MODULES,
    REQUIRED_SYSTEM_MODULES,
    USERS_COLUMNS,
)


class PreflightContractTests(unittest.TestCase):
    def test_script_prioritizes_its_own_project_over_conflicting_config_package(self):
        project_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            fake_package = Path(temporary) / "config"
            fake_package.mkdir()
            (fake_package / "__init__.py").write_text("", encoding="utf-8")
            environment = dict(os.environ)
            environment["PYTHONPATH"] = os.pathsep.join(
                [temporary, str(project_root)]
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(project_root / "tools" / "preflight_check.py"),
                    "--help",
                ],
                cwd=str(project_root),
                env=environment,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_runtime_credential_columns_are_part_of_preflight(self):
        self.assertTrue(
            {"username", "password_hash", "biometric_template"}.issubset(
                USERS_COLUMNS
            )
        )
        self.assertIn("auth_logs_details", AUTH_COLUMNS)
        self.assertIn("otp_hash", OTP_COLUMNS)
        self.assertNotIn("failed_attempts", AUTH_COLUMNS)
        self.assertNotIn("invalidated_reason", AUTH_COLUMNS)
        self.assertIn("failed_attempts", OTP_COLUMNS)
        self.assertIn("invalidated_reason", OTP_COLUMNS)
        self.assertIn("otp_enabled", USERS_COLUMNS)
        self.assertIn("manifest_sha256", CAMPAIGN_COLUMNS)
        self.assertIn("sampled_parameters", EXPERIMENT_RUN_COLUMNS)
        self.assertIn("authentication_succeeded", AUTH_EXPERIMENT_COLUMNS)
        self.assertIn("tcpdump", REQUIRED_COMMANDS)
        self.assertIn("ping", REQUIRED_COMMANDS)
        self.assertIn(("psutil", "psutil"), REQUIRED_MODULES)
        self.assertIn(("mininet", "Mininet Python bindings"), REQUIRED_SYSTEM_MODULES)

    def test_python_requirements_are_pinned_and_match_preflight(self):
        requirements_path = Path(__file__).resolve().parents[1] / "requirements.txt"
        lines = [
            line.strip()
            for line in requirements_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertTrue(all("==" in line for line in lines))
        declared = {line.split("==", 1)[0].lower() for line in lines}
        checked = {package.lower() for _, package in REQUIRED_MODULES}
        self.assertEqual(declared, checked)
        self.assertIn("arabic-reshaper", declared)
        self.assertIn("python-bidi", declared)


if __name__ == "__main__":
    unittest.main()
