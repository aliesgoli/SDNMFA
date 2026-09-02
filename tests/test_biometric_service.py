import base64
import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


for name in ("database", "database.db_config", "database.audit_log"):
    module = sys.modules.setdefault(name, types.ModuleType(name))
    if name == "database":
        module.__path__ = []
sys.modules["database.db_config"].get_db_connection = lambda: None
sys.modules["database.db_config"].release_db_connection = lambda conn: None
sys.modules["database.audit_log"].insert_auth_log = lambda *args, **kwargs: None

PATH = Path(__file__).resolve().parents[1] / "security" / "biometric_service.py"
SPEC = importlib.util.spec_from_file_location("sdnmfa_biometric_v2_test", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BiometricServiceTests(unittest.TestCase):
    def test_test_token_is_consistent_between_enrollment_and_login(self):
        first = MODULE._normalize_biometric_input("test", username="Alice")
        second = MODULE._normalize_biometric_input("test", username="alice")
        self.assertEqual(first, second)

    def test_test_token_is_scoped_to_username(self):
        alice = MODULE._normalize_biometric_input("test", username="alice")
        bob = MODULE._normalize_biometric_input("test", username="bob")
        self.assertNotEqual(alice, bob)

    def test_base64_is_decoded_only_with_explicit_prefix(self):
        raw = "0123456789abcdef"
        encoded = base64.b64encode(raw.encode()).decode()
        decoded_digest = MODULE._normalize_biometric_input("base64:" + encoded, username="alice")
        raw_digest = MODULE._normalize_biometric_input(raw, username="alice")
        self.assertEqual(decoded_digest, raw_digest)
        ambiguous = MODULE._normalize_biometric_input(encoded, username="alice")
        self.assertNotEqual(ambiguous, raw_digest)

    def test_short_sample_fails_closed(self):
        with self.assertRaises(ValueError):
            MODULE._normalize_biometric_input("short", username="alice")

    def test_template_hash_verification_uses_stable_pepper(self):
        digest = MODULE._normalize_biometric_input("test", username="alice")
        with patch.dict(
            os.environ,
            {"BIOMETRIC_PEPPER": "Biometric-Pepper-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789"},
        ):
            stored = MODULE._hash_biometric_template(digest)
            self.assertTrue(MODULE._verify_biometric_hash(stored, digest))
            other = MODULE._normalize_biometric_input("test", username="bob")
            self.assertFalse(MODULE._verify_biometric_hash(stored, other))


if __name__ == "__main__":
    unittest.main()
