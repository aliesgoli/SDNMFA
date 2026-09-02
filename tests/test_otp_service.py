import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import patch


OTP_PATH = Path(__file__).resolve().parents[1] / "otp" / "otp_service.py"
SPEC = importlib.util.spec_from_file_location("sdnmfa_otp_service_test", OTP_PATH)
otp_service = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(otp_service)


class FakeCursor:
    def __init__(self, otp_row):
        self.otp_row = otp_row
        self.queries = []
        self._phase = "columns"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, query, params=None):
        self.queries.append((" ".join(query.split()), params))
        if "FROM information_schema.columns" in query:
            self._phase = "columns"
        elif "FROM otp_sessions" in query and "SELECT id" in query:
            self._phase = "otp"
        else:
            self._phase = "update"

    def fetchall(self):
        return [("attempt_id",)] if self._phase == "columns" else []

    def fetchone(self):
        return self.otp_row if self._phase == "otp" else None


class FakeConnection:
    def __init__(self, otp_row):
        self.cursor_instance = FakeCursor(otp_row)
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


class OTPServiceTests(unittest.TestCase):
    @patch.object(otp_service, "get_db_connection")
    def test_invalid_ttl_is_rejected_before_database_access(self, connection):
        success, message = otp_service.store_otp("alice", "123456", ttl_seconds=0)
        self.assertFalse(success)
        self.assertIn("between 1 and 3600", message)
        connection.assert_not_called()

    @patch.object(otp_service, "get_db_connection")
    def test_malformed_otp_is_rejected_before_database_access(self, connection):
        success, message = otp_service.store_otp("alice", "12ab")
        self.assertFalse(success)
        self.assertIn("numeric", message)
        connection.assert_not_called()

    def test_validation_selects_the_linked_attempt_and_uses_database_time(self):
        attempt_id = "a0000000-0000-0000-0000-000000000001"
        with patch.dict(
            os.environ,
            {"OTP_PEPPER": "OTP-Test-Pepper-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789"},
            clear=False,
        ):
            stored_hash = otp_service.hash_otp(
                "123456", username="alice", attempt_id=attempt_id
            )
            connection = FakeConnection((7, stored_hash, False, False, 0))
            with patch.object(
                otp_service, "get_db_connection", return_value=connection
            ), patch.object(otp_service, "release_db_connection"):
                success, message = otp_service.validate_otp(
                    "alice",
                    "123456",
                    attempt_id=attempt_id,
                )
        self.assertTrue(success, message)
        select_query, select_params = connection.cursor_instance.queries[1]
        self.assertIn("expires_at <= CURRENT_TIMESTAMP", select_query)
        self.assertIn("attempt_id=%s", select_query)
        self.assertIn("FOR UPDATE", select_query)
        self.assertEqual(select_params[0], "alice")
        self.assertTrue(connection.committed)


if __name__ == "__main__":
    unittest.main()
