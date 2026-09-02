import unittest
from unittest.mock import MagicMock, patch

from admin.user_management import UserManager


def database_fixture(has_biometric):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = ("alice", True, has_biometric)
    return connection


class UserManagementTests(unittest.TestCase):
    @patch("admin.user_management.release_db_connection")
    @patch("admin.user_management.get_db_connection")
    @patch("admin.user_management.enroll_biometric")
    @patch("builtins.input", side_effect=["3", "no"])
    def test_existing_biometric_is_not_silently_overwritten(
        self, _input, enroll, get_connection, _release
    ):
        get_connection.return_value = database_fixture(True)

        success, message = UserManager.update_user_mfa("alice")

        self.assertFalse(success)
        self.assertIn("left unchanged", message)
        enroll.assert_not_called()

    @patch("admin.user_management.release_db_connection")
    @patch("admin.user_management.get_db_connection")
    @patch("admin.user_management.verify_biometric", return_value=(True, "verified"))
    @patch("admin.user_management.enroll_biometric", return_value=(True, "enrolled"))
    @patch("admin.user_management.getpass.getpass", side_effect=["test", "test"])
    @patch("builtins.input", side_effect=["3"])
    def test_first_enrollment_does_not_request_overwrite(
        self,
        _input,
        _getpass,
        enroll,
        _verify,
        get_connection,
        _release,
    ):
        get_connection.return_value = database_fixture(False)

        success, _message = UserManager.update_user_mfa("alice")

        self.assertTrue(success)
        enroll.assert_called_once_with(
            "alice", "test", overwrite_existing=False
        )

    @patch("admin.user_management.release_db_connection")
    @patch("admin.user_management.get_db_connection")
    @patch("admin.user_management.verify_biometric", return_value=(True, "verified"))
    @patch("admin.user_management.enroll_biometric", return_value=(True, "enrolled"))
    @patch("admin.user_management.getpass.getpass", side_effect=["test", "test"])
    @patch("builtins.input", side_effect=["3", "yes"])
    def test_replacement_requires_explicit_confirmation(
        self,
        _input,
        _getpass,
        enroll,
        _verify,
        get_connection,
        _release,
    ):
        get_connection.return_value = database_fixture(True)

        success, _message = UserManager.update_user_mfa("alice")

        self.assertTrue(success)
        enroll.assert_called_once_with(
            "alice", "test", overwrite_existing=True
        )


if __name__ == "__main__":
    unittest.main()
