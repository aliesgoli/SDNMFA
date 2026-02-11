"""
User Management CLI for SDN MFA System
Allows administrators to create, modify, and manage users
"""

import os
import sys
import logging
import re
from typing import Optional, Tuple

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from SDNMFA.database.db_config import get_db_connection, release_db_connection
    from SDNMFA.security.biometric_service import enroll_biometric, is_biometric_enrolled
    from SDNMFA.otp.otp_service import generate_otp, store_otp
except ImportError:
    try:
        from database.db_config import get_db_connection, release_db_connection
        from security.biometric_service import enroll_biometric, is_biometric_enrolled
        from otp.otp_service import generate_otp, store_otp
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print(f"💡 Please run from project root directory:")
        print(f"   cd 'My Thesis Project/SDNMFA'")
        print(f"   python3.9 admin/user_management.py")
        sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UserManager:

    @staticmethod
    def _get_user_identifier_column(cur) -> str:
        """Return a stable identifier column for users (prefers id, then primary key, then username)."""
        try:
            cur.execute("""
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'id'
                LIMIT 1
            """)
            if cur.fetchone():
                return 'id'

            cur.execute("""
                SELECT a.attname
                FROM pg_index i
                JOIN pg_attribute a
                  ON a.attrelid = i.indrelid
                 AND a.attnum = ANY(i.indkey)
                WHERE i.indrelid = 'users'::regclass
                  AND i.indisprimary
                LIMIT 1
            """)
            row = cur.fetchone()
            if row and row[0]:
                pk = str(row[0])
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", pk):
                    cur.execute("""
                        SELECT 1
                        FROM information_schema.columns
                        WHERE table_name = 'users' AND column_name = %s
                        LIMIT 1
                    """, (pk,))
                    if cur.fetchone():
                        return pk

            cur.execute("""
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'username'
                LIMIT 1
            """)
            if cur.fetchone():
                return 'username'
        except Exception:
            pass
        return 'username'

    @staticmethod
    def create_user(username: str, full_name: str, email: str, password: str,
                    role: str = "user") -> Tuple[bool, str]:
        """Create new user"""
        conn = get_db_connection()
        if not conn:
            return False, "Database connection failed"

        try:
            with conn.cursor() as cur:
                cur.execute("SELECT username FROM users WHERE username = %s", (username,))
                if cur.fetchone():
                    return False, f"User '{username}' already exists"

                identifier_col = UserManager._get_user_identifier_column(cur)

                if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", identifier_col):
                    return False, f"Invalid identifier column: {identifier_col}"

                cur.execute(f"""
                    INSERT INTO users (username, full_name, email, password_hash, role)
                    VALUES (%s, %s, %s, crypt(%s, gen_salt('bf')), %s)
                    RETURNING {identifier_col}
                """, (username, full_name, email, password, role))

                identifier_val = cur.fetchone()[0]
                conn.commit()

                label = "ID" if identifier_col == "id" else identifier_col
                logger.info(f"✅ User '{username}' created with {label} {identifier_val}")
                return True, f"User created successfully ({label}: {identifier_val})"

        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            if conn:
                conn.rollback()
            return False, f"Error: {e}"
        finally:
            release_db_connection(conn)

    @staticmethod
    def list_users() -> None:
        """List all users"""
        conn = get_db_connection()
        if not conn:
            print("❌ Database connection failed")
            return

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT username, full_name, email, role, 
                           otp_secret IS NOT NULL as has_otp,
                           biometric_template IS NOT NULL as has_biometric,
                           is_active, last_login, created_at
                    FROM users
                    ORDER BY created_at DESC
                """)

                users = cur.fetchall()

                if not users:
                    print("\n📋 No users found")
                    return

                print("\n" + "=" * 100)
                print("📋 USER LIST".center(100))
                print("=" * 100)
                print(
                    f"{'Username':<15} {'Name':<20} {'Email':<25} {'Role':<10} {'MFA':<15} {'Active':<8} {'Last Login':<20}")
                print("-" * 100)

                for user in users:
                    username, name, email, role, has_otp, has_bio, active, last_login, created = user

                    mfa_status = []
                    if has_otp:
                        mfa_status.append("OTP")
                    if has_bio:
                        mfa_status.append("BIO")
                    mfa = "+".join(mfa_status) if mfa_status else "None"

                    active_str = "✅ Yes" if active else "❌ No"

                    login_str = last_login.strftime("%Y-%m-%d %H:%M") if last_login else "Never"

                    print(f"{username:<15} {name:<20} {email:<25} {role:<10} {mfa:<15} {active_str:<8} {login_str:<20}")

                print("=" * 100)
                print(f"Total users: {len(users)}\n")

        except Exception as e:
            logger.error(f"Failed to list users: {e}")
            print(f"❌ Error: {e}")
        finally:
            release_db_connection(conn)

    @staticmethod
    def update_user_mfa(username: str) -> Tuple[bool, str]:
        """Update user MFA settings"""
        conn = get_db_connection()
        if not conn:
            return False, "Database connection failed"

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT username, otp_secret IS NOT NULL as has_otp,
                           biometric_template IS NOT NULL as has_biometric
                    FROM users WHERE username = %s
                """, (username,))

                user = cur.fetchone()
                if not user:
                    return False, f"User '{username}' not found"

                _, has_otp, has_bio = user

                print(f"\n📋 Current MFA Status for '{username}':")
                print(f"   OTP: {'✅ Enabled' if has_otp else '❌ Disabled'}")
                print(f"   Biometric: {'✅ Enrolled' if has_bio else '❌ Not enrolled'}")

                print("\n🔧 MFA Configuration:")
                print("1. Enable OTP")
                print("2. Disable OTP")
                print("3. Enroll Biometric")
                print("4. Remove Biometric")
                print("5. Cancel")

                choice = input("\nSelect option [1-5]: ").strip()

                if choice == "1":
                    otp_secret = generate_otp()
                    cur.execute("UPDATE users SET otp_secret = %s WHERE username = %s",
                                (otp_secret, username))
                    conn.commit()
                    return True, f"OTP enabled for '{username}'"

                elif choice == "2":
                    cur.execute("UPDATE users SET otp_secret = NULL WHERE username = %s",
                                (username,))
                    conn.commit()
                    return True, f"OTP disabled for '{username}'"

                elif choice == "3":
                    bio_data = input("Enter biometric data (or 'test' for test data): ").strip()
                    if bio_data.lower() == 'test':
                        bio_data = f"test_biometric_{username}"

                    success, msg = enroll_biometric(username, bio_data, overwrite_existing=True)
                    return success, msg

                elif choice == "4":
                    cur.execute("UPDATE users SET biometric_template = NULL WHERE username = %s",
                                (username,))
                    conn.commit()
                    return True, f"Biometric removed for '{username}'"

                else:
                    return False, "Operation cancelled"

        except Exception as e:
            logger.error(f"Failed to update MFA: {e}")
            if conn:
                conn.rollback()
            return False, f"Error: {e}"
        finally:
            release_db_connection(conn)

    @staticmethod
    def change_user_role(username: str, new_role: str) -> Tuple[bool, str]:
        """Change user role"""
        valid_roles = ['user', 'admin', 'superadmin']
        if new_role not in valid_roles:
            return False, f"Invalid role. Must be one of: {', '.join(valid_roles)}"

        conn = get_db_connection()
        if not conn:
            return False, "Database connection failed"

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE users SET role = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE username = %s
                    RETURNING username
                """, (new_role, username))

                result = cur.fetchone()
                if not result:
                    return False, f"User '{username}' not found"

                conn.commit()
                return True, f"Role changed to '{new_role}' for user '{username}'"

        except Exception as e:
            logger.error(f"Failed to change role: {e}")
            if conn:
                conn.rollback()
            return False, f"Error: {e}"
        finally:
            release_db_connection(conn)

    @staticmethod
    def delete_user(username: str) -> Tuple[bool, str]:
        """Delete user"""
        conn = get_db_connection()
        if not conn:
            return False, "Database connection failed"

        try:
            confirm = input(f"⚠️  Are you sure you want to delete user '{username}'? (yes/no): ").strip().lower()
            if confirm != 'yes':
                return False, "Operation cancelled"

            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username = %s RETURNING username", (username,))
                result = cur.fetchone()

                if not result:
                    return False, f"User '{username}' not found"

                conn.commit()
                return True, f"User '{username}' deleted successfully"

        except Exception as e:
            logger.error(f"Failed to delete user: {e}")
            if conn:
                conn.rollback()
            return False, f"Error: {e}"
        finally:
            release_db_connection(conn)

def main_menu():
    """Main menu for user management"""
    manager = UserManager()

    while True:
        print("\n" + "=" * 60)
        print(" 👥 USER MANAGEMENT SYSTEM ".center(60, "="))
        print("=" * 60)
        print("1. 📋 List all users")
        print("2. ➕ Create new user")
        print("3. 🔧 Update user MFA settings")
        print("4. 🎭 Change user role")
        print("5. 🗑️  Delete user")
        print("6. 🚪 Exit")
        print("=" * 60)

        choice = input("\nSelect option [1-6]: ").strip()

        if choice == "1":
            manager.list_users()

        elif choice == "2":
            print("\n➕ CREATE NEW USER")
            print("-" * 60)
            username = input("Username: ").strip()
            full_name = input("Full Name: ").strip()
            email = input("Email: ").strip()
            password = input("Password: ").strip()
            role = input("Role [user/admin/superadmin] (default: user): ").strip() or "user"

            success, message = manager.create_user(username, full_name, email, password, role)
            print(f"\n{'✅' if success else '❌'} {message}")

        elif choice == "3":
            username = input("\nEnter username: ").strip()
            success, message = manager.update_user_mfa(username)
            print(f"\n{'✅' if success else '❌'} {message}")

        elif choice == "4":
            username = input("\nEnter username: ").strip()
            new_role = input("New role [user/admin/superadmin]: ").strip()
            success, message = manager.change_user_role(username, new_role)
            print(f"\n{'✅' if success else '❌'} {message}")

        elif choice == "5":
            username = input("\nEnter username to delete: ").strip()
            success, message = manager.delete_user(username)
            print(f"\n{'✅' if success else '❌'} {message}")

        elif choice == "6":
            print("\n👋 Goodbye!")
            break

        else:
            print("\n❌ Invalid choice")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()