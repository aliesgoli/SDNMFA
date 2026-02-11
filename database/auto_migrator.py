import os
import sys
import logging
import psycopg2

"""Auto DB migrator.

This script is often executed in different ways:
  - from the package root:   python3 database/auto_migrator.py
  - from the repo parent:    python3 SDNMFA/database/auto_migrator.py

So we defensively ensure BOTH the SDNMFA package directory and its parent
are importable, and we also provide fallbacks that don't require the
"SDNMFA." prefix.
"""

# Ensure imports work whether the user runs this file from inside the SDNMFA
# folder or from its parent.
project_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../SDNMFA
parent_path = os.path.dirname(project_path)  # .../

for p in (parent_path, project_path):
    if p and p not in sys.path:
        sys.path.insert(0, p)
try:
    from SDNMFA.database.db_config import get_db_connection
except ImportError:
    from database.db_config import get_db_connection

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RESET = "\033[0m"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

class AutoMigrator:
    def __init__(self):
        self.conn = get_db_connection()

    def execute_safe(self, query):
        try:
            with self.conn.cursor() as cur:
                cur.execute(query)
            return True
        except psycopg2.Error as e:
            if "already exists" not in str(e):
                log.warning("Query note: %s", e)
            return False

    def migrate(self):
        # Import schema queries with a robust fallback.
        try:
            from SDNMFA.database.models import SCHEMA_QUERIES  # type: ignore
        except Exception:
            from database.models import SCHEMA_QUERIES  # type: ignore

        success_count = 0
        total_queries = len(SCHEMA_QUERIES)

        for query in SCHEMA_QUERIES:
            if self.execute_safe(query):
                success_count += 1

        self.conn.commit()
        return success_count, total_queries

    def close(self):
        if self.conn:
            self.conn.close()

def print_colored(message, color):
    print(f"{color}{message}{COLOR_RESET}")

def auto_migrate():
    migrator = AutoMigrator()
    if not migrator.conn:
        print_colored("❌ Database connection failed", COLOR_RED)
        return False

    try:
        success_count, total_queries = migrator.migrate()

        if success_count == total_queries:
            print_colored("✅ All schema changes applied", COLOR_GREEN)
        else:
            print_colored(f"⚠️  Applied {success_count}/{total_queries} changes", COLOR_YELLOW)

        return True

    except Exception as e:
        print_colored(f"❌ Migration failed: {e}", COLOR_RED)
        return False
    finally:
        migrator.close()

if __name__ == "__main__":
    auto_migrate()
