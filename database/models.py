"""Versioned schema loader.

The SQL file is the single source of truth. Keeping one schema definition
prevents the Python bootstrapper and the documented psql command from creating
different table layouts.
"""

import os
import sys


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
while PROJECT_ROOT in sys.path:
    sys.path.remove(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "sql", "tables.sql")
with open(SCHEMA_PATH, "r", encoding="utf-8") as schema_file:
    SCHEMA_QUERIES = [schema_file.read()]


def create_or_migrate_schema() -> bool:
    from database.auto_migrator import auto_migrate
    return bool(auto_migrate())


if __name__ == "__main__":
    raise SystemExit(0 if create_or_migrate_schema() else 1)
