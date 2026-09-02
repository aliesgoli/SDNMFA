import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SchemaFileTests(unittest.TestCase):
    def test_upgrade_adds_columns_before_new_indexes(self):
        sql = (ROOT / "database" / "sql" / "tables.sql").read_text(encoding="utf-8")
        self.assertLess(
            sql.index("ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS run_id"),
            sql.index("CREATE INDEX IF NOT EXISTS idx_auth_logs_run_id"),
        )
        self.assertLess(
            sql.index("ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS is_valid"),
            sql.index("CREATE INDEX IF NOT EXISTS idx_attack_logs_validity"),
        )
        self.assertLess(
            sql.index("ALTER TABLE otp_sessions ADD COLUMN IF NOT EXISTS run_id"),
            sql.index("CREATE INDEX IF NOT EXISTS idx_otp_sessions_run_id"),
        )

    def test_dedicated_migration_is_transactional_and_non_destructive(self):
        sql = (
            ROOT / "database" / "sql" / "migrate_v2_scientific.sql"
        ).read_text(encoding="utf-8")
        upper = sql.upper()
        self.assertIn("BEGIN;", upper)
        self.assertIn("COMMIT;", upper)
        self.assertNotIn("DROP TABLE", upper)
        self.assertNotIn("DELETE FROM", upper)
        self.assertNotIn("TRUNCATE", upper)

    def test_v2_schema_separates_enrollment_and_experiment_entities(self):
        sql = (ROOT / "database" / "sql" / "tables.sql").read_text(encoding="utf-8")
        self.assertIn("otp_enabled", sql)
        self.assertIn("biometric_mode", sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS experiment_campaigns", sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS experiment_runs", sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS authentication_experiment_logs", sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS chained_experiment_runs", sql)
        self.assertIn("task_auth_attempt_id", sql)
        self.assertIn("resource_metrics JSONB", sql)
        self.assertIn("uq_auth_experiment_cell", sql)

    def test_upgrade_adds_all_runtime_biometric_columns_to_legacy_users(self):
        for relative_path in (
            "database/sql/tables.sql",
            "database/sql/migrate_v2_scientific.sql",
        ):
            sql = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS biometric_template TEXT",
                sql,
            )
            self.assertIn(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS biometric_mode VARCHAR(32)",
                sql,
            )

    def test_user_management_never_stores_generated_otp_as_user_secret(self):
        source = (ROOT / "admin" / "user_management.py").read_text(encoding="utf-8")
        self.assertNotIn("generate_otp", source)
        self.assertNotIn("SET otp_secret = %s", source)
        self.assertIn("otp_enabled = TRUE", source)

    def test_migrator_loads_and_verifies_the_local_v2_schema(self):
        source = (ROOT / "database" / "auto_migrator.py").read_text(encoding="utf-8")
        self.assertIn('SCHEMA_PATH = Path(__file__).resolve().parent / "sql" / "tables.sql"', source)
        self.assertIn("_schema_gaps(cursor)", source)
        self.assertIn("Database schema is up to date and verified", source)
        legacy_import = "from " + "SDNMFA"
        self.assertNotIn(legacy_import, source)

    def test_project_has_no_ambiguous_legacy_package_imports(self):
        offenders = []
        legacy_import = "from " + "SDNMFA"
        for path in ROOT.rglob("*.py"):
            if legacy_import in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
