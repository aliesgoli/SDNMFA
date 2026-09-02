#!/usr/bin/env python3
"""Read-only readiness check for the SDNMFA laboratory."""

import argparse
import importlib
import os
import secrets
import shutil
import stat
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root_text = str(PROJECT_ROOT)
while project_root_text in sys.path:
    sys.path.remove(project_root_text)
sys.path.insert(0, project_root_text)
os.environ.setdefault("MPLCONFIGDIR", "/tmp/sdnmfa_matplotlib_cache")

from config.runtime_security import secret_validation_error

REQUIRED_COMMANDS = [
    "curl",
    "ip",
    "mn",
    "mnexec",
    "ovs-appctl",
    "ovs-vsctl",
    "ping",
    "psql",
    "python3",
    "ryu-manager",
    "sysctl",
    "tcpdump",
]
REQUIRED_MODULES = [
    ("arabic_reshaper", "arabic-reshaper"),
    ("bidi", "python-bidi"),
    ("cryptography", "cryptography"),
    ("dns", "dnspython"),
    ("eventlet", "eventlet"),
    ("dotenv", "python-dotenv"),
    ("matplotlib", "matplotlib"),
    ("pbr", "pbr"),
    ("psycopg2", "psycopg2-binary"),
    ("psutil", "psutil"),
    ("reportlab", "reportlab"),
    ("ryu", "ryu"),
    ("setuptools", "setuptools"),
    ("webob", "webob"),
    ("wheel", "wheel"),
]
# Mininet is normally installed by the operating-system package rather than
# from this project's pip requirements.  The virtual environment must expose
# that system binding (created with ``--system-site-packages`` on the reference
# platform), otherwise topology.py fails only after the laboratory is started.
REQUIRED_SYSTEM_MODULES = [
    ("mininet", "Mininet Python bindings"),
]
USERS_COLUMNS = {
    "username",
    "password_hash",
    "biometric_template",
    "biometric_mode",
    "otp_enabled",
    "last_login",
    "updated_at",
    "password_scheme", "failed_attempts", "locked_until",
    "biometric_threshold", "is_experiment_user", "experiment_cohort",
    "password_class",
}
AUTH_COLUMNS = {
    "username",
    "event_type",
    "auth_logs_details",
    "timestamp",
    "success",
    "run_id",
    "attempt_id",
    "mfa_mode",
}
OTP_COLUMNS = {
    "id",
    "username",
    "otp_hash",
    "created_at",
    "expires_at",
    "used",
    "run_id",
    "attempt_id",
    "failed_attempts",
    "invalidated_reason",
}
ATTACK_COLUMNS = {
    "username",
    "attack_type",
    "target_host",
    "target_port",
    "duration_seconds",
    "rate_pps",
    "threads",
    "mfa_mode",
    "attack_params",
    "attack_result",
    "success",
    "start_time",
    "end_time",
    "run_id",
    "attempt_id",
    "actual_mechanism",
    "is_valid",
    "execution_status",
    "security_outcome",
    "error_type",
    "authorized_at",
    "authorization_expires_at",
    "authorization_in_port",
    "authorization_dpid",
    "legitimate_before",
    "legitimate_after",
    "campaign_id",
    "task_id",
    "sample_id",
    "repetition",
    "intensity_level",
    "binding_profile",
    "topology_id",
    "resource_metrics",
    "pcap_evidence",
}

CAMPAIGN_COLUMNS = {
    "campaign_id",
    "study_id",
    "protocol_id",
    "schema_version",
    "seed",
    "scenario",
    "topology_id",
    "binding_profile",
    "repetitions",
    "manifest",
    "manifest_sha256",
    "status",
}

EXPERIMENT_RUN_COLUMNS = {
    "task_id",
    "campaign_id",
    "sample_id",
    "run_id",
    "task_auth_attempt_id",
    "experiment_username",
    "scenario",
    "intensity_level",
    "repetition",
    "mfa_mode",
    "binding_profile",
    "topology_id",
    "sampled_parameters",
    "observed_result",
    "execution_status",
    "is_valid",
}

AUTH_EXPERIMENT_COLUMNS = {
    "campaign_id", "study_id",
    "run_id",
    "username",
    "scenario",
    "mfa_mode",
    "repetition",
    "supplied_factors",
    "authentication_succeeded",
    "latency_ms",
    "resource_metrics",
    "attack_family", "attack_variant", "intensity_level",
    "expected_success", "biometric_score", "biometric_threshold", "is_valid",
}

STUDY_COLUMNS = {
    "study_id", "protocol_id", "implementation_revision", "base_seed",
    "repetitions", "expected_topologies", "design_config", "status",
}

TOPOLOGY_EXECUTION_COLUMNS = {
    "execution_id", "study_id", "topology_id", "status",
    "expected_network_runs", "completed_network_runs", "valid_network_runs",
    "auth_study_completed",
}

CHAINED_RUN_COLUMNS = {
    "chain_id", "study_id", "block_id", "base_task_id", "run_id",
    "auth_attempt_id", "experiment_username", "auth_attack_variant",
    "intensity_level", "mfa_mode", "binding_profile", "network_scenario",
    "topology_id", "repetition", "sampled_parameters", "factor_state",
    "authentication_succeeded", "expected_authentication_success",
    "authentication_latency_ms", "authentication_metrics",
    "network_stage_status", "network_result", "resource_metrics",
    "pcap_evidence", "chain_outcome", "execution_status", "is_valid",
}


def find_command(command: str):
    """Resolve both system commands and scripts beside the active Python."""
    candidates = [
        shutil.which(command),
        str(Path(sys.executable).parent / command),
        str(PROJECT_ROOT / "venv" / "bin" / command),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


class Results:
    def __init__(self):
        self.failures = 0
        self.warnings = 0

    def ok(self, message):
        print("[PASS] %s" % message)

    def fail(self, message):
        self.failures += 1
        print("[FAIL] %s" % message)

    def warn(self, message):
        self.warnings += 1
        print("[WARN] %s" % message)


def check_database(results: Results) -> None:
    os.environ["SDNMFA_NONINTERACTIVE"] = "1"
    try:
        from database.db_config import get_db_connection, release_db_connection
    except Exception as exc:
        results.fail("Database module could not be imported: %s" % exc)
        return
    conn = get_db_connection()
    if not conn:
        results.fail("PostgreSQL connection failed")
        return
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT table_name, column_name
                FROM information_schema.columns
                WHERE table_schema='public'
                  AND table_name IN (
                      'users', 'auth_logs', 'otp_sessions', 'attack_logs',
                      'experiment_campaigns', 'experiment_runs',
                      'authentication_experiment_logs', 'thesis_studies',
                      'topology_executions', 'chained_experiment_runs'
                  )
                """
            )
            columns = {
                "users": set(),
                "auth_logs": set(),
                "otp_sessions": set(),
                "attack_logs": set(),
                "experiment_campaigns": set(),
                "experiment_runs": set(),
                "authentication_experiment_logs": set(),
                "thesis_studies": set(),
                "topology_executions": set(),
                "chained_experiment_runs": set(),
            }
            for table, column in cursor.fetchall():
                columns[table].add(column)
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='pgcrypto')"
            )
            pgcrypto_available = bool(cursor.fetchone()[0])
        missing_users = sorted(USERS_COLUMNS - columns["users"])
        missing_auth = sorted(AUTH_COLUMNS - columns["auth_logs"])
        missing_otp = sorted(OTP_COLUMNS - columns["otp_sessions"])
        missing_attack = sorted(ATTACK_COLUMNS - columns["attack_logs"])
        missing_campaign = sorted(CAMPAIGN_COLUMNS - columns["experiment_campaigns"])
        missing_runs = sorted(EXPERIMENT_RUN_COLUMNS - columns["experiment_runs"])
        missing_auth_experiment = sorted(
            AUTH_EXPERIMENT_COLUMNS - columns["authentication_experiment_logs"]
        )
        missing_study = sorted(STUDY_COLUMNS - columns["thesis_studies"])
        missing_topology_execution = sorted(
            TOPOLOGY_EXECUTION_COLUMNS - columns["topology_executions"]
        )
        missing_chained_runs = sorted(
            CHAINED_RUN_COLUMNS - columns["chained_experiment_runs"]
        )
        if (
            missing_users
            or missing_auth
            or missing_otp
            or missing_attack
            or missing_campaign
            or missing_runs
            or missing_auth_experiment
            or missing_study
            or missing_topology_execution
            or missing_chained_runs
        ):
            results.fail(
                "Schema migration is required; missing users=%s auth=%s otp=%s attack=%s campaigns=%s runs=%s auth_experiment=%s studies=%s topology_executions=%s chained_runs=%s"
                % (
                    missing_users,
                    missing_auth,
                    missing_otp,
                    missing_attack,
                    missing_campaign,
                    missing_runs,
                    missing_auth_experiment,
                    missing_study,
                    missing_topology_execution,
                    missing_chained_runs,
                )
            )
        else:
            results.ok("PostgreSQL schema contains the experiment-tracking fields")
        if pgcrypto_available:
            results.ok("PostgreSQL pgcrypto extension is available")
        else:
            results.fail("PostgreSQL pgcrypto extension is missing")
    except Exception as exc:
        results.fail("Database schema check failed: %s" % exc)
    finally:
        release_db_connection(conn)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-db", action="store_true")
    args = parser.parse_args(argv)
    results = Results()

    if sys.version_info[:2] != (3, 9):
        results.fail(
            "Python 3.9 is required by the validated Ryu compatibility profile; found %s"
            % sys.version.split()[0]
        )
    else:
        results.ok("Python version: %s" % sys.version.split()[0])

    for command in REQUIRED_COMMANDS:
        path = find_command(command)
        if path:
            results.ok("Command available: %s" % command)
        else:
            results.fail("Required command is missing: %s" % command)
    for module, package in REQUIRED_MODULES:
        try:
            importlib.import_module(module)
            results.ok("Python dependency available: %s" % package)
        except Exception as exc:
            results.fail("Python dependency failed: %s (%s)" % (package, exc))
    for module, label in REQUIRED_SYSTEM_MODULES:
        try:
            importlib.import_module(module)
            results.ok("System Python dependency available: %s" % label)
        except Exception as exc:
            results.fail(
                "%s is not importable from this interpreter (%s). "
                "Install Mininet for Python 3.9 and create or upgrade the virtual "
                "environment with --system-site-packages."
                % (label, exc)
            )

    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        results.fail(".env is missing; copy .env.example and configure it")
    else:
        permissions = stat.S_IMODE(env_path.stat().st_mode)
        if permissions & 0o077:
            results.fail(".env permissions are too broad; run chmod 600 .env")
        else:
            results.ok(".env permissions do not grant group/other access")
        try:
            from dotenv import load_dotenv

            load_dotenv(str(env_path))
            missing = [
                key
                for key in (
                    "DB_NAME",
                    "DB_USER",
                    "DB_PASSWORD",
                    "BIOMETRIC_PEPPER",
                    "OTP_PEPPER",
                    "EXPERIMENT_MASTER_SECRET",
                    "CONTROLLER_API_TOKEN",
                )
                if not os.getenv(key)
            ]
            if missing:
                results.fail("Missing .env variables: %s" % ", ".join(missing))
            else:
                weak = []
                secret_keys = (
                    "BIOMETRIC_PEPPER", "OTP_PEPPER",
                    "EXPERIMENT_MASTER_SECRET", "CONTROLLER_API_TOKEN",
                )
                for key in secret_keys:
                    value = str(os.getenv(key) or "")
                    error = secret_validation_error(value)
                    if error:
                        weak.append("%s (%s)" % (key, error))
                if weak:
                    results.fail(
                        "Security secrets failed the length, placeholder, or character-diversity policy: %s"
                        % ", ".join(weak)
                    )
                elif len({str(os.getenv(key)) for key in secret_keys}) != len(secret_keys):
                    results.fail(
                        "All biometric, OTP, experiment, and API secrets must be independent"
                    )
                else:
                    results.ok("Required .env variables and independent secrets are configured")
        except Exception as exc:
            results.fail(".env could not be checked: %s" % exc)

    if not args.skip_db:
        check_database(results)
    print("\nSummary: %s failure(s), %s warning(s)" % (results.failures, results.warnings))
    return 1 if results.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
