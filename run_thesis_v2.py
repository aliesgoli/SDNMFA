#!/usr/bin/env python3
"""Run one complete SDN-MFA v2 topology study from a single command."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent
while str(PROJECT_ROOT) in sys.path:
    sys.path.remove(str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT))

from config.experiment_protocol import (
    DEFAULT_REPETITIONS,
    IMPLEMENTATION_REVISION,
    PROTOCOL_ID,
)
from config.topology_profiles import TOPOLOGY_PROFILES
from controller.mfa_controller import _ryu_request, main as campaign_main
from database.auto_migrator import auto_migrate
from experiments.authentication_study_v2 import run_authentication_study
from experiments.chained_protocol import expected_chained_runs_per_topology
from experiments.chained_storage import ChainedStore
from experiments.chained_study_v2 import run_chained_study
from experiments.study import StudyStore, THESIS_TOPOLOGIES
from experiments.synthetic_users import (
    DEFAULT_COHORT,
    build_user_profiles,
    provision_experiment_users,
)
from tools.preflight_check import main as preflight_main


DEFAULT_STUDY_SEED = 20260822
RYU_LOG = PROJECT_ROOT / "logs" / "ryu_v2.log"


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--topology", choices=THESIS_TOPOLOGIES, required=True,
        help="Run exactly one of the three thesis topologies.",
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_STUDY_SEED)
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument("--capture-pcap", action="store_true")
    parser.add_argument("--cooldown", type=float, default=0.25)
    parser.add_argument(
        "--phase",
        choices=("complete", "factorial", "chained"),
        default="complete",
        help=(
            "complete runs/resumes both studies; factorial runs only the "
            "independent matrix; chained runs only the end-to-end matrix"
        ),
    )
    parser.add_argument(
        "--refresh-experiment-users", action="store_true",
        help="Replace only the scoped synthetic v2 cohort before execution.",
    )
    parser.add_argument(
        "--skip-authentication-study", action="store_true",
        help="Skip only for diagnostics; the final report will remain incomplete.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print the deterministic study plan without changing the database/network.",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.repetitions <= 30:
        parser.error("--repetitions must be between 1 and 30")
    if not 0 <= args.seed <= 2**63 - 1:
        parser.error("--seed must be between 0 and 2^63-1")
    if not 0.0 <= args.cooldown <= 10.0:
        parser.error("--cooldown must be between 0 and 10 seconds")
    return args


def _plan(args: argparse.Namespace) -> Dict[str, Any]:
    per_topology = 4 * 4 * 6 * 3 * int(args.repetitions)
    auth_observations = 14 * 3 * 4 * int(args.repetitions)
    chained_per_topology = expected_chained_runs_per_topology(args.repetitions)
    return {
        "protocol_id": PROTOCOL_ID,
        "implementation_revision": IMPLEMENTATION_REVISION,
        "topology": args.topology,
        "all_topologies": list(THESIS_TOPOLOGIES),
        "seed": args.seed,
        "repetitions": args.repetitions,
        "network_runs_this_command": per_topology,
        "network_runs_complete_study": per_topology * len(THESIS_TOPOLOGIES),
        "unique_network_cells_complete_study": 4 * 4 * 6 * 3 * len(THESIS_TOPOLOGIES),
        "authentication_observations": auth_observations,
        "chained_runs_this_command": (
            chained_per_topology if args.phase in {"complete", "chained"} else 0
        ),
        "chained_runs_complete_study": chained_per_topology * len(THESIS_TOPOLOGIES),
        "phase": args.phase,
        "experiment_users": 500,
    }


def _cohort_count() -> int:
    from database.db_config import get_db_connection, release_db_connection

    conn = get_db_connection()
    if conn is None:
        raise RuntimeError("Database connection is unavailable")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) FROM users
                WHERE is_experiment_user=TRUE AND experiment_cohort=%s
                """,
                (DEFAULT_COHORT,),
            )
            return int(cur.fetchone()[0] or 0)
    finally:
        release_db_connection(conn)


def _controller_status() -> Tuple[bool, Dict[str, Any]]:
    ok, status = _ryu_request("/sdnmfa/status", "GET", timeout=1.0)
    compatible = bool(
        ok
        and status.get("protocol_id") == PROTOCOL_ID
        and status.get("implementation_revision") == IMPLEMENTATION_REVISION
    )
    return compatible, status


def _start_controller() -> Tuple[Optional[subprocess.Popen], Any]:
    compatible, status = _controller_status()
    if compatible:
        print("Using the already-running compatible SDN-MFA-V2 controller")
        return None, None
    ryu_manager = shutil.which("ryu-manager") or str(
        Path(sys.executable).parent / "ryu-manager"
    )
    if not Path(ryu_manager).is_file():
        raise RuntimeError("ryu-manager was not found beside the active Python")
    RYU_LOG.parent.mkdir(parents=True, exist_ok=True)
    log_handle = RYU_LOG.open("a", encoding="utf-8")
    process = subprocess.Popen(
        [
            ryu_manager,
            "--wsapi-host", "127.0.0.1",
            "--ofp-listen-host", "127.0.0.1",
            str(PROJECT_ROOT / "config" / "security_controller.py"),
            "--observe-links",
        ],
        cwd=str(PROJECT_ROOT),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    deadline = time.monotonic() + 30.0
    last_status: Dict[str, Any] = status
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log_handle.close()
            raise RuntimeError(
                "Ryu controller exited during startup; inspect %s" % RYU_LOG
            )
        compatible, last_status = _controller_status()
        if compatible:
            return process, log_handle
        time.sleep(0.25)
    process.terminate()
    process.wait(timeout=5)
    log_handle.close()
    raise RuntimeError(
        "Compatible controller did not become ready: %s" % last_status
    )


def _stop_controller(process: Optional[subprocess.Popen], log_handle: Any) -> None:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    if log_handle is not None:
        log_handle.close()


def main(argv=None) -> int:
    args = _parse_args(argv)
    plan = _plan(args)
    print(json.dumps(plan, indent=2, sort_keys=True))
    if args.dry_run:
        return 0
    if os.geteuid() != 0:
        print("This command must run with sudo -E because Mininet creates namespaces.")
        return 1

    # Dependency/environment checks are read-only. Migration is additive and
    # runs before the database-aware part of the preflight.
    if preflight_main(["--skip-db"]) != 0:
        return 1
    if not auto_migrate():
        return 1
    if preflight_main([]) != 0:
        return 1

    if args.refresh_experiment_users or _cohort_count() < 500:
        print("Preparing the isolated 500-user experiment cohort...")
        result = provision_experiment_users(
            count=500,
            cohort=DEFAULT_COHORT,
            replace_cohort=args.refresh_experiment_users,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("The isolated 500-user experiment cohort is ready")

    study_store = StudyStore()
    study_id = study_store.register(
        base_seed=args.seed,
        repetitions=args.repetitions,
        topologies=THESIS_TOPOLOGIES,
    )
    study_store.start_topology(study_id, args.topology, args.repetitions)
    print("Study ID: %s" % study_id)

    if (
        not args.skip_authentication_study
        and not study_store.authentication_study_exists(study_id)
    ):
        print("Running the controlled authentication-factor attack study...")
        auth_summary = run_authentication_study(
            study_id=study_id,
            base_seed=args.seed,
            repetitions=args.repetitions,
            users=build_user_profiles(500),
        )
        print(json.dumps(auth_summary, indent=2, sort_keys=True))
        study_store.mark_authentication_complete(study_id, args.topology)
    elif not args.skip_authentication_study:
        print("Authentication-factor study is already complete; resuming network work")
        study_store.mark_authentication_complete(study_id, args.topology)

    controller_process: Optional[subprocess.Popen] = None
    controller_log = None
    network = None
    campaign_exit = 0
    chain_summary: Optional[Dict[str, Any]] = None
    try:
        controller_process, controller_log = _start_controller()
        from config.topology import create_topology

        network = create_topology(args.topology, open_cli=False)
        if args.phase in {"complete", "factorial"}:
            campaign_args = [
                "--all-scenarios", "--all-bindings", "--repetitions",
                str(args.repetitions), "--seed", str(args.seed),
                "--cooldown", str(args.cooldown), "--yes", "--study-id", study_id,
            ]
            if args.capture_pcap:
                campaign_args.append("--capture-pcap")
            campaign_exit = campaign_main(campaign_args)

        factorial_progress = study_store.refresh_topology(study_id, args.topology)
        if args.phase == "chained" and factorial_progress.get("status") != "completed":
            raise RuntimeError(
                "The independent network matrix for this topology must be complete "
                "before the chained phase starts"
            )
        if args.phase in {"complete", "chained"} and campaign_exit == 0:
            from controller.mfa_controller import _load_mininet_ctx

            print("Starting/resuming the end-to-end chained study...")
            chain_summary = run_chained_study(
                study_id=study_id,
                topology_id=args.topology,
                base_seed=args.seed,
                repetitions=args.repetitions,
                users=build_user_profiles(500),
                mn=_load_mininet_ctx(),
                capture_pcap=args.capture_pcap,
                cooldown_seconds=args.cooldown,
            )
            print(json.dumps(chain_summary, indent=2, sort_keys=True))
            if int(chain_summary.get("technical_errors") or 0) > 0:
                campaign_exit = 2
    finally:
        if network is not None:
            network.stop()
        _stop_controller(controller_process, controller_log)
        cleanup = shutil.which("mn")
        if cleanup:
            subprocess.run([cleanup, "-c"], check=False, timeout=30)

    progress = study_store.refresh_topology(study_id, args.topology)
    print(json.dumps(progress, indent=2, sort_keys=True))
    try:
        from analysis.article_report_v2 import generate_study_report

        complete_factorial = (
            int(progress.get("completed_topology_count") or 0)
            == len(THESIS_TOPOLOGIES)
        )
        expected_chains = expected_chained_runs_per_topology(args.repetitions)
        chain_store = ChainedStore()
        chain_progress = {
            topology_id: chain_store.progress(study_id, topology_id, expected_chains)
            for topology_id in THESIS_TOPOLOGIES
        }
        complete_chained = all(
            item["valid"] == item["expected"]
            and item["technical_errors"] == 0
            for item in chain_progress.values()
        )
        strict_report = complete_factorial and complete_chained
        report = generate_study_report(
            study_id=study_id,
            strict=strict_report,
        )
        print(
            "%s report: %s"
            % ("Final strict" if strict_report else "Current partial", report["pdf_fa"])
        )
    except Exception as exc:
        print("Report generation warning: %s" % exc)
        if campaign_exit == 0:
            campaign_exit = 2
    return int(campaign_exit)


if __name__ == "__main__":
    raise SystemExit(main())
