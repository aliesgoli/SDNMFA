import csv
import hashlib
import io
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from analysis.evidence_export import (
    DEFAULT_EXPECTED_POLICIES,
    RUN_FIELDNAMES,
    compute_checksum_inventory,
    export_evidence_package,
    flatten_authentication_observations,
    flatten_experiment_run,
    flatten_probe_samples,
    flatten_resource_samples,
    normalize_large_seeds,
    summarize_sample_blocks,
    student_t_summary,
)
from experiments.campaign import manifest_digest


LARGE_SEED = 2**63 - 1


def campaign_fixture():
    manifest = {"seed": LARGE_SEED, "tasks": []}
    manifest["manifest_sha256"] = manifest_digest(manifest)
    return {
        "campaign_id": "campaign-1",
        "protocol_id": "sdnmfa-exp-v2-final",
        "seed": LARGE_SEED,
        "manifest": manifest,
        "manifest_sha256": manifest["manifest_sha256"],
        "authentication_runs": [
            {
                "campaign_id": "campaign-1",
                "run_id": "auth-run-1",
                "username": "private-user",
                "password": "private-password",
                "otp_code": "123456",
                "biometric_data": "private-biometric",
                "scenario": "valid_factors",
                "mfa_mode": "password_otp_biometric",
                "repetition": 1,
                "supplied_factors": {
                    "required": ["password", "otp", "biometric"],
                    "supplied": ["password", "otp", "biometric"],
                    "simulation": "software_factor_availability",
                },
                "authentication_succeeded": True,
                "latency_ms": 12.5,
                "message": "message that is deliberately not exported",
                "resource_metrics": {
                    "process_pid": 123,
                    "process_label": "mfa_verifier",
                    "cpu_seconds": 0.01,
                    "cpu_percent_equivalent": 8.0,
                    "rss_before_bytes": 1000,
                    "rss_after_bytes": 1100,
                    "rss_delta_bytes": 100,
                },
            }
        ],
    }


def run_fixture(
    sample_id="sample-1",
    policy="password_only",
    position=1,
    valid=True,
    error_type=None,
    pcap=None,
    include_resource_samples=True,
):
    availability_samples = [
        {"phase": "baseline", "sample_index": 1, "accessible": True, "elapsed_ms": 4.0},
        {"phase": "baseline", "sample_index": 2, "accessible": False, "elapsed_ms": 5.0},
        {"phase": "during", "sample_index": 1, "accessible": False, "elapsed_ms": 6.0},
        {"phase": "during", "sample_index": 2, "accessible": False, "elapsed_ms": 7.0},
        {"phase": "recovery", "sample_index": 1, "accessible": True, "elapsed_ms": 4.5},
        {"phase": "recovery", "sample_index": 2, "accessible": True, "elapsed_ms": 4.2},
    ]
    attack_samples = [
        {"sample_index": index, "accessible": index == 1, "timed_out": index == 4, "elapsed_ms": 10 + index}
        for index in range(1, 5)
    ]
    metrics = {
        "protocol_id": "sdnmfa-exp-v2-final",
        "campaign_id": "campaign-1",
        "task_id": "%s-%s" % (sample_id, policy),
        "sample_id": sample_id,
        "run_id": "run-%s-%s" % (sample_id, policy),
        "attack_type": "dos_udp_flood",
        "mode": policy,
        "intensity_level": "low",
        "repetition": 1,
        "actual_mechanism": "udp_flood_single_source",
        "execution_status": "completed" if valid else "technical_error",
        "is_valid": valid,
        "security_outcome": "availability_preserved" if valid else "not_evaluable",
        "error_type": error_type,
        "preflight": {
            "legitimate_rate": 1.0,
            "legitimate_samples": [
                {"phase": "legitimate_before", "sample_index": 1, "accessible": True, "elapsed_ms": 3.5}
            ],
        },
        "postflight": {
            "rate": 1.0,
            "samples": [
                {"phase": "recovery", "sample_index": 1, "accessible": True, "elapsed_ms": 4.5}
            ],
        },
        "attack_probe": {
            "accessible": True,
            "attempt_count": 4,
            "successful_attempts": 1,
            "blocked_or_failed_attempts": 3,
            "timed_out_attempts": 1,
            "actual_request_rate": 3.75,
            "latency_mean_ms": 12.5,
            "latency_p95_ms": 14.0,
            "return_code": 0,
            "samples": attack_samples,
        },
        "availability_samples": availability_samples,
        "baseline_availability_rate": 0.5,
        "during_availability_rate": 0.0,
        "recovery_availability_rate": 1.0,
        "target_rate_pps": 100,
        "actual_rate_pps": 90.0,
        "rate_achievement_percent": 90.0,
        "packets_sent": 900,
        "bytes_sent": 57600,
        "send_errors": 0,
        "packets_received": 850,
        "bytes_received": 54400,
        "packet_delivery_percent": 94.444,
        "receiver_evidence_valid": True,
        "receiver_result": {
            "return_code": 0,
            "duration_seconds": 10.0,
            "actual_receive_rate_pps": 85.0,
            "packets_received": 850,
            "bytes_received": 54400,
            "stderr": "",
        },
        "controller_deny_evidence": {
            "available": True,
            "count": 2,
            "events": [
                {"reason": "binding_mismatch", "dpid": 1, "in_port": 3},
                {"reason": "binding_mismatch", "dpid": 1, "in_port": 3},
            ],
            "error": None,
        },
    }
    if not valid:
        metrics["restore_error"] = "identity restoration failed"
        metrics["monitor_error"] = "monitor stopped"
    resource = {
        "sample_count": 2,
        "interval_seconds": 0.2,
        "process_pid": 777,
        "process_label": "ryu_controller",
        "process_cpu_percent": {"mean": 5.0, "p95": 7.5, "max": 8.0},
        "process_rss_bytes": {"mean": 1000, "p95": 1100, "max": 1200},
        "system_cpu_percent": {"mean": 20.0, "p95": 25.0, "max": 30.0},
        "system_memory_percent": {"mean": 50.0, "p95": 51.0, "max": 52.0},
    }
    if include_resource_samples:
        resource["samples"] = [
            {
                "elapsed_seconds": 0.2,
                "process_cpu_percent": 4.0,
                "process_rss_bytes": 1000,
                "system_cpu_percent": 19.0,
                "system_memory_percent": 50.0,
            },
            {
                "elapsed_seconds": 0.4,
                "process_cpu_percent": 6.0,
                "process_rss_bytes": 1100,
                "system_cpu_percent": 21.0,
                "system_memory_percent": 50.5,
            },
        ]
    observed = {
        "success": False,
        "message": "valid result" if valid else "technical failure",
        "metrics": metrics,
    }
    return {
        "campaign_id": "campaign-1",
        "task_id": metrics["task_id"],
        "sample_id": sample_id,
        "run_id": metrics["run_id"],
        "operator_attempt_id": "operator-attempt",
        "task_auth_attempt_id": "task-auth-attempt",
        "scenario": "dos_udp_flood",
        "intensity_level": "low",
        "repetition": 1,
        "policy_position": position,
        "mfa_mode": policy,
        "binding_profile": "ip_mac_port",
        "topology_id": "tree-medium",
        "execution_status": metrics["execution_status"],
        "is_valid": valid,
        "sampled_parameters": {
            "target_host": "10.0.0.2",
            "target_port": 18080,
            "duration_seconds": 10,
            "rate_pps": 100,
            "request_count": None,
            "worker_count": 1,
            "source_count": 1,
            "payload_size_bytes": 64,
            "offered_load_ratio": 0.1,
        },
        "observed_result": observed,
        "resource_metrics": resource,
        "pcap_evidence": pcap or {"enabled": False},
    }


class EvidenceExportTests(unittest.TestCase):
    def test_flatten_current_shape_preserves_observed_metrics(self):
        row = flatten_experiment_run(run_fixture(), campaign_fixture())
        self.assertEqual(tuple(row), RUN_FIELDNAMES)
        self.assertEqual(row["campaign_seed"], str(LARGE_SEED))
        self.assertEqual(row["configured_rate_pps"], 100)
        self.assertEqual(row["achieved_rate_pps"], 90)
        self.assertEqual(row["rate_achievement_percent"], 90)
        self.assertEqual(row["attack_probe_count"], 4)
        self.assertEqual(row["attack_probe_successes"], 1)
        self.assertEqual(row["attack_probe_unsuccessful_count"], 3)
        self.assertEqual(row["attack_probe_loss_percent"], 75.0)
        self.assertEqual(row["baseline_probe_count"], 2)
        self.assertEqual(row["baseline_probe_successes"], 1)
        self.assertEqual(row["baseline_probe_loss_count"], 1)
        self.assertEqual(row["during_availability_rate"], 0.0)
        self.assertEqual(row["recovery_availability_rate"], 1.0)
        self.assertEqual(row["receiver_status"], "valid")
        self.assertEqual(row["deny_event_count"], 2)
        self.assertEqual(json.loads(row["deny_reasons_json"]), ["binding_mismatch"])
        self.assertEqual(row["process_cpu_p95_percent"], 7.5)
        self.assertIsNone(row["error_message"])

    def test_successful_restoration_evidence_is_not_a_cleanup_error(self):
        run = run_fixture()
        metrics = run["observed_result"]["metrics"]
        metrics.update(
            {
                "restoration_verified": True,
                "restored_arp_state": {
                    "verified": True,
                    "h1_to_h2": {"state": "PERMANENT"},
                },
                "arp_restored_state": {
                    "verified": True,
                    "h2_to_h1": {"state": "PERMANENT"},
                },
            }
        )

        row = flatten_experiment_run(run, campaign_fixture())

        self.assertEqual(json.loads(row["cleanup_errors_json"]), [])

    def test_failed_restoration_and_real_cleanup_errors_are_preserved(self):
        run = run_fixture()
        metrics = run["observed_result"]["metrics"]
        metrics.update(
            {
                "restoration_verified": False,
                "restored_arp_state": {"verified": False},
                "cleanup_warning": "capture process required forced termination",
            }
        )

        row = flatten_experiment_run(run, campaign_fixture())
        errors = json.loads(row["cleanup_errors_json"])

        self.assertEqual(
            {item["field"] for item in errors},
            {
                "metrics.cleanup_warning",
                "metrics.restoration_verified",
                "metrics.restored_arp_state",
            },
        )

    def test_flatten_legacy_json_and_missing_values_without_zero_fill(self):
        legacy = {
            "task_id": "legacy-task",
            "sample_id": "legacy-sample",
            "mfa_mode": "password_only",
            "sampled_parameters": json.dumps({"duration_s": 4, "rate_pps": 9}),
            "observed_result": json.dumps(
                {
                    "success": False,
                    "metrics": {
                        "is_valid": True,
                        "execution_status": "completed",
                        "security_outcome": "attack_blocked",
                        "preflight": {
                            "legitimate_rate": 0.5,
                            "legitimate_samples": [
                                {"accessible": True},
                                {"accessible": False},
                            ],
                        },
                        "postflight": {"rate": 0.75},
                        "resource_metrics": {
                            "cpu_percent_equivalent": 3.25,
                            "process_cpu_percent": {"p95": 4.0},
                        },
                        "pcap_evidence": {
                            "capture_enabled": True,
                            "file_path": "/missing/legacy.pcap",
                            "checksum": "b" * 64,
                            "bytes": 12,
                        },
                    },
                }
            ),
        }
        row = flatten_experiment_run(legacy, {"seed": LARGE_SEED})
        self.assertEqual(row["configured_duration_seconds"], 4)
        self.assertEqual(row["baseline_availability_rate"], 0.5)
        self.assertEqual(row["baseline_probe_count"], 2)
        self.assertEqual(row["recovery_availability_rate"], 0.75)
        self.assertIsNone(row["during_availability_rate"])
        self.assertIsNone(row["attack_probe_count"])
        self.assertIsNone(row["packets_sent"])
        self.assertIsNone(row["receiver_status"])
        self.assertEqual(row["legacy_cpu_percent_equivalent"], 3.25)
        self.assertEqual(row["process_cpu_p95_percent"], 4.0)
        self.assertEqual(row["pcap_path"], "/missing/legacy.pcap")
        self.assertEqual(row["pcap_size_bytes"], 12)

    def test_large_integer_counts_are_never_rounded_through_float(self):
        run = run_fixture()
        exact = 2**53 + 1
        run["observed_result"]["metrics"]["packets_sent"] = exact
        row = flatten_experiment_run(run, campaign_fixture())
        self.assertEqual(row["packets_sent"], exact)

    def test_seed_normalization_is_key_scoped(self):
        normalized = normalize_large_seeds(
            {"seed": LARGE_SEED, "random_seed": LARGE_SEED, "packets_sent": LARGE_SEED}
        )
        self.assertEqual(normalized["seed"], str(LARGE_SEED))
        self.assertEqual(normalized["random_seed"], str(LARGE_SEED))
        self.assertEqual(normalized["packets_sent"], LARGE_SEED)

    def test_block_summary_uses_only_complete_fully_valid_blocks(self):
        runs = []
        for sample_index in (1, 2):
            for position, policy in enumerate(DEFAULT_EXPECTED_POLICIES, start=1):
                invalid = sample_index == 2 and policy == "password_otp_biometric"
                runs.append(
                    run_fixture(
                        sample_id="sample-%s" % sample_index,
                        policy=policy,
                        position=position,
                        valid=not invalid,
                        error_type="flood_receiver_failed" if invalid else None,
                        include_resource_samples=False,
                    )
                )
        summary = summarize_sample_blocks(runs, campaign=campaign_fixture())
        self.assertEqual(summary["unit"], "sample_id")
        self.assertEqual(summary["total_blocks"], 2)
        self.assertEqual(summary["complete_blocks"], 2)
        self.assertEqual(summary["fully_valid_blocks"], 1)
        self.assertEqual(summary["blocks_with_invalid_runs"], 1)
        self.assertEqual(summary["invalid_runs"], 1)
        self.assertEqual(summary["invalid_runs_by_error_type"], {"flood_receiver_failed": 1})
        baseline = next(
            row for row in summary["metric_rows"]
            if row["metric"] == "baseline_availability_rate"
        )
        self.assertEqual(baseline["n_blocks"], 1)
        self.assertEqual(baseline["mean"], 0.5)
        self.assertTrue(all(row["n_blocks"] == 1 for row in summary["policy_rows"]))
        invalid = summary["invalid_run_rows"][0]
        self.assertEqual(invalid["error_type"], "flood_receiver_failed")
        self.assertIn("identity restoration failed", invalid["restoration_error"])

    def test_inconsistent_paired_parameters_exclude_the_entire_block(self):
        runs = [
            run_fixture(policy=policy, position=position)
            for position, policy in enumerate(DEFAULT_EXPECTED_POLICIES, start=1)
        ]
        runs[0]["sampled_parameters"]["rate_pps"] = 999
        summary = summarize_sample_blocks(runs, campaign=campaign_fixture())
        self.assertEqual(summary["complete_blocks"], 1)
        self.assertEqual(summary["fully_valid_blocks"], 0)
        self.assertEqual(summary["blocks_with_inconsistent_parameters"], 1)
        self.assertFalse(summary["block_rows"][0]["paired_parameters_consistent"])

    def test_missing_outcome_is_not_an_adverse_valid_observation(self):
        run = run_fixture()
        run["observed_result"]["metrics"].pop("security_outcome")
        summary = summarize_sample_blocks([run], campaign=campaign_fixture())
        self.assertEqual(summary["valid_runs"], 0)
        self.assertEqual(summary["invalid_runs"], 1)

    def test_manifest_and_pcap_inventory_reports_present_missing_and_unverified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pcap_path = root / "capture.pcap"
            pcap_path.write_bytes(b"pcap evidence")
            pcap_digest = hashlib.sha256(b"pcap evidence").hexdigest()
            manifest = {"campaign_id": "campaign-1", "seed": 7, "tasks": []}
            manifest["manifest_sha256"] = manifest_digest(manifest)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
            campaign = {
                "campaign_id": "campaign-1",
                "manifest": manifest,
                "manifest_sha256": manifest["manifest_sha256"],
            }
            present = run_fixture(
                pcap={
                    "enabled": True,
                    "path": str(pcap_path),
                    "size_bytes": pcap_path.stat().st_size,
                    "sha256": pcap_digest,
                }
            )
            missing = run_fixture(
                sample_id="sample-2",
                pcap={
                    "enabled": True,
                    "path": str(root / "missing.pcap"),
                    "size_bytes": 10,
                    "sha256": "c" * 64,
                },
            )
            disabled = run_fixture(
                sample_id="sample-3", pcap={"enabled": False}
            )
            rows = compute_checksum_inventory(
                campaign,
                [present, missing, disabled],
                manifest_path=manifest_path,
            )
            self.assertEqual(len(rows), 4)
            manifest_row = rows[0]
            self.assertEqual(manifest_row["artifact_type"], "manifest")
            self.assertEqual(manifest_row["presence_status"], "present")
            self.assertEqual(manifest_row["checksum_status"], "verified")
            self.assertEqual(manifest_row["payload_checksum_status"], "verified")
            pcap_rows = {row["task_id"]: row for row in rows[1:]}
            self.assertEqual(
                pcap_rows[present["task_id"]]["presence_status"], "present"
            )
            self.assertEqual(
                pcap_rows[present["task_id"]]["checksum_status"], "verified"
            )
            self.assertEqual(
                pcap_rows[missing["task_id"]]["presence_status"], "missing"
            )
            self.assertEqual(
                pcap_rows[missing["task_id"]]["checksum_status"], "missing"
            )
            self.assertEqual(
                pcap_rows[disabled["task_id"]]["presence_status"], "unverified"
            )
            self.assertEqual(
                pcap_rows[disabled["task_id"]]["checksum_status"], "unverified"
            )

    def test_block_performance_summary_reports_uncertainty(self):
        runs = [
            run_fixture(
                sample_id="sample-%s" % sample_index,
                policy=policy,
                position=position,
            )
            for sample_index in (1, 2)
            for position, policy in enumerate(DEFAULT_EXPECTED_POLICIES, start=1)
        ]
        summary = summarize_sample_blocks(runs, campaign=campaign_fixture())
        baseline = next(
            row
            for row in summary["metric_rows"]
            if row["metric"] == "baseline_availability_rate"
        )
        self.assertEqual(baseline["n_blocks"], 2)
        self.assertEqual(baseline["standard_deviation"], 0.0)
        self.assertEqual(baseline["ci95_low"], 0.5)
        self.assertEqual(baseline["ci95_high"], 0.5)
        self.assertEqual(baseline["ci95_method"], "student_t_on_block_means")
        self.assertEqual(len(summary["policy_metric_rows"]), 32)

    def test_large_sample_interval_uses_conservative_student_t_value(self):
        summary = student_t_summary(range(40))
        self.assertEqual(summary["n"], 40)
        self.assertEqual(summary["ci95_method"], "student_t_conservative_table")
        normal_margin = 1.96 * summary["standard_error"]
        self.assertGreater(summary["mean"] - summary["ci95_low"], normal_margin)

    def test_long_form_samples_and_privacy_minimal_authentication_rows(self):
        run = run_fixture()
        resources = flatten_resource_samples([run], campaign_fixture())
        probes = flatten_probe_samples([run], campaign_fixture())
        authentication = flatten_authentication_observations(campaign_fixture())
        self.assertEqual(len(resources), 2)
        self.assertEqual(resources[0]["process_cpu_percent"], 4)
        self.assertGreaterEqual(len(probes), 11)
        self.assertIn("attack_probe", {row["series"] for row in probes})
        self.assertIn("availability", {row["series"] for row in probes})
        self.assertEqual(len(authentication), 1)
        auth = authentication[0]
        self.assertNotIn("username", auth)
        self.assertNotIn("message", auth)
        self.assertEqual(auth["policy"], "password_otp_biometric")
        self.assertEqual(
            json.loads(auth["required_factors_json"]),
            ["biometric", "otp", "password"],
        )
        self.assertEqual(auth["resource_cpu_percent_equivalent"], 8)

    def test_export_is_byte_deterministic_and_scrubs_credentials(self):
        campaign = campaign_fixture()
        run = run_fixture()
        run["username"] = "private-user"
        run["password"] = "private-password"
        run["observed_result"]["metrics"]["controller_api_token"] = "private-token"
        run["observed_result"]["metrics"]["otp_code"] = "123456"
        run["observed_result"]["metrics"]["biometric_sample"] = "private-biometric"
        run["observed_result"]["metrics"]["headers"] = {
            "Authorization": "Bearer private-authorization-value"
        }
        run["observed_result"]["message"] = (
            "request failed: Authorization: Bearer embedded-message-secret"
        )
        run["observed_result"]["metrics"]["receiver_result"]["stderr"] = (
            "connection password=embedded-stderr-secret refused"
        )
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "evidence"
            paths = export_evidence_package(campaign, [run], output)
            first = {key: path.read_bytes() for key, path in paths.items()}
            paths_again = export_evidence_package(campaign, [run], output)
            second = {key: path.read_bytes() for key, path in paths_again.items()}
            self.assertEqual(first, second)
            self.assertTrue(all(path.exists() for path in paths.values()))
            raw = json.loads(paths["raw_metrics_json"].read_text(encoding="utf-8"))
            self.assertIsInstance(raw["campaign"]["seed"], str)
            self.assertIsInstance(raw["campaign"]["manifest"]["seed"], int)
            self.assertEqual(
                manifest_digest(raw["campaign"]["manifest"]),
                campaign["manifest_sha256"],
            )
            self.assertNotIn("authentication_runs", raw["campaign"])
            combined = b"\n".join(first.values()).decode("utf-8")
            for secret in (
                "private-user",
                "private-password",
                "private-token",
                "123456",
                "private-biometric",
                "message that is deliberately not exported",
                "private-authorization-value",
                "embedded-message-secret",
                "embedded-stderr-secret",
            ):
                self.assertNotIn(secret, combined)
            resource_csv = list(
                csv.DictReader(
                    io.StringIO(paths["resource_samples_csv"].read_text(encoding="utf-8"))
                )
            )
            self.assertEqual(len(resource_csv), 2)
            task_csv = list(
                csv.DictReader(
                    io.StringIO(paths["task_evidence_csv"].read_text(encoding="utf-8"))
                )
            )
            self.assertEqual(task_csv[0]["campaign_seed"], str(LARGE_SEED))
            self.assertTrue(paths["policy_metric_summary_csv"].exists())

    def test_exported_artifact_paths_are_portable_and_still_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            project_root = Path(temp) / "private-workstation" / "SDNMFA"
            pcap_path = (
                project_root
                / "evidence"
                / "pcap"
                / "campaign-1"
                / "capture.pcap"
            )
            manifest_path = (
                project_root
                / "evidence"
                / "manifests"
                / "campaign-1.json"
            )
            pcap_path.parent.mkdir(parents=True)
            manifest_path.parent.mkdir(parents=True)
            pcap_bytes = b"portable-path regression evidence"
            pcap_path.write_bytes(pcap_bytes)
            pcap_digest = hashlib.sha256(pcap_bytes).hexdigest()

            manifest = {"campaign_id": "campaign-1", "seed": 7, "tasks": []}
            manifest["manifest_sha256"] = manifest_digest(manifest)
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True),
                encoding="utf-8",
            )
            campaign = {
                "campaign_id": "campaign-1",
                "manifest": manifest,
                "manifest_sha256": manifest["manifest_sha256"],
                "manifest_path": str(manifest_path),
            }
            run = run_fixture(
                pcap={
                    "enabled": True,
                    "path": str(pcap_path),
                    "size_bytes": len(pcap_bytes),
                    "sha256": pcap_digest,
                }
            )
            paths = export_evidence_package(
                campaign,
                [run],
                project_root / "reports" / "data" / "evidence",
                manifest_path=manifest_path,
                artifact_root=project_root,
            )

            combined = "\n".join(
                path.read_text(encoding="utf-8") for path in paths.values()
            )
            self.assertNotIn(str(project_root), combined)
            self.assertNotIn("/home/", combined)

            expected_pcap = "evidence/pcap/campaign-1/capture.pcap"
            expected_manifest = "evidence/manifests/campaign-1.json"
            task_rows = list(
                csv.DictReader(
                    io.StringIO(
                        paths["task_evidence_csv"].read_text(encoding="utf-8")
                    )
                )
            )
            self.assertEqual(task_rows[0]["pcap_path"], expected_pcap)
            nested_pcap = json.loads(task_rows[0]["pcap_evidence_json"])
            self.assertEqual(nested_pcap["path"], expected_pcap)

            raw = json.loads(paths["raw_metrics_json"].read_text(encoding="utf-8"))
            self.assertEqual(raw["campaign"]["manifest_path"], expected_manifest)
            self.assertEqual(raw["runs"][0]["pcap_evidence"]["path"], expected_pcap)

            inventory = json.loads(
                paths["checksum_inventory_json"].read_text(encoding="utf-8")
            )["rows"]
            by_type = {row["artifact_type"]: row for row in inventory}
            self.assertEqual(by_type["manifest"]["recorded_path"], expected_manifest)
            self.assertEqual(by_type["manifest"]["resolved_path"], expected_manifest)
            self.assertEqual(by_type["pcap"]["recorded_path"], expected_pcap)
            self.assertEqual(by_type["pcap"]["resolved_path"], expected_pcap)
            for row in inventory:
                self.assertEqual(row["checksum_status"], "verified")
                for field in ("recorded_path", "resolved_path"):
                    self.assertFalse(Path(row[field]).is_absolute())

    def test_concurrent_exports_to_one_destination_remain_coherent(self):
        campaign = campaign_fixture()
        run = run_fixture()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "evidence"
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(
                    pool.map(
                        lambda _index: export_evidence_package(
                            campaign, [run], output
                        ),
                        range(12),
                    )
                )
            self.assertEqual(len(results), 12)
            for path in results[-1].values():
                self.assertTrue(path.exists())
            raw = json.loads(
                results[-1]["raw_metrics_json"].read_text(encoding="utf-8")
            )
            self.assertEqual(raw["runs"][0]["task_id"], run["task_id"])


if __name__ == "__main__":
    unittest.main()
