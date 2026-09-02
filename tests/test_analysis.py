import copy
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from analysis.scientific_report import (
    _render_html,
    _save_charts,
    _write_csv,
    _archive_report_directory,
    _evidence_integrity_summary,
    _validate_report_output_tree,
    exact_mcnemar_p,
    main,
    summarize,
    wilson_interval,
)
from config.experiment_protocol import (
    AUTH_SCENARIO_ORDER,
    AUTH_SCENARIO_SPECS,
    INTENSITY_ORDER,
    POLICY_ORDER,
    POLICY_SPECS,
)
from experiments.campaign import manifest_digest


def fixture():
    runs = []
    task_number = 0
    for repetition in (1, 2):
        for intensity in INTENSITY_ORDER:
            for policy_position, policy in enumerate(POLICY_ORDER, start=1):
                task_number += 1
                outcome = (
                    "attack_success"
                    if policy == "password_only" and intensity == "high" and repetition == 2
                    else "attack_blocked"
                )
                runs.append(
                    {
                        "task_id": "task-%s" % task_number,
                        "sample_id": "sample-%s-%s" % (repetition, intensity),
                        "scenario": "unauthorized_access",
                        "repetition": repetition,
                        "intensity_level": intensity,
                        "mfa_mode": policy,
                        "policy_position": policy_position,
                        "binding_profile": "ip_mac_port",
                        "topology_id": "tree-medium",
                        "execution_status": "completed",
                        "is_valid": True,
                        "sampled_parameters": {
                            "duration_seconds": 5,
                            "rate_pps": 2,
                            "request_count": 5,
                            "source_count": 1,
                            "payload_size_bytes": None,
                            "offered_load_ratio": None,
                        },
                        "observed_result": {
                            "success": outcome == "attack_success",
                            "metrics": {
                                "security_outcome": outcome,
                                "attack_probe": {"latency_p95_ms": 20 + task_number},
                                "preflight": {
                                    "legitimate_samples": [
                                        {"elapsed_ms": 5 + task_number / 10.0},
                                        {"elapsed_ms": 6 + task_number / 10.0},
                                    ]
                                },
                                "postflight": {
                                    "samples": [
                                        {"elapsed_ms": 7 + task_number / 10.0}
                                    ]
                                },
                            },
                        },
                        "resource_metrics": {
                            "process_cpu_percent": {"p95": 10 + task_number / 10.0}
                        },
                        "pcap_evidence": {"sha256": "a" * 64},
                    }
                )

    auth_runs = []
    for repetition in (1, 2):
        for scenario in AUTH_SCENARIO_ORDER:
            available = set(AUTH_SCENARIO_SPECS[scenario]["available_factors"])
            for policy in POLICY_ORDER:
                required = set(POLICY_SPECS[policy]["factor_keys"])
                auth_runs.append(
                    {
                        "scenario": scenario,
                        "mfa_mode": policy,
                        "repetition": repetition,
                        "authentication_succeeded": required.issubset(available),
                        "latency_ms": 15.0,
                        "supplied_factors": {
                            "required": sorted(required),
                            "supplied": sorted(required & available),
                            "simulation": "software_factor_availability",
                        },
                        "resource_metrics": {"cpu_percent_equivalent": 12.5},
                    }
                )
    manifest = {
        "tasks": [
            {
                "task_id": row["task_id"],
                "sample_id": row["sample_id"],
                "scenario": row["scenario"],
                "intensity": row["intensity_level"],
                "repetition": row["repetition"],
                "policy": row["mfa_mode"],
                "policy_position": row["policy_position"],
                "binding_profile": row["binding_profile"],
                "topology_id": row["topology_id"],
                "parameters": row["sampled_parameters"],
            }
            for row in runs
        ],
        "protocol_parameters": {
            "minimum_control_availability": 0.80,
            "availability_degradation_margin": 0.10,
        },
    }
    manifest["manifest_sha256"] = manifest_digest(manifest)
    campaign = {
        "campaign_id": "00000000-0000-0000-0000-000000000001",
        "protocol_id": "sdnmfa-exp-v2-final",
        "scenario": "unauthorized_access",
        "topology_id": "tree-medium",
        "binding_profile": "ip_mac_port",
        "seed": 42,
        "repetitions": 2,
        "status": "completed",
        "manifest": manifest,
        "manifest_sha256": manifest["manifest_sha256"],
        "authentication_runs": auth_runs,
    }
    return campaign, runs


class AnalysisTests(unittest.TestCase):
    def test_wilson_interval_reports_finite_sample_uncertainty(self):
        low, high = wilson_interval(5, 5)
        self.assertAlmostEqual(low, 56.55, places=2)
        self.assertAlmostEqual(high, 100.0, places=6)
        self.assertEqual(wilson_interval(0, 0), (None, None))

    def test_exact_mcnemar_uses_only_discordant_pairs(self):
        self.assertEqual(exact_mcnemar_p(0, 0), 1.0)
        self.assertEqual(exact_mcnemar_p(0, 1), 1.0)
        self.assertAlmostEqual(exact_mcnemar_p(0, 6), 0.03125)
        with self.assertRaises(ValueError):
            exact_mcnemar_p(-1, 2)

    def test_evidence_integrity_fails_when_an_enabled_capture_is_missing(self):
        manifest = {
            "artifact_type": "manifest",
            "presence_status": "present",
            "checksum_status": "verified",
            "payload_checksum_status": "verified",
        }
        missing_manifest = {
            "artifact_type": "manifest",
            "presence_status": "missing",
            "checksum_status": "missing",
            "payload_checksum_status": "verified",
        }
        missing_pcap = {
            "artifact_type": "pcap",
            "enabled": True,
            "presence_status": "missing",
            "checksum_status": "missing",
            "size_status": "missing",
        }
        complete = _evidence_integrity_summary([manifest])
        incomplete = _evidence_integrity_summary([manifest, missing_pcap])
        self.assertTrue(complete["evidence_integrity_valid"])
        self.assertFalse(incomplete["evidence_integrity_valid"])
        self.assertEqual(incomplete["pcap_missing_n"], 1)
        self.assertFalse(
            _evidence_integrity_summary([missing_manifest])[
                "evidence_integrity_valid"
            ]
        )

    def test_single_campaign_excludes_unfinished_and_invalid_resisted_rows(self):
        campaign, runs = fixture()
        changed = copy.deepcopy(runs)
        changed[0]["execution_status"] = "running"
        changed[1]["is_valid"] = False
        summary = summarize(campaign, changed)
        self.assertEqual(summary["valid"], 22)
        self.assertEqual(summary["incomplete"], 1)
        self.assertEqual(summary["invalid_nontechnical"], 1)
        self.assertEqual(summary["technical_errors"], 0)
        self.assertEqual(sum(summary["valid_outcome_counts"].values()), 22)
        charts = {
            "curve": "curve.png",
            "policy": "policy.png",
            "outcome": "outcome.png",
            "performance": "performance.png",
            "authentication": "authentication.png",
        }
        page = _render_html(campaign, changed, summary, charts, False)
        self.assertIn("Valid observations", page)

    def test_non_numeric_latency_sample_is_missing_not_fatal(self):
        campaign, runs = fixture()
        runs[0]["observed_result"]["metrics"]["preflight"][
            "legitimate_samples"
        ].append({"elapsed_ms": "timeout"})
        summary = summarize(campaign, runs)
        self.assertIsNotNone(
            summary["policy_rows"][0]["mean_legitimate_latency_p95_ms"]
        )

    def test_policy_comparison_reports_insufficient_pairs(self):
        campaign, runs = fixture()
        one_policy = [run for run in runs if run["mfa_mode"] == "password_only"]
        summary = summarize(campaign, one_policy)
        self.assertFalse(summary["policy_comparison_evidence_available"])
        self.assertTrue(
            all(row["exact_mcnemar_p"] is None for row in summary["paired_policy_rows"])
        )
        charts = {
            "curve": "curve.png",
            "policy": "policy.png",
            "outcome": "outcome.png",
            "performance": "performance.png",
            "authentication": "authentication.png",
        }
        page = _render_html(campaign, one_policy, summary, charts, False)
        self.assertIn("insufficient for comparative inference", page)

    def test_report_archive_rejects_symlinks_and_excludes_unrelated_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "report"
            (output / "data").mkdir(parents=True)
            index = output / "index.html"
            summary_path = output / "data" / "summary.json"
            index.write_text("report", encoding="utf-8")
            summary_path.write_text("{}", encoding="utf-8")
            (output / "unrelated.txt").write_text("exclude", encoding="utf-8")
            (output / "data" / "unrelated-secret.txt").write_text(
                "exclude", encoding="utf-8"
            )
            outside = root / "outside.txt"
            outside.write_text("secret", encoding="utf-8")
            link = output / "data" / "outside-link"
            link.symlink_to(outside)
            with self.assertRaisesRegex(RuntimeError, "symbolic links"):
                _archive_report_directory(output, [index, summary_path, link])
            link.unlink()
            archive_path = _archive_report_directory(output, [index, summary_path])
            with zipfile.ZipFile(archive_path) as archive:
                names = set(archive.namelist())
            self.assertIn("report/index.html", names)
            self.assertIn("report/data/summary.json", names)
            self.assertNotIn("report/unrelated.txt", names)
            self.assertNotIn("report/data/unrelated-secret.txt", names)

    def test_report_archive_refuses_a_symbolic_link_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "report"
            output.mkdir()
            index = output / "index.html"
            index.write_text("report", encoding="utf-8")
            outside = root / "outside.zip"
            outside.write_bytes(b"preserve")
            archive_link = root / "report.zip"
            archive_link.symlink_to(outside)

            with self.assertRaisesRegex(RuntimeError, "destination"):
                _archive_report_directory(output, [index])

            self.assertEqual(outside.read_bytes(), b"preserve")

    def test_report_archive_supports_relative_paths_and_deduplicates_members(self):
        with tempfile.TemporaryDirectory(dir=".") as temp:
            output = (Path(temp) / "relative-report").absolute()
            output.mkdir()
            index = output / "index.html"
            index.write_text("report", encoding="utf-8")
            relative_output = output.relative_to(Path.cwd())
            relative_index = index.relative_to(Path.cwd())

            archive_path = _archive_report_directory(
                relative_output,
                [relative_index, relative_index],
            )

            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(
                    archive.namelist().count("relative-report/index.html"),
                    1,
                )

    def test_report_generation_rejects_a_symlink_in_an_existing_output_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "report"
            output.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (output / "data").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(RuntimeError, "symbolic links"):
                _validate_report_output_tree(output)

    def test_report_archive_reads_from_the_validated_file_descriptor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "report"
            output.mkdir()
            index = output / "index.html"
            index.write_bytes(b"validated-report")
            outside = root / "outside.txt"
            outside.write_bytes(b"TOPSECRET")
            real_copy = shutil.copyfileobj

            def swap_path_then_copy(source, destination, length=0):
                index.unlink()
                index.symlink_to(outside)
                return real_copy(source, destination, length=length)

            with patch(
                "analysis.scientific_report.shutil.copyfileobj",
                side_effect=swap_path_then_copy,
            ):
                archive_path = _archive_report_directory(output, [index])

            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(
                    archive.read("report/index.html"),
                    b"validated-report",
                )

    def test_report_archive_closes_descriptors_when_member_inspection_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            output.mkdir()
            index = output / "index.html"
            index.write_text("report", encoding="utf-8")
            descriptor_directory = Path("/proc/self/fd")
            before = len(list(descriptor_directory.iterdir()))

            with patch(
                "analysis.scientific_report.os.fstat",
                side_effect=OSError("injected inspection failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "could not inspect"):
                    _archive_report_directory(output, [index])

            after = len(list(descriptor_directory.iterdir()))
            self.assertEqual(after, before)

    def test_summary_uses_only_observed_results(self):
        campaign, runs = fixture()
        summary = summarize(campaign, runs)
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["planned"], 24)
        self.assertEqual(summary["valid"], 24)
        password = next(row for row in summary["policy_rows"] if row["policy"] == "password_only")
        full = next(row for row in summary["policy_rows"] if row["policy"] == "password_otp_biometric")
        self.assertAlmostEqual(password["resistance_percent"], 5 / 6 * 100)
        self.assertEqual(full["resistance_percent"], 100.0)
        self.assertEqual(summary["authentication_observations"], 40)
        self.assertTrue(summary["authentication_complete"])
        self.assertTrue(summary["manifest_integrity_valid"])
        self.assertEqual(
            summary["policy_rows"][0]["mean_valid_authentication_latency_ms"],
            15.0,
        )
        self.assertEqual(
            summary["policy_rows"][0]["mean_valid_authentication_cpu_percent"],
            12.5,
        )
        self.assertEqual(summary["policy_rows"][0]["valid_authentication_n"], 2)
        self.assertEqual(
            summary["policy_rows"][0][
                "ci95_valid_authentication_latency_low_ms"
            ],
            15.0,
        )
        self.assertEqual(
            summary["policy_rows"][0][
                "ci95_valid_authentication_latency_high_ms"
            ],
            15.0,
        )
        self.assertIsNotNone(
            summary["policy_rows"][0]["mean_legitimate_latency_p95_ms"]
        )
        password_vs_full = next(
            row
            for row in summary["paired_policy_rows"]
            if row["left_policy"] == "password_only"
            and row["right_policy"] == "password_otp_biometric"
        )
        self.assertEqual(password_vs_full["paired_n"], 6)
        self.assertEqual(password_vs_full["right_only_resisted"], 1)

    def test_factor_matrix_shows_value_of_missing_factors(self):
        campaign, runs = fixture()
        summary = summarize(campaign, runs)
        password_only = next(
            row for row in summary["authentication_rows"]
            if row["scenario"] == "password_compromised" and row["policy"] == "password_only"
        )
        full = next(
            row for row in summary["authentication_rows"]
            if row["scenario"] == "password_compromised" and row["policy"] == "password_otp_biometric"
        )
        self.assertEqual(password_only["authentication_success_percent"], 100.0)
        self.assertEqual(full["authentication_success_percent"], 0.0)

    def test_summary_rejects_run_that_no_longer_matches_manifest(self):
        campaign, runs = fixture()
        changed = copy.deepcopy(runs)
        changed[0]["sampled_parameters"]["rate_pps"] = 999
        summary = summarize(campaign, changed)
        self.assertFalse(summary["run_manifest_alignment_valid"])
        self.assertFalse(summary["complete"])

    def test_summary_rejects_inconsistent_authentication_evidence(self):
        campaign, runs = fixture()
        campaign = copy.deepcopy(campaign)
        campaign["authentication_runs"][0]["supplied_factors"]["simulation"] = "unknown"
        summary = summarize(campaign, runs)
        self.assertFalse(summary["authentication_evidence_valid"])
        self.assertFalse(summary["authentication_complete"])
        self.assertFalse(summary["analysis_eligible"])
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["valid"], 0)
        self.assertEqual(summary["task_level_valid_before_campaign_checks"], 24)
        self.assertTrue(
            all(row["valid_n"] == 0 for row in summary["policy_rows"])
        )
        self.assertTrue(
            all(row["paired_n"] == 0 for row in summary["paired_policy_rows"])
        )
        self.assertTrue(all(row["n"] == 0 for row in summary["authentication_rows"]))
        self.assertTrue(
            all(
                row["mean_valid_authentication_latency_ms"] is None
                for row in summary["policy_rows"]
            )
        )
        charts = {
            "curve": "curve.png",
            "policy": "policy.png",
            "outcome": "outcome.png",
            "performance": "performance.png",
            "authentication": "authentication.png",
        }
        page = _render_html(campaign, runs, summary, charts, False)
        self.assertIn("invalid; excluded from analysis", page)

    def test_charts_html_and_data_package_are_generated(self):
        campaign, runs = fixture()
        summary = summarize(campaign, runs)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            charts = _save_charts(summary, output / "assets" / "charts")
            _write_csv(output, summary, runs)
            page = _render_html(campaign, runs, summary, charts, False)
            persian = _render_html(campaign, runs, summary, charts, True)
            self.assertEqual(set(charts), {"curve", "policy", "outcome", "performance", "authentication"})
            for filename in charts.values():
                self.assertTrue((output / "assets" / "charts" / filename).exists())
            self.assertTrue((output / "data" / "policy_summary.csv").exists())
            self.assertTrue((output / "data" / "paired_policy_comparison.csv").exists())
            self.assertTrue((output / "data" / "authentication_factor_matrix.csv").exists())
            self.assertIn('target="_blank"', page)
            self.assertIn("table-scroll", page)
            self.assertIn("Security/availability response", page)
            self.assertIn('dir="rtl"', persian)
        self.assertIn("نتایج سنجش امنیت و کارایی", persian)

    @patch("analysis.scientific_report.generate_report")
    def test_strict_exit_rejects_technical_or_incomplete_data(self, generate):
        generate.return_value = (
            Path("/tmp/index.html"),
            {"completed": 1, "planned": 2, "valid": 1, "technical_errors": 1, "complete": False},
        )
        self.assertEqual(main(["--strict"]), 2)


if __name__ == "__main__":
    unittest.main()
