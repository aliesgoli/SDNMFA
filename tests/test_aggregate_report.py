import copy
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from analysis.scientific_report import (
    _render_aggregate_html,
    _select_latest_complete_suite,
    _write_aggregate_csv,
    generate_aggregate_report,
    main,
    summarize_aggregate,
)
from experiments.campaign import build_campaign, manifest_digest
from tests.test_analysis import fixture


CAMPAIGN_ONE = "00000000-0000-0000-0000-000000000001"
CAMPAIGN_TWO = "00000000-0000-0000-0000-000000000002"


def aggregate_fixture():
    first_campaign, first_runs = fixture()
    first_campaign["manifest"]["seed"] = str(first_campaign["seed"])
    first_campaign["manifest"]["manifest_sha256"] = manifest_digest(
        first_campaign["manifest"]
    )
    first_campaign["manifest_sha256"] = first_campaign["manifest"]["manifest_sha256"]
    second_campaign = copy.deepcopy(first_campaign)
    second_runs = copy.deepcopy(first_runs)
    second_campaign["campaign_id"] = CAMPAIGN_TWO
    second_campaign["scenario"] = "ddos_udp_flood"
    second_campaign["seed"] = 2**60 + 7
    second_campaign["manifest"]["seed"] = second_campaign["seed"]

    tasks = second_campaign["manifest"]["tasks"]
    for task, run in zip(tasks, second_runs):
        run["task_id"] = "second-%s" % run["task_id"]
        run["sample_id"] = "second-%s" % run["sample_id"]
        run["scenario"] = "ddos_udp_flood"
        outcome = (
            "availability_degraded"
            if run["intensity_level"] == "high"
            else "availability_preserved"
        )
        run["observed_result"]["metrics"]["security_outcome"] = outcome
        run["observed_result"]["success"] = False
        task["task_id"] = run["task_id"]
        task["sample_id"] = run["sample_id"]
        task["scenario"] = run["scenario"]

    # A completed campaign may contain a finished technical-error task. It is
    # recorded, but must never become an adverse or resisted security outcome.
    second_runs[0]["execution_status"] = "technical_error"
    second_runs[0]["is_valid"] = False
    second_runs[0]["observed_result"]["metrics"].update(
        {
            "security_outcome": "not_evaluable",
            "error_type": "test_transport_error",
        }
    )
    manifest = second_campaign["manifest"]
    manifest["manifest_sha256"] = manifest_digest(manifest)
    second_campaign["manifest_sha256"] = manifest["manifest_sha256"]
    return [(first_campaign, first_runs), (second_campaign, second_runs)]


class AggregateReportTests(unittest.TestCase):
    def test_latest_suite_never_mixes_incompatible_experiment_signatures(self):
        scenarios = [
            "unauthorized_access",
            "ip_spoofing",
            "ip_mac_spoofing",
            "arp_mitm",
            "dos_udp_flood",
            "ddos_udp_flood",
        ]
        complete = [
            {
                "campaign_id": "00000000-0000-0000-0000-%012d" % (index + 10),
                "protocol_id": "sdnmfa-exp-v2-final",
                "schema_version": 3,
                "seed": 42,
                "scenario": scenario,
                "topology_id": "tree-medium",
                "binding_profile": "ip_mac_port",
                "repetitions": 5,
                "completed_at": "2026-08-15T10:%02d:00+00:00" % index,
            }
            for index, scenario in enumerate(scenarios)
        ]
        newer_but_incomplete = [
            {
                **row,
                "campaign_id": "10000000-0000-0000-0000-%012d" % (index + 10),
                "seed": 99,
                "completed_at": "2026-08-16T10:%02d:00+00:00" % index,
            }
            for index, row in enumerate(complete[:-1])
        ]

        selected = _select_latest_complete_suite(complete + newer_but_incomplete)

        self.assertEqual(len(selected), 6)
        self.assertEqual({row["seed"] for row in selected}, {42})
        self.assertEqual([row["scenario"] for row in selected], scenarios)

    def test_latest_suite_rejects_a_partial_scenario_set(self):
        rows = [
            {
                "campaign_id": "00000000-0000-0000-0000-%012d" % index,
                "protocol_id": "sdnmfa-exp-v2-final",
                "schema_version": 3,
                "seed": 42,
                "scenario": scenario,
                "topology_id": "tree-medium",
                "binding_profile": "ip_mac_port",
                "repetitions": 5,
                "completed_at": "2026-08-15T10:00:00+00:00",
            }
            for index, scenario in enumerate(
                ["ip_spoofing", "ip_mac_spoofing", "arp_mitm"], start=1
            )
        ]
        with self.assertRaisesRegex(RuntimeError, "complete six-scenario suite"):
            _select_latest_complete_suite(rows)

    def test_latest_suite_requires_one_design_and_protocol_parameter_set(self):
        scenarios = [
            "unauthorized_access", "ip_spoofing", "ip_mac_spoofing",
            "arp_mitm", "dos_udp_flood", "ddos_udp_flood",
        ]
        rows = [
            {
                "campaign_id": "20000000-0000-0000-0000-%012d" % index,
                "protocol_id": "sdnmfa-exp-v2-final",
                "schema_version": 3,
                "seed": 42,
                "scenario": scenario,
                "topology_id": "tree-medium",
                "binding_profile": "ip_mac_port",
                "repetitions": 5,
                "completed_at": "2026-08-15T10:%02d:00+00:00" % index,
                "manifest": {
                    "design": {"kind": "randomized_complete_block"},
                    "protocol_parameters": {"minimum_control_availability": 0.8},
                },
            }
            for index, scenario in enumerate(scenarios)
        ]
        rows[-1]["manifest"]["protocol_parameters"] = {
            "minimum_control_availability": 0.5
        }
        with self.assertRaisesRegex(RuntimeError, "complete six-scenario suite"):
            _select_latest_complete_suite(rows)

    def test_latest_suite_accepts_real_scenario_specific_intensity_ranges(self):
        scenarios = [
            "unauthorized_access", "ip_spoofing", "ip_mac_spoofing",
            "arp_mitm", "dos_udp_flood", "ddos_udp_flood",
        ]
        rows = []
        for index, scenario in enumerate(scenarios):
            manifest = build_campaign(
                scenario,
                seed=20260815,
                repetitions=1,
            ).to_dict()
            rows.append(
                {
                    "campaign_id": manifest["campaign_id"],
                    "protocol_id": manifest["protocol_id"],
                    "schema_version": manifest["schema_version"],
                    "seed": manifest["seed"],
                    "scenario": manifest["scenario"],
                    "topology_id": manifest["topology_id"],
                    "binding_profile": manifest["binding_profile"],
                    "repetitions": manifest["repetitions"],
                    "design": manifest["design"],
                    "manifest": manifest,
                    "completed_at": "2026-08-15T11:%02d:00+00:00" % index,
                }
            )

        selected = _select_latest_complete_suite(rows)

        self.assertEqual([row["scenario"] for row in selected], scenarios)
        self.assertEqual({row["seed"] for row in selected}, {20260815})
        self.assertTrue(
            all(
                "declared_intensity_ranges"
                in row["manifest"]["protocol_parameters"]
                for row in selected
            )
        )
        self.assertTrue(
            all(
                manifest_digest(row["manifest"])
                == row["manifest"]["manifest_sha256"]
                for row in selected
            )
        )

    def test_summary_separates_invalid_tasks_and_counts_blocks(self):
        summary = summarize_aggregate(aggregate_fixture())
        self.assertEqual(summary["report_type"], "multi_campaign_aggregate")
        self.assertEqual(summary["campaign_n"], 2)
        self.assertEqual(summary["recorded_task_n"], 48)
        self.assertEqual(summary["valid_task_n"], 47)
        self.assertEqual(summary["technical_error_task_n"], 1)
        self.assertEqual(summary["incomplete_task_n"], 0)
        self.assertEqual(summary["invalid_nontechnical_task_n"], 0)
        self.assertEqual(
            {row["scenario"] for row in summary["scenario_rows"]},
            {"unauthorized_access", "ddos_udp_flood"},
        )
        self.assertEqual(len(summary["scenario_intensity_policy_rows"]), 24)
        self.assertEqual(len(summary["factor_compromise_resistance_rows"]), 4)
        self.assertEqual(sum(row["block_n"] for row in summary["block_summary_rows"]), 12)
        self.assertEqual(
            sum(row["not_comparable_block_n"] for row in summary["block_summary_rows"]),
            1,
        )
        ddos_low = next(
            row
            for row in summary["scenario_intensity_rows"]
            if row["scenario"] == "ddos_udp_flood" and row["intensity"] == "low"
        )
        self.assertEqual(ddos_low["recorded_n"], 8)
        self.assertEqual(ddos_low["valid_n"], 7)
        self.assertEqual(ddos_low["technical_error_n"], 1)
        self.assertEqual(ddos_low["adverse_outcome_n"], 0)
        self.assertEqual(summary["campaign_rows"][1]["seed"], str(2**60 + 7))
        self.assertEqual(
            summary["statistical_scope"]["paired_policy_rows"],
            "descriptive_only_no_equivalence_claim",
        )
        self.assertEqual(len(summary["quality_rows"]), 2)
        self.assertEqual(
            sum(row["technical_error_n"] for row in summary["quality_rows"]),
            1,
        )
        self.assertEqual(summary["technical_error_rows"][0]["task_n"], 1)
        self.assertTrue(summary["block_metric_rows"])
        verifier = summary["software_verifier_conformance_rows"][0]
        self.assertEqual(verifier["observation_n"], 4)
        self.assertEqual(verifier["mean_latency_ms"], 15.0)
        self.assertEqual(verifier["ci95_latency_low_ms"], 15.0)
        self.assertEqual(verifier["ci95_latency_high_ms"], 15.0)

    def test_invalid_campaign_evidence_is_excluded_from_inference_rates(self):
        observations = aggregate_fixture()
        observations[0][0]["manifest_sha256"] = "0" * 64
        summary = summarize_aggregate(observations)
        first = summary["campaign_rows"][0]
        self.assertFalse(first["analysis_eligible"])
        self.assertEqual(summary["excluded_campaign_n"], 1)
        self.assertEqual(summary["excluded_campaign_task_n"], 24)
        self.assertEqual(summary["task_level_valid_before_campaign_checks_n"], 47)
        self.assertEqual(summary["valid_task_n"], 23)
        unauthorized = next(
            row for row in summary["scenario_rows"]
            if row["scenario"] == "unauthorized_access"
        )
        self.assertEqual(unauthorized["valid_n"], 0)
        self.assertEqual(unauthorized["excluded_campaign_evidence_n"], 24)

    def test_all_invalid_campaigns_leave_every_analysis_denominator_empty(self):
        observations = aggregate_fixture()
        for campaign, _runs in observations:
            campaign["manifest_sha256"] = "0" * 64

        summary = summarize_aggregate(observations)

        self.assertEqual(summary["analysis_eligible_campaign_n"], 0)
        self.assertEqual(summary["valid_task_n"], 0)
        self.assertEqual(summary["excluded_campaign_task_n"], 48)
        self.assertTrue(all(row["valid_n"] == 0 for row in summary["scenario_rows"]))
        self.assertEqual(
            sum(row["excluded_campaign_evidence_n"] for row in summary["scenario_rows"]),
            48,
        )
        self.assertTrue(
            all(not row["comparable_valid_block"] for row in summary["block_rows"])
        )
        self.assertEqual(summary["software_verifier_conformance_rows"], [])

    def test_invalid_authentication_evidence_is_not_pooled(self):
        observations = aggregate_fixture()
        bad_campaign = observations[0][0]
        bad_auth = bad_campaign["authentication_runs"][0]
        bad_auth["supplied_factors"]["simulation"] = "invalid"
        bad_auth["latency_ms"] = -999.0

        summary = summarize_aggregate(observations)

        self.assertFalse(summary["campaign_rows"][0]["analysis_eligible"])
        self.assertTrue(summary["campaign_rows"][1]["analysis_eligible"])
        self.assertTrue(summary["software_verifier_conformance_rows"])
        self.assertTrue(
            all(
                row["mean_latency_ms"] == 15.0
                for row in summary["software_verifier_conformance_rows"]
            )
        )

    def test_mismatched_paired_parameters_make_block_noncomparable(self):
        observations = aggregate_fixture()
        campaign, runs = observations[0]
        runs[0]["sampled_parameters"]["rate_pps"] = 777
        campaign["manifest"]["tasks"][0]["parameters"]["rate_pps"] = 777
        campaign["manifest"]["manifest_sha256"] = manifest_digest(
            campaign["manifest"]
        )
        campaign["manifest_sha256"] = campaign["manifest"]["manifest_sha256"]
        summary = summarize_aggregate(observations)
        changed = next(
            row for row in summary["block_rows"]
            if row["campaign_id"] == CAMPAIGN_ONE
            and row["sample_id"] == runs[0]["sample_id"]
        )
        self.assertFalse(changed["paired_parameters_consistent"])
        self.assertFalse(changed["comparable_valid_block"])

    def test_duplicate_policy_block_is_excluded_from_paired_counts(self):
        observations = aggregate_fixture()
        campaign, runs = observations[0]
        duplicate = copy.deepcopy(runs[0])
        duplicate["task_id"] = "duplicate-policy-task"
        runs.append(duplicate)
        manifest_task = copy.deepcopy(campaign["manifest"]["tasks"][0])
        manifest_task["task_id"] = duplicate["task_id"]
        campaign["manifest"]["tasks"].append(manifest_task)
        campaign["manifest"]["manifest_sha256"] = manifest_digest(
            campaign["manifest"]
        )
        campaign["manifest_sha256"] = campaign["manifest"]["manifest_sha256"]

        summary = summarize_aggregate(observations)

        duplicated_block = next(
            row for row in summary["block_rows"]
            if row["campaign_id"] == CAMPAIGN_ONE
            and row["sample_id"] == duplicate["sample_id"]
        )
        self.assertFalse(duplicated_block["complete_recorded_block"])
        self.assertFalse(duplicated_block["comparable_valid_block"])
        comparison = next(
            row for row in summary["paired_policy_descriptive_rows"]
            if row["scenario"] == "unauthorized_access"
            and row["intensity"] == duplicate["intensity_level"]
            and row["left_policy"] == "password_only"
            and row["right_policy"] == "password_otp"
        )
        self.assertEqual(comparison["paired_valid_block_n"], 1)

    def test_bundle_contains_json_csv_manifests_and_defensible_html(self):
        observations = aggregate_fixture()
        summary = summarize_aggregate(observations, selection="explicit")
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            _write_aggregate_csv(output, summary, observations)
            expected = {
                "aggregate_summary.json",
                "aggregate_campaigns.csv",
                "aggregate_scenarios.csv",
                "aggregate_scenario_intensity_policy.csv",
                "aggregate_block_summary.csv",
                "aggregate_paired_policy_descriptive.csv",
                "aggregate_software_verifier_conformance.csv",
                "aggregate_run_details.csv",
                "aggregate_manifest_index.csv",
            }
            self.assertTrue(expected.issubset({path.name for path in (output / "data").iterdir()}))
            self.assertTrue((output / "data" / "manifests" / (CAMPAIGN_ONE + ".json")).exists())
            saved = json.loads((output / "data" / "aggregate_summary.json").read_text())
            self.assertIsInstance(saved["campaign_rows"][0]["seed"], str)
            manifest = json.loads(
                (output / "data" / "manifests" / (CAMPAIGN_TWO + ".json")).read_text()
            )
            self.assertIsInstance(manifest["seed"], int)
            self.assertEqual(
                manifest_digest(manifest),
                observations[1][0]["manifest_sha256"],
            )

        page = _render_aggregate_html(summary, False)
        self.assertIn("Software verifier conformance", page)
        self.assertIn("Mean latency [95% CI]", page)
        self.assertIn("Mean CPU [95% CI]", page)
        self.assertIn("No observed difference", page)
        self.assertIn("none is converted", page)
        self.assertIn("System at a glance", page)
        self.assertIn("not yet ready for final thesis inference", page)
        self.assertIn("ROC", page)
        self.assertNotIn("policies are equivalent", page.lower())
        self.assertIn('dir="rtl"', _render_aggregate_html(summary, True))

    def test_non_evaluable_scenario_is_rendered_as_na_not_zero(self):
        observations = aggregate_fixture()
        campaign, runs = observations[1]
        for run in runs:
            run["execution_status"] = "technical_error"
            run["is_valid"] = False
            run["observed_result"]["metrics"].update(
                {
                    "security_outcome": "not_evaluable",
                    "error_type": "synthetic_setup_failure",
                }
            )
        summary = summarize_aggregate(observations)

        ddos = next(
            row for row in summary["scenario_rows"]
            if row["scenario"] == "ddos_udp_flood"
        )
        self.assertIsNone(ddos["resistance_percent"])
        page = _render_aggregate_html(summary, False)
        self.assertIn("N/A", page)
        self.assertIn(
            "%s technical errors; no security rate computed" % len(runs),
            page,
        )

    @patch("analysis.scientific_report._query_campaigns")
    def test_api_writes_deterministic_aggregate_location(self, query):
        query.return_value = aggregate_fixture()
        with tempfile.TemporaryDirectory() as temp:
            index, summary = generate_aggregate_report(
                [CAMPAIGN_ONE, CAMPAIGN_TWO],
                output_dir=Path(temp),
            )
            self.assertTrue(index.exists())
            self.assertTrue((Path(temp) / "data" / "aggregate_summary.json").exists())
            self.assertTrue((Path(temp) / "data" / "chart_manifest.json").exists())
            self.assertEqual(
                len(list((Path(temp) / "assets" / "charts").glob("*.png"))),
                11,
            )
            self.assertEqual(
                len(list((Path(temp) / "assets" / "charts").glob("*.svg"))),
                11,
            )
            self.assertEqual(
                len(list((Path(temp) / "assets" / "charts").glob("*.pdf"))),
                11,
            )
            page = index.read_text(encoding="utf-8")
            self.assertIn("assets/charts/intensity_response.png", page)
            self.assertIn("PNG 300dpi", page)
            self.assertTrue(summary["aggregate_id"].startswith("aggregate-"))
            first_id = summary["aggregate_id"]
            second = summarize_aggregate(aggregate_fixture())["aggregate_id"]
            self.assertEqual(first_id, second)
        query.assert_called_once_with(
            [CAMPAIGN_ONE, CAMPAIGN_TWO],
            selector=None,
            latest_count=1,
            days=None,
        )

    @patch("analysis.scientific_report._query_campaigns")
    def test_optional_archive_contains_report_and_manifest_evidence(self, query):
        query.return_value = aggregate_fixture()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            _, summary = generate_aggregate_report(
                [CAMPAIGN_ONE, CAMPAIGN_TWO],
                output_dir=output,
                archive=True,
            )
            archive = Path(summary["archive_path"])
            self.assertTrue(archive.exists())
            with zipfile.ZipFile(archive) as bundle:
                names = set(bundle.namelist())
            self.assertIn("report/index.html", names)
            self.assertIn("report/data/aggregate_summary.json", names)
            self.assertIn("report/data/chart_manifest.json", names)
            self.assertIn(
                "report/assets/charts/intensity_response.png", names
            )
            self.assertIn(
                "report/assets/charts/intensity_response.svg", names
            )
            self.assertIn(
                "report/assets/charts/intensity_response.pdf", names
            )
            self.assertIn(
                "report/data/manifests/%s.json" % CAMPAIGN_ONE,
                names,
            )

    @patch("analysis.scientific_report.generate_aggregate_report")
    def test_cli_supports_repeated_campaigns_and_latest_suite(self, generate):
        generate.return_value = (
            Path("/tmp/aggregate/index.html"),
            {
                "report_type": "multi_campaign_aggregate",
                "campaign_n": 2,
                "recorded_task_n": 2,
                "valid_task_n": 2,
                "technical_error_task_n": 0,
                "incomplete_task_n": 0,
                "invalid_nontechnical_task_n": 0,
                "complete": True,
                "all_manifest_integrity_valid": True,
                "all_authentication_evidence_complete": True,
            },
        )
        self.assertEqual(
            main(["--campaign", CAMPAIGN_ONE, "--campaign", CAMPAIGN_TWO]),
            0,
        )
        self.assertEqual(generate.call_args.args[0], [CAMPAIGN_ONE, CAMPAIGN_TWO])
        generate.reset_mock()
        self.assertEqual(main(["--latest-suite", "--days", "30"]), 0)
        self.assertEqual(generate.call_args.kwargs["selector"], "latest-suite")
        self.assertEqual(generate.call_args.kwargs["days"], 30)
        self.assertEqual(main(["--latest-suite", "--strict"]), 2)
        generate.reset_mock()
        self.assertEqual(main(["--campaign", CAMPAIGN_ONE, "--days", "30"]), 1)
        generate.assert_not_called()
        self.assertEqual(main(["--days", "30"]), 1)

    @patch("analysis.scientific_report.generate_report")
    def test_one_campaign_keeps_single_campaign_entry_point(self, generate):
        generate.return_value = (
            Path("/tmp/single/index.html"),
            {
                "completed": 1,
                "planned": 1,
                "valid": 1,
                "technical_errors": 0,
                "complete": True,
                "authentication_observations": 1,
                "expected_authentication_observations": 1,
                "authentication_complete": True,
                "manifest_integrity_valid": True,
            },
        )
        self.assertEqual(main(["--campaign", CAMPAIGN_ONE]), 0)
        self.assertEqual(generate.call_args.args[0], CAMPAIGN_ONE)


if __name__ == "__main__":
    unittest.main()
