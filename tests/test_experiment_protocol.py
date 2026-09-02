import json
import unittest
from unittest.mock import patch

from config.experiment_protocol import (
    AUTHORIZATION_TTL_SECONDS,
    BINDING_SPECS,
    DEFAULT_BINDING_PROFILE,
    DISPLAY_SCENARIO_ORDER,
    FLOOD_INTENSITY_RANGES,
    INTENSITY_ORDER,
    POLICY_ORDER,
    POLICY_SPECS,
    PROTECTED_HOST,
    PROTECTED_PORT,
    SCENARIO_SPECS,
    offered_load_ratio,
    protocol_parameter_errors,
)
from config.runtime_security import secret_validation_error, strong_secret_or_none
from experiments.campaign import build_campaign, manifest_digest, validate_campaign


class ExperimentProtocolTests(unittest.TestCase):
    def test_authentication_factors_are_separate_from_network_binding(self):
        factor_sets = [POLICY_SPECS[mode]["factor_keys"] for mode in POLICY_ORDER]
        self.assertEqual(
            factor_sets,
            [
                ("password",),
                ("password", "otp"),
                ("password", "biometric"),
                ("password", "otp", "biometric"),
            ],
        )
        self.assertEqual(
            {POLICY_SPECS[mode]["ttl_seconds"] for mode in POLICY_ORDER},
            {AUTHORIZATION_TTL_SECONDS},
        )
        self.assertEqual(
            {POLICY_SPECS[mode]["network_binding"] for mode in POLICY_ORDER},
            {BINDING_SPECS[DEFAULT_BINDING_PROFILE]["label"]},
        )

    def test_labels_are_honest_one_to_one_mechanisms(self):
        self.assertEqual(len(DISPLAY_SCENARIO_ORDER), 6)
        mechanisms = [SCENARIO_SPECS[item]["mechanism"] for item in DISPLAY_SCENARIO_ORDER]
        self.assertEqual(len(mechanisms), len(set(mechanisms)))
        self.assertNotIn("phishing", DISPLAY_SCENARIO_ORDER)
        self.assertNotIn("credential_theft", DISPLAY_SCENARIO_ORDER)

    def test_ddos_declares_three_distinct_sources(self):
        self.assertEqual(SCENARIO_SPECS["dos_udp_flood"]["source_count"], 1)
        self.assertEqual(SCENARIO_SPECS["ddos_udp_flood"]["source_count"], 3)
        self.assertEqual(SCENARIO_SPECS["ddos_udp_flood"]["mechanism"], "udp_flood_multi_source")

    def test_campaign_has_paired_inputs_and_randomized_complete_blocks(self):
        manifest = build_campaign(
            "ddos_udp_flood",
            seed=314159,
            repetitions=5,
            topology_id="tree-medium",
        )
        self.assertEqual(len(manifest.tasks), 60)
        self.assertEqual(validate_campaign(manifest), [])
        self.assertEqual(manifest.protocol_parameters["control_probe_count"], 5)
        self.assertEqual(manifest.protocol_parameters["minimum_control_availability"], 0.80)
        blocks = {}
        for task in manifest.tasks:
            blocks.setdefault(task.sample_id, []).append(task)
        self.assertEqual(len(blocks), 15)
        for tasks in blocks.values():
            self.assertEqual({task.policy for task in tasks}, set(POLICY_ORDER))
            self.assertEqual(
                len({json.dumps(task.parameters, sort_keys=True) for task in tasks}),
                1,
            )
            self.assertEqual(len({task.policy_position for task in tasks}), 4)

    def test_same_seed_reproduces_samples_and_order(self):
        first = build_campaign("ip_spoofing", seed=7, repetitions=2)
        second = build_campaign("ip_spoofing", seed=7, repetitions=2)
        first_signature = [
            (task.task_id, task.sample_id, task.policy, task.parameters) for task in first.tasks
        ]
        second_signature = [
            (task.task_id, task.sample_id, task.policy, task.parameters) for task in second.tasks
        ]
        self.assertEqual(first_signature, second_signature)
        self.assertEqual(first.campaign_id, second.campaign_id)

    def test_implementation_revision_is_manifested_and_changes_campaign_identity(self):
        current = build_campaign("ip_spoofing", seed=7, repetitions=1)
        self.assertEqual(
            current.protocol_parameters["implementation_revision"],
            "sdnmfa-thesis-v2",
        )
        with patch("experiments.campaign.IMPLEMENTATION_REVISION", "older-revision"):
            older = build_campaign("ip_spoofing", seed=7, repetitions=1)
        self.assertNotEqual(current.campaign_id, older.campaign_id)

    def test_different_seed_changes_sampled_inputs(self):
        first = build_campaign("dos_udp_flood", seed=1, repetitions=2)
        second = build_campaign("dos_udp_flood", seed=2, repetitions=2)
        self.assertNotEqual(
            [task.parameters for task in first.tasks],
            [task.parameters for task in second.tasks],
        )

    def test_generated_parameters_validate_for_every_scenario(self):
        for scenario in SCENARIO_SPECS:
            manifest = build_campaign(scenario, seed=20260813, repetitions=2)
            for task in manifest.tasks:
                params = task.parameters
                errors = protocol_parameter_errors(
                    scenario,
                    duration_seconds=params["duration_seconds"],
                    rate_pps=params["rate_pps"],
                    worker_count=params["worker_count"],
                    payload_size_bytes=params["payload_size_bytes"],
                    target_host=PROTECTED_HOST,
                    target_port=PROTECTED_PORT,
                    intensity_level=task.intensity,
                    request_count=params["request_count"],
                    source_count=params["source_count"],
                )
                self.assertEqual(errors, [], (scenario, task.intensity, params))

    def test_flood_load_bands_are_ordered(self):
        previous_upper = 0.0
        for intensity in INTENSITY_ORDER:
            lower, upper = FLOOD_INTENSITY_RANGES[intensity]["offered_load_ratio"]
            self.assertGreater(lower, previous_upper)
            self.assertGreater(upper, lower)
            previous_upper = upper
        self.assertAlmostEqual(offered_load_ratio(1000, 972), 0.8, places=6)

    def test_flood_packet_rate_rounding_never_leaves_declared_band(self):
        for scenario in ("dos_udp_flood", "ddos_udp_flood"):
            for seed in range(250):
                manifest = build_campaign(scenario, seed=seed, repetitions=1)
                for task in manifest.tasks:
                    params = task.parameters
                    lower, upper = FLOOD_INTENSITY_RANGES[task.intensity][
                        "offered_load_ratio"
                    ]
                    observed = offered_load_ratio(
                        params["rate_pps"], params["payload_size_bytes"]
                    )
                    self.assertGreaterEqual(observed, lower)
                    self.assertLessEqual(observed, upper)

    def test_validator_rejects_external_target_and_wrong_source_count(self):
        errors = protocol_parameter_errors(
            "ddos_udp_flood",
            duration_seconds=10,
            rate_pps=100,
            worker_count=1,
            payload_size_bytes=600,
            target_host="192.0.2.10",
            target_port=80,
            intensity_level="medium",
            source_count=1,
        )
        self.assertIn("target_host_mismatch", errors)
        self.assertIn("target_port_mismatch", errors)
        self.assertIn("source_count_mismatch", errors)

    def test_manifest_digest_detects_changes(self):
        payload = build_campaign("unauthorized_access", seed=9, repetitions=1).to_dict()
        original = payload["manifest_sha256"]
        self.assertEqual(manifest_digest(payload), original)
        payload["seed"] = 10
        self.assertNotEqual(manifest_digest(payload), original)

    def test_manifest_digest_ignores_creation_timestamp_for_resume(self):
        first = build_campaign(
            "unauthorized_access",
            seed=9,
            repetitions=1,
            created_at_utc="2026-01-01T00:00:00+00:00",
        ).to_dict()
        second = build_campaign(
            "unauthorized_access",
            seed=9,
            repetitions=1,
            created_at_utc="2026-01-02T00:00:00+00:00",
        ).to_dict()
        self.assertEqual(first["campaign_id"], second["campaign_id"])
        self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])

    def test_invalid_campaign_inputs_fail_closed(self):
        with self.assertRaises(ValueError):
            build_campaign("not-real", seed=1)
        with self.assertRaises(ValueError):
            build_campaign("unauthorized_access", seed=-1)
        with self.assertRaises(ValueError):
            build_campaign("unauthorized_access", seed=1, repetitions=0)
        with self.assertRaises(ValueError):
            build_campaign("unauthorized_access", seed=1, topology_id="unknown")

    def test_runtime_secret_policy_fails_closed(self):
        self.assertEqual(secret_validation_error(""), "missing")
        self.assertEqual(secret_validation_error("short"), "too_short")
        self.assertEqual(secret_validation_error("a" * 40), "insufficient_character_diversity")
        strong = "secure-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789"
        self.assertIsNone(secret_validation_error(strong))
        self.assertEqual(strong_secret_or_none(strong), strong)


if __name__ == "__main__":
    unittest.main()
