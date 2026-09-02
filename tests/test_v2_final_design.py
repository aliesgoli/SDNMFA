import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config.experiment_protocol import (
    BINDING_ORDER,
    NETWORK_DESIGN_CELL_COUNT_PER_TOPOLOGY,
    NETWORK_RUN_COUNT_PER_TOPOLOGY,
    POLICY_ORDER,
)
from analysis.article_report_v2 import _demo_data, _summary
from experiments.authentication_protocol import (
    AUTH_ATTACK_ORDER,
    AUTH_ATTACK_SPECS,
    build_authentication_plan,
    expected_policy_outcome,
)
from experiments.campaign import build_thesis_suite
from experiments.synthetic_users import PASSWORD_CLASSES, build_user_profiles
from security.password_service import SCHEME, hash_password, verify_password
from security.simulated_biometric_v2 import (
    DEFAULT_THRESHOLD,
    decrypt_template,
    encrypt_template,
    reference_vector,
    score_probe,
    simulated_probe,
    verify_probe,
)


SECRETS = {
    "BIOMETRIC_PEPPER": "Biometric-Pepper-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789",
    "OTP_PEPPER": "OTP-Pepper-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789",
    "EXPERIMENT_MASTER_SECRET": "Experiment-Master-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789",
}


class V2FinalDesignTests(unittest.TestCase):
    def test_complete_suite_has_24_campaigns_and_1440_runs(self):
        suite = build_thesis_suite(
            topology_id="tree-medium", base_seed=20260822, repetitions=5
        )
        self.assertEqual(len(suite), 24)
        self.assertEqual(sum(len(manifest.tasks) for manifest in suite), 1440)
        self.assertEqual({manifest.binding_profile for manifest in suite}, set(BINDING_ORDER))
        self.assertEqual(NETWORK_DESIGN_CELL_COUNT_PER_TOPOLOGY, 288)
        self.assertEqual(NETWORK_RUN_COUNT_PER_TOPOLOGY, 1440)

    def test_binding_comparison_reuses_identical_samples_and_policy_order(self):
        suite = build_thesis_suite(
            topology_id="star-small", base_seed=41, repetitions=2
        )
        by_scenario = {}
        for manifest in suite:
            by_scenario.setdefault(manifest.scenario, []).append(manifest)
        for manifests in by_scenario.values():
            self.assertEqual(len(manifests), 4)
            signatures = []
            sample_ids = []
            for manifest in manifests:
                signatures.append([
                    (
                        task.intensity, task.repetition, task.policy,
                        task.policy_position, task.parameters,
                    )
                    for task in manifest.tasks
                ])
                sample_ids.append([task.sample_id for task in manifest.tasks])
            self.assertTrue(all(signature == signatures[0] for signature in signatures[1:]))
            self.assertTrue(all(ids == sample_ids[0] for ids in sample_ids[1:]))
            task_ids = [
                task.task_id for manifest in manifests for task in manifest.tasks
            ]
            self.assertEqual(len(task_ids), len(set(task_ids)))

    def test_authentication_matrix_has_840_observations_and_isolated_blocks(self):
        plans = build_authentication_plan(
            base_seed=20260822, repetitions=5, user_count=500
        )
        self.assertEqual(len(AUTH_ATTACK_ORDER), 14)
        self.assertEqual(len(plans), 840)
        blocks = {}
        for plan in plans:
            blocks.setdefault(plan.block_id, []).append(plan)
        self.assertEqual(len(blocks), 210)
        self.assertEqual(len({rows[0].user_ordinal for rows in blocks.values()}), 210)
        for rows in blocks.values():
            self.assertEqual({row.policy for row in rows}, set(POLICY_ORDER))
            self.assertEqual(len({row.user_ordinal for row in rows}), 1)

    def test_single_factor_attacks_keep_non_target_factors_valid(self):
        otp_attack = {
            key: AUTH_ATTACK_SPECS["otp_replay"][key]
            for key in ("password", "otp", "biometric")
        }
        self.assertTrue(expected_policy_outcome("password_biometric", otp_attack))
        self.assertFalse(expected_policy_outcome("password_otp", otp_attack))

        biometric_attack = {
            key: AUTH_ATTACK_SPECS["biometric_impostor"][key]
            for key in ("password", "otp", "biometric")
        }
        self.assertTrue(expected_policy_outcome("password_otp", biometric_attack))
        self.assertFalse(expected_policy_outcome("password_biometric", biometric_attack))

    def test_synthetic_cohort_is_balanced_unique_and_namespaced(self):
        with patch.dict(os.environ, SECRETS, clear=False):
            users = build_user_profiles(500)
        self.assertEqual(len(users), 500)
        self.assertEqual(len({item.username for item in users}), 500)
        counts = {name: 0 for name in PASSWORD_CLASSES}
        for item in users:
            counts[item.password_class] += 1
            self.assertTrue(item.username.startswith("expv2_"))
        self.assertEqual(set(counts.values()), {100})

    def test_scrypt_password_hash_is_salted_and_verifiable(self):
        first = hash_password("Research!Password-2026")
        second = hash_password("Research!Password-2026")
        self.assertTrue(first.startswith(SCHEME + "$"))
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password(first, "Research!Password-2026"))
        self.assertFalse(verify_password(first, "wrong"))

    def test_v2_biometric_template_is_encrypted_scored_and_tamper_evident(self):
        with patch.dict(os.environ, SECRETS, clear=False):
            vector = reference_vector("expv2_alice")
            template = encrypt_template("expv2_alice", vector)
            self.assertNotIn("vector", template)
            self.assertEqual(len(decrypt_template("expv2_alice", template)), 64)
            genuine = simulated_probe("expv2_alice", probe_index=2, genuine=True)
            impostor = simulated_probe(
                "expv2_alice", probe_index=2, genuine=False,
                impostor_username="expv2_bob",
            )
            genuine_score = score_probe("expv2_alice", template, genuine)
            impostor_score = score_probe("expv2_alice", template, impostor)
            self.assertGreater(genuine_score, impostor_score)
            self.assertTrue(verify_probe(
                "expv2_alice", template, genuine, threshold=DEFAULT_THRESHOLD
            )[0])
            self.assertFalse(verify_probe(
                "expv2_alice", template, impostor, threshold=DEFAULT_THRESHOLD
            )[0])
            with self.assertRaises(Exception):
                decrypt_template("expv2_bob", template)

    def test_report_contains_separate_paired_policy_and_binding_inference(self):
        summary = _summary(_demo_data(), eer=0.0)
        self.assertEqual(len(summary["paired_authentication_comparisons"]), 3)
        self.assertEqual(len(summary["paired_network_binding_comparisons"]), 3)
        self.assertEqual(
            {row["paired_blocks"] for row in summary["paired_network_binding_comparisons"]},
            {720},
        )


if __name__ == "__main__":
    unittest.main()
