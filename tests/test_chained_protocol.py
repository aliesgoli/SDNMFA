import unittest

from experiments.chained_protocol import (
    CHAIN_AUTH_ATTACK_ORDER,
    build_chained_plan,
    expected_chained_runs_per_topology,
)


class ChainedProtocolTests(unittest.TestCase):
    def test_default_plan_contains_11520_chains_per_topology(self):
        plan = build_chained_plan(
            topology_id="star-small",
            base_seed=20260822,
            repetitions=5,
            user_count=500,
        )
        self.assertEqual(len(plan), 11520)
        self.assertEqual(len(plan), expected_chained_runs_per_topology(5))
        self.assertEqual(
            {task.auth_plan.attack_variant for task in plan},
            set(CHAIN_AUTH_ATTACK_ORDER),
        )

    def test_plan_is_deterministic_and_paired(self):
        first = build_chained_plan(
            topology_id="tree-medium", base_seed=19,
            repetitions=1, user_count=500,
        )
        second = build_chained_plan(
            topology_id="tree-medium", base_seed=19,
            repetitions=1, user_count=500,
        )
        self.assertEqual(
            [task.chain_id for task in first],
            [task.chain_id for task in second],
        )
        blocks = {}
        for task in first:
            key = (
                task.network_scenario, task.intensity, task.repetition,
                task.auth_plan.attack_variant,
            )
            blocks.setdefault(key, set()).add(task.user_ordinal)
        self.assertTrue(blocks)
        self.assertTrue(all(len(ordinals) == 1 for ordinals in blocks.values()))

    def test_all_targets_remain_inside_the_declared_mininet_service(self):
        plan = build_chained_plan(
            topology_id="partial-mesh-medium", base_seed=7,
            repetitions=1, user_count=500,
        )
        self.assertTrue(plan)
        for task in plan:
            self.assertEqual(task.network_parameters["target_host"], "10.0.0.2")
            self.assertEqual(task.network_parameters["target_port"], 18080)


if __name__ == "__main__":
    unittest.main()
