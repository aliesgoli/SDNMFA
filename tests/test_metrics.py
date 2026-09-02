import unittest

from experiments.metrics import ResourceSampler


class ResourceMetricTests(unittest.TestCase):
    def test_resource_summary_retains_recomputable_time_series(self):
        sampler = ResourceSampler.__new__(ResourceSampler)
        sampler.interval_seconds = 0.2
        sampler.process_pid = 123
        sampler.process_label = "ryu_controller"
        sampler.samples = [
            {
                "elapsed_seconds": 0.2000014,
                "process_cpu_percent": 12.3456,
                "process_rss_bytes": 1024.0,
                "system_cpu_percent": 20.4567,
                "system_memory_percent": 30.5678,
            },
            {
                "elapsed_seconds": 0.4000014,
                "process_cpu_percent": 22.3456,
                "process_rss_bytes": 2048.0,
                "system_cpu_percent": 25.4567,
                "system_memory_percent": 35.5678,
            },
        ]

        summary = sampler.summary()

        self.assertEqual(summary["sample_count"], 2)
        self.assertEqual(len(summary["samples"]), 2)
        self.assertEqual(summary["samples"][0]["elapsed_seconds"], 0.200001)
        self.assertEqual(summary["samples"][1]["process_rss_bytes"], 2048)
        self.assertAlmostEqual(summary["process_cpu_percent"]["mean"], 17.346)


if __name__ == "__main__":
    unittest.main()
