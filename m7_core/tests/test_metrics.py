"""Prometheus instrumentation tests for the M7 API."""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from m7_core.api.app import create_app
from m7_core.metrics import ANALYSES, STAGE_FAILURES, normalise_path


class MetricsEndpointTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(create_app())

    def test_metrics_endpoint_exposes_platform_metrics(self):
        res = self.client.get("/api/v1/health")
        self.assertEqual(res.status_code, 200)
        body = self.client.get("/metrics").text
        self.assertIn("trac_http_requests_total", body)
        self.assertIn('service="m7-core-api"', body)

    def test_normalise_path_masks_uuids_and_hashes(self):
        self.assertEqual(
            normalise_path("/api/v1/analyses/60b52e6a-2cf4-4915-b833-112674beaf92/view"),
            "/api/v1/analyses/:id/view",
        )
        self.assertEqual(
            normalise_path("/samples/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
            "/samples/:hash",
        )

    def test_stage_failure_counter_labels_by_stage(self):
        before = STAGE_FAILURES.labels(stage="dynamic")._value.get()
        STAGE_FAILURES.labels(stage="dynamic").inc()
        self.assertEqual(STAGE_FAILURES.labels(stage="dynamic")._value.get(), before + 1)

    def test_analysis_counter_counts_by_verdict(self):
        before = ANALYSES.labels(verdict="benign")._value.get()
        ANALYSES.labels(verdict="benign").inc()
        self.assertEqual(ANALYSES.labels(verdict="benign")._value.get(), before + 1)


if __name__ == "__main__":
    unittest.main()
