"""Tests for M8 Report Generation Worker and Event Handling."""
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from m8_ui_devops.reporting.worker import (
    ReportWorker,
    create_report_done_event,
    create_stage_failed_event,
)

ROOT = Path(__file__).resolve().parent.parent.parent


class TestReportWorker(unittest.TestCase):
    def test_create_report_done_event_schema(self):
        analysis_id = str(uuid.uuid4())
        vault_id = str(uuid.uuid4())
        report_vault_id = str(uuid.uuid4())

        ev = create_report_done_event(analysis_id, vault_id, report_vault_id)
        self.assertEqual(ev["producer"], "M8")
        self.assertEqual(ev["type"], "report.done")
        self.assertEqual(ev["analysis_id"], analysis_id)
        self.assertEqual(ev["payload"]["report_vault_id"], report_vault_id)

    def test_create_stage_failed_event_schema(self):
        analysis_id = str(uuid.uuid4())
        vault_id = str(uuid.uuid4())

        ev = create_stage_failed_event(analysis_id, vault_id, "DISK_FULL", "Cannot write PDF", retryable=True)
        self.assertEqual(ev["producer"], "M8")
        self.assertEqual(ev["type"], "stage.failed")
        self.assertEqual(ev["payload"]["stage"], "report")
        self.assertEqual(ev["payload"]["code"], "DISK_FULL")
        self.assertTrue(ev["payload"]["retryable"])

    def test_worker_process_analysis(self):
        fixture_path = ROOT / "contract" / "examples" / "valid_synthetic_trojan_record.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            doc = json.load(f)

        with tempfile.TemporaryDirectory() as tmp_dir:
            worker = ReportWorker(reports_dir=tmp_dir)
            event = worker.process_analysis(doc)

            self.assertEqual(event.get("type"), "report.done")
            self.assertEqual(event.get("producer"), "M8")
            self.assertIn("report_vault_id", event.get("payload", {}))

            # Verify files were generated in reports_dir
            generated_files = list(Path(tmp_dir).glob("*"))
            self.assertGreaterEqual(len(generated_files), 2)  # .pdf and .html


if __name__ == "__main__":
    unittest.main()
