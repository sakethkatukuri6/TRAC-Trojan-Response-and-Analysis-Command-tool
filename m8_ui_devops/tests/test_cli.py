"""Tests for M8 Command Line Interface."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parent.parent.parent


class TestM8CLI(unittest.TestCase):
    def test_cli_generates_report_and_event(self):
        analysis_id = str(uuid.uuid4())
        vault_id = str(uuid.uuid4())

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf, \
             tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_event:
            pdf_path = Path(tmp_pdf.name)
            event_path = Path(tmp_event.name)

        try:
            cmd = [
                sys.executable,
                "-m",
                "m8_ui_devops.cli",
                "--analysis-id",
                analysis_id,
                "--vault-id",
                vault_id,
                "--out-pdf",
                str(pdf_path),
                "--event",
                str(event_path),
            ]

            res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
            self.assertEqual(res.returncode, 0, f"CLI exited with error: {res.stderr}\n{res.stdout}")

            # Verify PDF created
            self.assertTrue(pdf_path.exists())
            self.assertGreater(pdf_path.stat().st_size, 1000)

            # Verify Event JSON
            self.assertTrue(event_path.exists())
            with open(event_path, "r", encoding="utf-8") as f:
                event = json.load(f)

            self.assertEqual(event.get("producer"), "M8")
            self.assertEqual(event.get("type"), "report.done")
            self.assertEqual(event.get("analysis_id"), analysis_id)
            self.assertEqual(event.get("vault_id"), vault_id)
            self.assertIn("report_vault_id", event.get("payload", {}))
        finally:
            if pdf_path.exists():
                pdf_path.unlink()
            if event_path.exists():
                event_path.unlink()


if __name__ == "__main__":
    unittest.main()
