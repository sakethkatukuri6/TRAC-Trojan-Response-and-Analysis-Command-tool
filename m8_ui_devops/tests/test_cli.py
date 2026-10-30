"""Tests for M8 Command Line Interface."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parent.parent.parent


class TestM8CLI(unittest.TestCase):
    def test_cli_generates_report_and_event(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf, \
             tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_event:
            pdf_path = Path(tmp_pdf.name)
            event_path = Path(tmp_event.name)

        try:
            cmd = [
                sys.executable,
                "-m",
                "m8_ui_devops.cli",
                "--input",
                "contract/examples/valid_synthetic_trojan_record.json",
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

            # The ids come from the analysed document, not from flags that overwrite it.
            with open(ROOT / "contract" / "examples" / "valid_synthetic_trojan_record.json", encoding="utf-8") as f:
                source = json.load(f)

            self.assertEqual(event.get("producer"), "M8")
            self.assertEqual(event.get("type"), "report.done")
            self.assertEqual(event.get("analysis_id"), source["analysis_id"])
            self.assertEqual(event.get("vault_id"), source["sample"]["vault_id"])
            self.assertIn("report_vault_id", event.get("payload", {}))
        finally:
            if pdf_path.exists():
                pdf_path.unlink()
            if event_path.exists():
                event_path.unlink()

    def test_cli_refuses_to_report_an_unknown_analysis(self):
        """No --input and an id M7 never persisted must not fall back to the example document."""
        from sqlalchemy import create_engine

        from m7_core.database import init_db

        with tempfile.TemporaryDirectory() as tmp:
            out_pdf = Path(tmp) / "report.pdf"
            db_url = f"sqlite:///{(Path(tmp) / 'm8_cli.db').as_posix()}"
            engine = create_engine(db_url, connect_args={"check_same_thread": False})
            init_db(engine)
            engine.dispose()  # Windows refuses to remove the directory while SQLite holds the file

            res = subprocess.run(
                [
                    sys.executable, "-m", "m8_ui_devops.cli",
                    "--analysis-id", str(uuid.uuid4()),
                    "--out-pdf", str(out_pdf),
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                env={**os.environ, "DATABASE_URL": db_url},
            )
            self.assertEqual(res.returncode, 1)
            self.assertIn("not recorded", res.stderr)
            self.assertFalse(out_pdf.exists())

    def test_cli_requires_exactly_one_document_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_pdf = Path(tmp) / "report.pdf"
            for flags in ([], ["--analysis-id", str(uuid.uuid4()), "--input", "contract/examples/valid_synthetic_trojan_record.json"]):
                res = subprocess.run(
                    [sys.executable, "-m", "m8_ui_devops.cli", *flags, "--out-pdf", str(out_pdf)],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                )
                self.assertEqual(res.returncode, 2, res.stderr)
            self.assertFalse(out_pdf.exists())


if __name__ == "__main__":
    unittest.main()
