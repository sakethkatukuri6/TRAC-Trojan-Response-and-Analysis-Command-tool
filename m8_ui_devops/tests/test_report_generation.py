"""Tests for M8 Forensic Report Generation (PDF and HTML)."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from m7_core.services.pipeline_runner import run_full_pipeline
from m7_core.tests.benign_pe import build_benign_pe
from m8_ui_devops.reporting.pdf_report import generate_pdf_report
from m8_ui_devops.reporting.html_report import generate_html_report
from m8_ui_devops.reporting.models import ReportData

ROOT = Path(__file__).resolve().parent.parent.parent


class TestReportGeneration(unittest.TestCase):
    def setUp(self):
        self.fixtures = [
            ROOT / "contract" / "examples" / "valid_synthetic_trojan_record.json",
            ROOT / "contract" / "examples" / "valid_benign_test_binary.json",
            ROOT / "contract" / "examples" / "valid_eicar_test_file.json",
        ]

    def test_model_normalization_across_all_valid_fixtures(self):
        for fixture_path in self.fixtures:
            with open(fixture_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            data = ReportData.from_doc(doc)
            self.assertTrue(data.sample_name, f"Missing sample_name for {fixture_path.name}")
            self.assertTrue(data.verdict_label, f"Missing verdict_label for {fixture_path.name}")
            self.assertIsNotNone(data.contract_version)

    def test_pdf_report_generation_for_synthetic_trojan(self):
        trojan_path = ROOT / "contract" / "examples" / "valid_synthetic_trojan_record.json"
        with open(trojan_path, "r", encoding="utf-8") as f:
            doc = json.load(f)

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            generate_pdf_report(doc, tmp_path)
            self.assertTrue(tmp_path.exists())
            self.assertGreater(tmp_path.stat().st_size, 5000, "PDF file is too small")

            # Verify with pypdf
            import pypdf
            reader = pypdf.PdfReader(str(tmp_path))
            self.assertGreaterEqual(len(reader.pages), 1)
            full_text = "".join([p.extract_text() for p in reader.pages])
            self.assertIn("TRAC // THREAT RESPONSE & ANALYSIS COMMAND", full_text)
            self.assertIn("TLP:AMBER", full_text)
            self.assertIn("invoice_synthetic.exe", full_text)
            self.assertIn("c2[.]example", full_text)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_pdf_report_generation_for_benign_binary(self):
        benign_path = ROOT / "contract" / "examples" / "valid_benign_test_binary.json"
        with open(benign_path, "r", encoding="utf-8") as f:
            doc = json.load(f)

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            generate_pdf_report(doc, tmp_path)
            self.assertTrue(tmp_path.exists())
            self.assertGreater(tmp_path.stat().st_size, 3000)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_html_report_generation(self):
        trojan_path = ROOT / "contract" / "examples" / "valid_synthetic_trojan_record.json"
        with open(trojan_path, "r", encoding="utf-8") as f:
            doc = json.load(f)

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            html = generate_html_report(doc, tmp_path)
            self.assertTrue(tmp_path.exists())
            self.assertIn("<!DOCTYPE html>", html)
            self.assertIn("invoice_synthetic.exe", html)
            self.assertIn("c2[.]example", html)
            self.assertIn("TLP:AMBER", html)
            self.assertNotIn("http://c2.example", html, "Active un-defanged URL leaked in HTML")
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


class TestRealPeEvidenceInReports(unittest.TestCase):
    """Static evidence parsed from a real PE must reach both report renderers."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls._old_vault = os.environ.get("VAULT_STORAGE_PATH")
        os.environ["VAULT_STORAGE_PATH"] = str(Path(cls.tmpdir.name) / "vault")
        os.environ.pop("TRAC_CAPE_URL", None)
        os.environ.pop("TRAC_CAPE_TOKEN", None)
        cls.doc = run_full_pipeline(build_benign_pe(), "benign_fixture.exe")
        cls.imphash = cls.doc["static"]["pe"]["imphash"]

    @classmethod
    def tearDownClass(cls):
        if cls._old_vault is None:
            os.environ.pop("VAULT_STORAGE_PATH", None)
        else:
            os.environ["VAULT_STORAGE_PATH"] = cls._old_vault
        cls.tmpdir.cleanup()

    def setUp(self):
        self.assertEqual(self.doc["static"]["status"], "done")
        self.assertEqual(self.doc["dynamic"], {"status": "skipped"})

    def test_pdf_report_contains_parsed_sections_and_imports(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            generate_pdf_report(self.doc, tmp_path)
            import pypdf

            reader = pypdf.PdfReader(str(tmp_path))
            extracted = "".join(page.extract_text() for page in reader.pages)
            # Text-flow paragraphs wrap, so compare without whitespace.
            compact = "".join(extracted.split())

            self.assertIn(self.imphash, compact)
            self.assertIn("kernel32.dll:ExitProcess", compact)
            self.assertIn("user32.dll:MessageBoxA", compact)
            self.assertIn(".text", compact)
            self.assertIn(".rdata", compact)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_html_report_contains_parsed_sections_and_imports(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            markup = generate_html_report(self.doc, tmp_path)
            self.assertIn(self.imphash, markup)
            self.assertIn("kernel32.dll:ExitProcess", markup)
            self.assertIn("user32.dll:MessageBoxA", markup)
            self.assertIn("Static Analysis Evidence", markup)
            for name in (".text", ".rdata"):
                self.assertIn(name, markup)
            self.assertNotIn("<script", markup, "Report must not embed executable script")
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


if __name__ == "__main__":
    unittest.main()
