"""Strict contract compliance testing for M8 Module."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "contract" / "tools"))
import validate as v
import check_module as cm


class TestM8ContractCompliance(unittest.TestCase):
    def setUp(self):
        self.event_path = ROOT / "m8_ui_devops" / "contract_events" / "report_done.json"
        self.assertTrue(self.event_path.exists(), "m8_ui_devops/contract_events/report_done.json must exist")
        with open(self.event_path, "r", encoding="utf-8") as f:
            self.event = json.load(f)

    def test_event_producer_is_m8(self):
        self.assertEqual(self.event.get("producer"), "M8")

    def test_event_type_is_report_done(self):
        self.assertEqual(self.event.get("type"), "report.done")

    def test_contract_version_is_valid(self):
        self.assertEqual(self.event.get("contract_version"), "1.0.0")

    def test_report_vault_id_present_in_payload(self):
        payload = self.event.get("payload", {})
        self.assertIn("report_vault_id", payload)
        self.assertTrue(isinstance(payload["report_vault_id"], str))

    def test_event_validates_against_schema(self):
        if v.jsonschema:
            errs = v.schema_errors(self.event, "events.schema.json")
            self.assertEqual(errs, [], f"Schema errors: {errs}")

    def test_check_module_gate_for_m8(self):
        errs = cm.check_event("M8", self.event)
        self.assertEqual(errs, [], f"check_module.py errors: {errs}")

    def test_m8_owns_no_direct_sections(self):
        self.assertEqual(cm.REQUIRED["M8"], [])

    def test_check_all_script_passes_m8(self):
        res = subprocess.run(
            [sys.executable, str(ROOT / "contract" / "tools" / "check_all.py"), "--repo-root", str(ROOT)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"check_all.py failed: {res.stdout}\n{res.stderr}")
        self.assertIn("ok   M8", res.stdout)


if __name__ == "__main__":
    unittest.main()
