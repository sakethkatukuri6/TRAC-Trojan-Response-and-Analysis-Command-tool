import json, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import validate as v

EX = ROOT / "examples"
HAVE_SCHEMA = v.jsonschema is not None
VALID = sorted(EX.glob("valid_*.json"))
INVALID_SCHEMA = sorted(p for p in EX.glob("invalid_*.json") if "semantic" not in p.name)
INVALID_SEMANTIC = sorted(EX.glob("invalid_semantic_*.json"))


def load(p): return json.loads(Path(p).read_text())


class TestFilesParse(unittest.TestCase):
    def test_all_json_and_yaml_parse(self):
        for p in list((ROOT / "schemas").glob("*.json")) + list(EX.glob("*.json")):
            load(p)
        import yaml
        for p in [ROOT / "pipeline/state_machine.yaml", ROOT / "api/openapi.yaml"]:
            yaml.safe_load(p.read_text())

    def test_fixture_counts(self):
        self.assertGreaterEqual(len(VALID), 4)
        self.assertGreaterEqual(len(INVALID_SCHEMA), 10)
        self.assertEqual(len(INVALID_SEMANTIC), 4)


class TestSemantic(unittest.TestCase):
    def test_valid_fixtures_have_no_semantic_errors(self):
        for p in VALID:
            self.assertEqual(v.semantic_errors(load(p)), [], p.name)

    def test_each_semantic_fixture_is_caught(self):
        expect = {
            "invalid_semantic_live_url_ioc": "not defanged",
            "invalid_semantic_malicious_low_score": "requires score >= 60",
            "invalid_semantic_score_components_mismatch": "components sum",
            "invalid_semantic_sandbox_not_reverted": "reverted",
        }
        for p in INVALID_SEMANTIC:
            errs = " | ".join(v.semantic_errors(load(p)))
            self.assertIn(expect[p.stem], errs, p.name)

    def test_defang_helper(self):
        self.assertTrue(v._is_defanged("domain", "c2[.]example"))
        self.assertFalse(v._is_defanged("domain", "c2.example"))
        self.assertTrue(v._is_defanged("url", "hxxp://c2[.]example/x"))
        self.assertFalse(v._is_defanged("url", "http://c2.example/x"))
        self.assertFalse(v._is_defanged("ip", "192.0.2.10"))


class TestOwnership(unittest.TestCase):
    def test_owner_may_write(self):
        self.assertEqual(v.ownership_errors("M2", ["static"]), [])
        self.assertEqual(v.ownership_errors("M5", ["detections", "score", "verdict"]), [])

    def test_non_owner_rejected(self):
        self.assertTrue(v.ownership_errors("M4", ["verdict"]))
        self.assertTrue(v.ownership_errors("M6", ["static"]))
        self.assertTrue(v.ownership_errors("M2", ["pipeline"]))  # only M7


class TestEventFlow(unittest.TestCase):
    def ev(self, *types): return [{"type": t} for t in types]

    def test_happy_path(self):
        order = ["sample.received", "static.done", "dynamic.done", "iocs.done",
                 "scoring.done", "response.done", "report.done"]
        self.assertEqual(v.event_flow_errors(self.ev(*order)), [])

    def test_skipping_a_stage_rejected(self):
        self.assertTrue(v.event_flow_errors(self.ev("sample.received", "iocs.done")))

    def test_failure_events_do_not_advance_state(self):
        self.assertEqual(v.event_flow_errors(self.ev("sample.received", "stage.failed", "static.done")), [])


@unittest.skipUnless(HAVE_SCHEMA, "jsonschema not installed")
class TestJsonSchema(unittest.TestCase):
    def test_valid_fixtures_pass(self):
        for p in VALID:
            self.assertEqual(v.schema_errors(load(p)), [], p.name)

    def test_invalid_fixtures_fail(self):
        for p in INVALID_SCHEMA:
            self.assertTrue(v.schema_errors(load(p)), f"{p.name} should fail schema validation")

    def test_event_envelope(self):
        good = {"event_id": "00000001-0000-4000-8000-000000000001", "type": "static.done",
                "analysis_id": "00000001-0000-4000-8000-000000000001",
                "vault_id": "00000001-0000-4000-8000-000000000002",
                "emitted_at": "2026-10-10T09:00:00Z", "producer": "M2",
                "contract_version": "1.0.0", "payload": {"section": "static"}}
        self.assertEqual(v.schema_errors(good, "events.schema.json"), [])
        wrong_producer = dict(good, producer="M4")
        self.assertTrue(v.schema_errors(wrong_producer, "events.schema.json"))
        with_path = dict(good, payload={"section": "static", "path": "/tmp/x"})
        self.assertTrue(v.schema_errors(with_path, "events.schema.json"))


if __name__ == "__main__":
    unittest.main()
