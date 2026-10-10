import json, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import validate as v, check_module as cm, stub_module  # noqa

MODS = sorted(cm.REQUIRED)
SRC = v.load_json(ROOT / "examples" / "valid_synthetic_trojan_record.json")


def stub(m): return {s: SRC[s] for s in cm.REQUIRED[m]}


class TestModuleGate(unittest.TestCase):
    so = not v.jsonschema  # fall back to semantic-only when jsonschema is absent

    def test_every_stub_passes_its_own_gate(self):
        for m in MODS:
            if cm.REQUIRED[m]:
                self.assertEqual(cm.check_output(m, stub(m), self.so), [], m)

    def test_cross_module_write_rejected(self):
        for m in MODS:
            for other in MODS:
                if other != m and cm.REQUIRED[other]:
                    errs = cm.check_output(m, stub(other), True)
                    self.assertTrue(any("may not write" in e for e in errs), f"{m} wrote {other}'s section")

    def test_missing_owned_section_rejected(self):
        partial = {"verdict": SRC["verdict"]}
        self.assertTrue(any("missing required section" in e for e in cm.check_output("M5", partial, True)))

    def test_empty_and_non_object_rejected(self):
        self.assertTrue(cm.check_output("M2", {}, True))
        self.assertTrue(cm.check_output("M2", [], True))

    def test_semantic_violation_caught_through_gate(self):
        bad = stub("M4"); bad["iocs"] = json.loads(json.dumps(bad["iocs"]))
        bad["iocs"]["items"][0]["value"] = "c2.example"
        self.assertTrue(any("not defanged" in e for e in cm.check_output("M4", bad, True)))

    def test_malformed_sections_fail_cleanly_not_crash(self):
        for bad in ({"verdict": 1}, {"verdict": "x"}, {"verdict": None}, {"response_actions": {}}):
            m = "M6" if "response_actions" in bad else "M5"
            errs = cm.check_output(m, bad, True)
            self.assertTrue(errs, bad)

    def test_event_producer_and_type_enforced(self):
        ev = {"type": "static.done", "producer": "M2"}
        self.assertEqual(cm.check_event("M2", ev, True), [])
        self.assertTrue(cm.check_event("M3", ev, True))                      # wrong producer
        self.assertTrue(cm.check_event("M2", {"type": "iocs.done", "producer": "M2"}, True))  # wrong type
        self.assertEqual(cm.check_event("M2", {"type": "stage.failed", "producer": "M2"}, True), [])

    @unittest.skipUnless(v.jsonschema, "jsonschema not installed")
    def test_stub_events_pass_schema(self):
        import subprocess
        for m, t in cm.EVENTS.items():
            if t:
                out = subprocess.run([sys.executable, str(ROOT / "tools/stub_module.py"), m, "--event"],
                                     capture_output=True, text=True, check=True).stdout
                self.assertEqual(cm.check_event(m, json.loads(out)), [], m)


if __name__ == "__main__":
    unittest.main()
