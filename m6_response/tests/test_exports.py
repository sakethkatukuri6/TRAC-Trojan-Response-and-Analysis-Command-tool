"""Test STIX 2.1, CSV, and JSON exporters."""
import json
from m6_response.exports.stix_exporter import export_stix_bundle
from m6_response.exports.csv_exporter import export_csv
from m6_response.exports.json_exporter import export_json


def test_exports():
    actions = [
        {
            "action_id": "0000001e-0000-4000-8000-00000000001e",
            "type": "block_hash",
            "target": "c" * 64,
            "mode": "dry_run",
            "status": "proposed",
            "playbook": "trojan_generic",
            "approval": {"required": False}
        }
    ]
    iocs = [{"type": "domain", "value": "c2[.]example"}]

    stix_out = export_stix_bundle(actions, iocs)
    stix_dict = json.loads(stix_out)
    assert stix_dict["type"] == "bundle"
    assert len(stix_dict["objects"]) > 0

    csv_out = export_csv(actions)
    assert "action_id,type,target,mode,status" in csv_out
    assert "block_hash" in csv_out

    json_out = export_json(actions)
    parsed = json.loads(json_out)
    assert "response_actions" in parsed
    assert len(parsed["response_actions"]) == 1
