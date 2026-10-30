"""M4's CLI republishes extracted indicators; the shared defanger must satisfy the contract gate."""
import unittest

import pytest

from contract.tools.validate import _is_defanged
from m4_ioc.cli import create_event, generate_iocs_output
from m4_ioc.extractor import defang


class TestDefang(unittest.TestCase):
    def test_defang_url(self):
        self.assertEqual(defang("url", "http://c2.example/gate"), "hxxp://c2[.]example/gate")
        self.assertEqual(defang("url", "https://malicious.com"), "hxxps://malicious[.]com")

    def test_defang_ip(self):
        self.assertEqual(defang("ip", "192.168.1.1"), "192[.]168[.]1[.]1")

    def test_defang_domain(self):
        self.assertEqual(defang("domain", "malware.c2.net"), "malware[.]c2[.]net")

    def test_every_boundary_is_defanged_not_just_alternate_ones(self):
        # Single-digit octets sit one character apart; a consuming regex leaves the
        # last dot raw and the contract gate rejects the indicator.
        for value in ("8.8.8.8", "192.0.2.10", "1.1.1.1"):
            self.assertTrue(_is_defanged("ip", defang("ip", value)), value)

    def test_defanged_values_clear_the_contract_gate(self):
        for ioc_type, value in [
            ("ip", "203.0.113.7"),
            ("domain", "a.b.c.example.com"),
            ("url", "http://x.y.z/gate"),
            ("email", "drop@x.y.z"),
        ]:
            self.assertTrue(_is_defanged(ioc_type, defang(ioc_type, value)), value)


def _doc(**overrides):
    doc = {
        "analysis_id": "33333333-3333-4333-8333-333333333333",
        "sample": {"vault_id": "44444444-4444-4444-8444-444444444444"},
        "iocs": {
            "status": "done",
            "items": [{"type": "domain", "value": "c2[.]example", "source": "pcap", "confidence": 0.9}],
        },
    }
    doc.update(overrides)
    return doc


class TestIocsCli:
    def test_output_is_the_stored_iocs_section(self):
        doc = _doc()
        assert generate_iocs_output(doc) == {"iocs": doc["iocs"]}

    def test_event_counts_the_indicators_actually_extracted(self):
        doc = _doc(iocs={"status": "done", "items": []})
        assert create_event(doc)["payload"]["ioc_count"] == 0

    def test_event_is_attributed_to_the_stored_sample(self):
        doc = _doc()
        event = create_event(doc)
        assert event["analysis_id"] == doc["analysis_id"]
        assert event["vault_id"] == doc["sample"]["vault_id"]

    def test_event_without_a_sample_reference_fails_closed(self):
        with pytest.raises(LookupError):
            create_event(_doc(sample={}))

    def test_missing_section_is_an_error_rather_than_a_placeholder(self):
        doc = _doc()
        del doc["iocs"]
        with pytest.raises(LookupError, match="iocs"):
            generate_iocs_output(doc)
