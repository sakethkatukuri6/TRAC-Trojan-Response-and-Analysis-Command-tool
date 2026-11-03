"""M5's CLI republishes the verdict the scoring engine computed; it synthesises nothing."""
import pytest

from m5_detection.cli import OWNED_SECTIONS, create_event, generate_scoring_output
from m7_core.contract.loader import validate_event


def _doc(**overrides):
    doc = {
        "analysis_id": "11111111-1111-4111-8111-111111111111",
        "sample": {"vault_id": "22222222-2222-4222-8222-222222222222"},
        "detections": {"status": "done", "items": []},
        "score": {"value": 12.0, "method": "weighted_rules_v1", "components": []},
        "verdict": {"label": "benign", "severity": "low"},
    }
    doc.update(overrides)
    return doc


class TestM5:
    def test_create_event(self):
        event = create_event(_doc())
        assert event["type"] == "scoring.done"
        assert not validate_event(event)

    def test_event_publishes_the_computed_verdict_not_a_default(self):
        event = create_event(_doc(verdict={"label": "benign", "severity": "low"}))
        assert event["payload"] == {"section": "verdict", "label": "benign", "severity": "low"}

    def test_event_is_attributed_to_the_stored_sample(self):
        doc = _doc()
        event = create_event(doc)
        assert event["analysis_id"] == doc["analysis_id"]
        assert event["vault_id"] == doc["sample"]["vault_id"]

    def test_event_without_a_sample_reference_fails_closed(self):
        with pytest.raises(LookupError):
            create_event(_doc(sample={}))

    def test_output_contains_exactly_the_owned_sections(self):
        assert set(generate_scoring_output(_doc())) == set(OWNED_SECTIONS)

    def test_missing_section_is_an_error_rather_than_a_placeholder(self):
        doc = _doc()
        del doc["verdict"]
        with pytest.raises(LookupError, match="verdict"):
            generate_scoring_output(doc)
