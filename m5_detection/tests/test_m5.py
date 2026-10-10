import unittest
from m5_detection.cli import create_event

class TestM5(unittest.TestCase):
    def test_create_event(self):
        event = create_event("test_id")
        self.assertEqual(event["type"], "scoring.done")
        self.assertEqual(event["payload"]["label"], "malicious")
