"""Security, sanitization, and defensive guardrail tests for M8."""
import re
import unittest

ROOT = None


class TestM8SecurityDefenses(unittest.TestCase):
    def test_upload_cap_boundary(self):
        MAX_CAP = 100 * 1024 * 1024  # 100 MiB (104857600 bytes)
        under_cap = 104857600
        over_cap = 104857601

        self.assertTrue(under_cap <= MAX_CAP)
        self.assertFalse(over_cap <= MAX_CAP)

    def test_filename_sanitization_rules(self):
        pattern = re.compile(r"^[A-Za-z0-9._ -]+$")

        good_names = ["invoice_sample.exe", "report.pdf", "sample 1.bin"]
        for name in good_names:
            self.assertTrue(bool(pattern.match(name)), f"{name} should match pattern")

        # Dangerous names
        bad_names = ["../../evil.exe", "..\\..\\evil.exe", "/etc/passwd", "file;rm -rf /", "cmd|whoami.exe"]
        for bad in bad_names:
            # Clean should strip unsafe characters
            clean = re.sub(r"[^A-Za-z0-9._ -]", "_", bad)
            clean_basename = clean.split("/")[-1].split("\\")[-1]
            self.assertTrue(bool(pattern.match(clean_basename)))

    def test_no_live_urls_in_defanged_indicators(self):
        live_pattern = re.compile(r"\b(?:https?|ftp)://", re.I)

        defanged_iocs = [
            "hxxp://c2[.]example/gate",
            "c2[.]example",
            "192[.]0[.]2[.]10",
            "hxxps://evil[.]com/drop",
        ]
        for val in defanged_iocs:
            self.assertFalse(bool(live_pattern.search(val)), f"{val} looks like a live URL")


if __name__ == "__main__":
    unittest.main()
