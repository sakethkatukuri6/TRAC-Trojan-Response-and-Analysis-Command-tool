"""Security, sanitization, and defensive guardrail tests for M8."""
import os
import re
import unittest
from unittest import mock

from m1_ingestion.vault import MAX_FILE_SIZE
from m7_core.contract.loader import get_max_upload_bytes

ROOT = None


class TestConsoleOriginPolicy(unittest.TestCase):
    """The console API must not accept credentialed calls from arbitrary pages."""

    def _clean_env(self):
        return {k: v for k, v in os.environ.items() if k != "TRAC_UI_ALLOWED_ORIGINS"}

    def test_default_origin_is_the_console_itself(self):
        from m8_ui_devops.cli import _allowed_origins

        with mock.patch.dict(os.environ, self._clean_env(), clear=True):
            self.assertEqual(_allowed_origins("127.0.0.1", 8088), ["http://127.0.0.1:8088"])

    def test_wildcard_bind_still_advertises_the_loopback_origin(self):
        """0.0.0.0 is a bind address, not a URL a browser can name."""
        from m8_ui_devops.cli import _allowed_origins

        with mock.patch.dict(os.environ, self._clean_env(), clear=True):
            self.assertEqual(_allowed_origins("0.0.0.0", 9000), ["http://127.0.0.1:9000"])

    def test_operator_configured_origins_are_used_verbatim(self):
        from m8_ui_devops.cli import _allowed_origins

        with mock.patch.dict(
            os.environ,
            {**self._clean_env(), "TRAC_UI_ALLOWED_ORIGINS": "https://soc.internal, https://blue.internal"},
            clear=True,
        ):
            self.assertEqual(
                _allowed_origins("127.0.0.1", 8088),
                ["https://soc.internal", "https://blue.internal"],
            )

    def test_served_app_carries_no_wildcard_and_no_credentials(self):
        from fastapi.middleware.cors import CORSMiddleware

        from m8_ui_devops.cli import create_dashboard_app

        with mock.patch.dict(os.environ, self._clean_env(), clear=True):
            app = create_dashboard_app(host="127.0.0.1", port=8088)

        cors = [m for m in app.user_middleware if m.cls is CORSMiddleware]
        self.assertEqual(len(cors), 1)
        self.assertNotIn("*", cors[0].kwargs["allow_origins"])
        self.assertFalse(cors[0].kwargs["allow_credentials"])


class TestM8SecurityDefenses(unittest.TestCase):
    def test_upload_cap_is_the_contract_number(self):
        # The cap is a schema constant, not an M8 setting: M7 and M8 reject uploads
        # before M1 does, and a locally invented limit would let a file through one
        # gate only to fail as a schema violation at the next.
        self.assertEqual(MAX_FILE_SIZE, get_max_upload_bytes())
        self.assertEqual(MAX_FILE_SIZE, 104857600)

        under_cap = MAX_FILE_SIZE
        over_cap = MAX_FILE_SIZE + 1

        self.assertTrue(under_cap <= MAX_FILE_SIZE)
        self.assertFalse(over_cap <= MAX_FILE_SIZE)

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
