"""Tests for the M8 console wired to the real M7 pipeline result.

The console may only present evidence the pipeline actually produced, and it
must never present runtime facts that were not observed.
"""
from __future__ import annotations

import io
import os
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from m7_core.database import Base, get_db
from m8_ui_devops.cli import create_dashboard_app
from m8_ui_devops.evidence import (
    OBSERVED_SANDBOX_LABEL,
    SANDBOX_FAILED_LABEL,
    SANDBOX_NOT_CONFIGURED_LABEL,
    STATIC_EVIDENCE_LABEL,
    build_presentation,
)

ROOT = Path(__file__).resolve().parent.parent.parent
DASHBOARD = ROOT / "m8_ui_devops" / "ui" / "standalone.html"

EICAR = (
    rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


class EvidenceLabelTests(unittest.TestCase):
    """The three dynamic stage outcomes must map onto distinct labels."""

    def _doc(self, status, extra=None):
        dynamic = {"status": status}
        dynamic.update(extra or {})
        return {"analysis_id": "a", "dynamic": dynamic}

    def test_skipped_is_sandbox_not_configured(self):
        view = build_presentation(self._doc("skipped"))
        self.assertEqual(view["sandbox"]["label"], SANDBOX_NOT_CONFIGURED_LABEL)
        self.assertFalse(view["sandbox"]["observed"])

    def test_failed_is_sandbox_failed(self):
        view = build_presentation(self._doc("failed"))
        self.assertEqual(view["sandbox"]["label"], SANDBOX_FAILED_LABEL)
        self.assertFalse(view["sandbox"]["observed"])

    def test_done_is_observed_sandbox_telemetry(self):
        view = build_presentation(self._doc("done"))
        self.assertEqual(view["sandbox"]["label"], OBSERVED_SANDBOX_LABEL)
        self.assertTrue(view["sandbox"]["observed"])

    def test_unknown_status_is_not_claimed_as_observed(self):
        view = build_presentation(self._doc("running"))
        self.assertFalse(view["sandbox"]["observed"])
        self.assertNotEqual(view["sandbox"]["label"], OBSERVED_SANDBOX_LABEL)

    def test_telemetry_is_withheld_until_the_stage_is_done(self):
        for status in ("skipped", "failed", "running"):
            view = build_presentation(
                self._doc(status, {"process_tree": [{"pid": 4242, "name": "evil.exe"}]})
            )
            self.assertIsNone(
                view["sandbox"]["telemetry"],
                f"telemetry leaked for dynamic.status={status}",
            )
            self.assertEqual(view["iocs"]["beacons"], [])

    def test_observed_telemetry_is_surfaced_when_done(self):
        view = build_presentation(
            self._doc(
                "done",
                {
                    "process_tree": [{"pid": 4242, "name": "evil.exe"}],
                    "network_summary": {"dns_queries": 3},
                },
            )
        )
        self.assertTrue(view["sandbox"]["observed"])
        self.assertEqual(len(view["sandbox"]["telemetry"]["process_tree"]), 1)
        self.assertEqual(view["sandbox"]["telemetry"]["network_summary"]["dns_queries"], 3)

    def test_failed_sandbox_surfaces_the_operator_error(self):
        doc = self._doc("failed")
        doc["pipeline"] = {
            "errors": [{"stage": "dynamic", "code": "SANDBOX_FAILED", "message": "cape timed out"}]
        }
        view = build_presentation(doc)
        self.assertEqual(view["sandbox"]["error"], "cape timed out")

    def test_static_capabilities_are_labelled_as_static(self):
        view = build_presentation({"iocs": {"attack_techniques": [{"id": "T1055"}]}})
        self.assertEqual(view["static_evidence"]["label"], STATIC_EVIDENCE_LABEL)
        self.assertEqual(view["capabilities"]["techniques"], [{"id": "T1055"}])


class DashboardContentTests(unittest.TestCase):
    """The served console must not carry hardcoded sample data."""

    def setUp(self):
        self.html = DASHBOARD.read_text(encoding="utf-8")

    def test_no_synthetic_fixtures_are_embedded(self):
        for marker in ("SYNTHETIC_TROJAN", "BENIGN_SAMPLE", "invoice_synthetic.exe"):
            self.assertNotIn(marker, self.html, f"{marker} is hardcoded in the dashboard")

    def test_no_fabricated_telemetry_defaults(self):
        for marker in ("192[.]0[.]2[.]10", "c2[.]example", "win10-x64"):
            self.assertNotIn(marker, self.html, f"{marker} is hardcoded in the dashboard")

    def test_labels_come_from_the_server(self):
        # The sandbox tab title must be driven by the server supplied label.
        self.assertIn("sandbox.label", self.html)
        self.assertNotIn(">Observed sandbox telemetry<", self.html)


class UploadRouteTests(unittest.TestCase):
    """The upload route must run the real pipeline and persist through M7."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        self._old_vault = os.environ.get("VAULT_STORAGE_PATH")
        os.environ["VAULT_STORAGE_PATH"] = str(tmp / "vault")
        self.addCleanup(self._restore_vault_env)

        self.engine = create_engine(
            f"sqlite:///{(tmp / 'm8_test.db').as_posix()}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(bind=self.engine)
        self.addCleanup(self.engine.dispose)
        self.session_factory = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        app = create_dashboard_app()
        self.addCleanup(app.dependency_overrides.clear)

        def override_get_db():
            db = self.session_factory()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def _restore_vault_env(self):
        if self._old_vault is None:
            os.environ.pop("VAULT_STORAGE_PATH", None)
        else:
            os.environ["VAULT_STORAGE_PATH"] = self._old_vault

    def test_health_endpoint(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")

    def test_upload_returns_the_real_pipeline_document(self):
        res = self.client.post(
            "/api/samples/upload",
            files={"file": ("eicar.txt", EICAR, "application/octet-stream")},
        )
        self.assertEqual(res.status_code, 200, res.text)
        payload = res.json()

        document = payload["document"]
        for section in (
            "contract_version",
            "analysis_id",
            "sample",
            "static",
            "dynamic",
            "iocs",
            "detections",
            "score",
            "verdict",
            "response_actions",
            "pipeline",
        ):
            self.assertIn(section, document)

        # The hashes must be the real ones of the uploaded bytes.
        import hashlib

        self.assertEqual(
            document["sample"]["sha256"], hashlib.sha256(EICAR).hexdigest()
        )
        self.assertEqual(document["sample"]["md5"], hashlib.md5(EICAR).hexdigest())

        presentation = payload["presentation"]
        self.assertEqual(presentation["static_evidence"]["label"], STATIC_EVIDENCE_LABEL)
        self.assertEqual(
            presentation["static_evidence"]["sample"]["sha256"],
            document["sample"]["sha256"],
        )

        from contract.tools.validate import validate_document

        self.assertEqual(validate_document(document), [])

    def test_upload_reports_the_sandbox_status_truthfully(self):
        res = self.client.post(
            "/api/samples/upload",
            files={"file": ("eicar.txt", EICAR, "application/octet-stream")},
        )
        self.assertEqual(res.status_code, 200, res.text)
        sandbox = res.json()["presentation"]["sandbox"]

        self.assertEqual(sandbox["status"], document_status(res.json()))
        self.assertFalse(sandbox["observed"])
        self.assertIsNone(sandbox["telemetry"])
        self.assertIn(sandbox["label"], (SANDBOX_NOT_CONFIGURED_LABEL, SANDBOX_FAILED_LABEL))

    def test_upload_persists_the_analysis_through_m7(self):
        res = self.client.post(
            "/api/samples/upload",
            files={"file": ("eicar.txt", EICAR, "application/octet-stream")},
        )
        self.assertEqual(res.status_code, 200, res.text)
        analysis_id = res.json()["document"]["analysis_id"]

        listing = self.client.get("/api/analyses")
        self.assertEqual(listing.status_code, 200)
        self.assertIn(analysis_id, [row["analysis_id"] for row in listing.json()])

        view = self.client.get(f"/api/analyses/{analysis_id}/view")
        self.assertEqual(view.status_code, 200)
        stored = view.json()["document"]
        self.assertEqual(stored["analysis_id"], analysis_id)
        self.assertEqual(stored["sample"]["sha256"], res.json()["document"]["sample"]["sha256"])
        self.assertEqual(stored["pipeline"]["status"], "complete")

    def test_response_actions_stay_dry_run_proposals(self):
        res = self.client.post(
            "/api/samples/upload",
            files={"file": ("eicar.txt", EICAR, "application/octet-stream")},
        )
        self.assertEqual(res.status_code, 200, res.text)
        actions = res.json()["document"]["response_actions"]
        for action in actions:
            self.assertEqual(action["mode"], "dry_run")
            self.assertEqual(action["status"], "proposed")
            self.assertFalse(action["approval"]["required"])

    def test_password_protected_zip_is_unpacked_in_memory(self):
        import pyzipper

        buffer = io.BytesIO()
        with pyzipper.AESZipFile(
            buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as zf:
            zf.setpassword(b"infected")
            zf.writestr("payload.exe", EICAR)

        res = self.client.post(
            "/api/samples/upload",
            files={"file": ("sample.zip", buffer.getvalue(), "application/zip")},
        )
        self.assertEqual(res.status_code, 200, res.text)
        document = res.json()["document"]
        self.assertEqual(document["sample"]["original_name"], "payload.exe")
        import hashlib

        self.assertEqual(
            document["sample"]["sha256"], hashlib.sha256(EICAR).hexdigest()
        )

    def test_empty_upload_is_rejected(self):
        res = self.client.post(
            "/api/samples/upload",
            files={"file": ("empty.bin", b"", "application/octet-stream")},
        )
        self.assertEqual(res.status_code, 422)

    def test_missing_analysis_returns_404(self):
        res = self.client.get("/api/analyses/00000000-0000-4000-8000-000000000000/view")
        self.assertEqual(res.status_code, 404)


def document_status(payload):
    return payload["document"]["dynamic"]["status"]


class SandboxFailurePathTests(unittest.TestCase):
    """A configured but unreachable sandbox must fail loudly, not silently."""

    def setUp(self):
        self._old_cape_url = os.environ.get("TRAC_CAPE_URL")
        self._old_cape_token = os.environ.get("TRAC_CAPE_TOKEN")
        os.environ["TRAC_CAPE_URL"] = "http://127.0.0.1:1/"
        os.environ.pop("TRAC_CAPE_TOKEN", None)
        self.addCleanup(self._restore_cape_env)

        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        self._old_vault = os.environ.get("VAULT_STORAGE_PATH")
        os.environ["VAULT_STORAGE_PATH"] = str(tmp / "vault")
        self.addCleanup(self._restore_vault_env)

        self.engine = create_engine(
            f"sqlite:///{(tmp / 'm8_fail.db').as_posix()}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(bind=self.engine)
        self.addCleanup(self.engine.dispose)
        self.session_factory = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def _restore_cape_env(self):
        if self._old_cape_url is None:
            os.environ.pop("TRAC_CAPE_URL", None)
        else:
            os.environ["TRAC_CAPE_URL"] = self._old_cape_url
        if self._old_cape_token is None:
            os.environ.pop("TRAC_CAPE_TOKEN", None)
        else:
            os.environ["TRAC_CAPE_TOKEN"] = self._old_cape_token

    def _restore_vault_env(self):
        if self._old_vault is None:
            os.environ.pop("VAULT_STORAGE_PATH", None)
        else:
            os.environ["VAULT_STORAGE_PATH"] = self._old_vault

    def test_failed_sandbox_is_recorded_and_labelled(self):
        from m7_core.services.pipeline_runner import run_full_pipeline

        document = run_full_pipeline(raw_bytes=EICAR, original_filename="eicar.bin")

        self.assertEqual(document["dynamic"]["status"], "failed")
        self.assertNotIn("_error", document["dynamic"])
        self.assertNotIn("_static_capabilities", document["dynamic"])

        errors = document["pipeline"]["errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["stage"], "dynamic")
        self.assertEqual(errors[0]["code"], "SANDBOX_FAILED")
        self.assertTrue(errors[0]["message"])

        view = build_presentation(document)
        self.assertEqual(view["sandbox"]["label"], SANDBOX_FAILED_LABEL)
        self.assertFalse(view["sandbox"]["observed"])
        self.assertIsNone(view["sandbox"]["telemetry"])
        self.assertEqual(view["sandbox"]["error"], errors[0]["message"])

    def test_failed_sandbox_error_does_not_leak_credentials(self):
        from m7_core.services.pipeline_runner import run_full_pipeline

        os.environ["TRAC_CAPE_URL"] = "http://operator:hunter2@127.0.0.1:1/"
        document = run_full_pipeline(raw_bytes=EICAR, original_filename="eicar.bin")
        message = document["pipeline"]["errors"][0]["message"]
        self.assertNotIn("hunter2", message)
        self.assertNotIn("operator:", message)

    def test_failed_sandbox_survives_the_m7_round_trip(self):
        from contract.tools.validate import validate_document
        from m7_core.services.analysis_service import AnalysisService
        from m7_core.services.pipeline_runner import run_full_pipeline

        document = run_full_pipeline(raw_bytes=EICAR, original_filename="eicar.bin")
        db = self.session_factory()
        try:
            service = AnalysisService(db)
            service.persist_pipeline_result(document)
            stored = service.get_analysis_document(document["analysis_id"])
        finally:
            db.close()

        self.assertEqual(stored["pipeline"]["status"], "failed")
        self.assertEqual(len(stored["pipeline"]["errors"]), 1)
        self.assertEqual(stored["pipeline"]["errors"][0]["stage"], "dynamic")
        self.assertEqual(stored["pipeline"]["errors"][0]["code"], "SANDBOX_FAILED")
        self.assertTrue(stored["pipeline"]["errors"][0]["message"])
        self.assertEqual(validate_document(stored), [])


if __name__ == "__main__":
    unittest.main()
