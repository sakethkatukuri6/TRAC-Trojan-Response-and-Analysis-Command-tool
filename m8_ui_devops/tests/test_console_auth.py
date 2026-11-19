"""Console authentication tests.

The console role picker used to be purely client-side decoration; these tests
pin the real session behavior: bootstrap admin creation, cookie-based login,
role enforcement on the upload route, and logout.
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

from m7_core.database import get_db, init_db
from m8_ui_devops.auth import ensure_bootstrap_admin
from m8_ui_devops.cli import create_dashboard_app

BOOTSTRAP_PASSWORD = "auth-test-admin-pass"


class ConsoleAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        self._old_vault = os.environ.get("VAULT_STORAGE_PATH")
        os.environ["VAULT_STORAGE_PATH"] = str(tmp / "vault")
        self.addCleanup(self._restore_vault_env)
        os.environ["TRAC_BOOTSTRAP_ADMIN_PASSWORD"] = BOOTSTRAP_PASSWORD
        self.addCleanup(os.environ.pop, "TRAC_BOOTSTRAP_ADMIN_PASSWORD", None)

        self.engine = create_engine(
            f"sqlite:///{(tmp / 'auth_test.db').as_posix()}",
            connect_args={"check_same_thread": False},
        )
        init_db(self.engine)
        self.addCleanup(self.engine.dispose)
        self.session_factory = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        with self.session_factory() as db:
            ensure_bootstrap_admin(db)

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

    def _login(self, username="admin", password=BOOTSTRAP_PASSWORD):
        return self.client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )

    def test_bootstrap_admin_is_created_once(self):
        from m7_core.models.user import UserModel

        with self.session_factory() as db:
            admin = db.query(UserModel).filter(UserModel.username == "admin").first()
            self.assertIsNotNone(admin)
            self.assertEqual(admin.role, "admin")
            # Second call must not duplicate or overwrite.
            ensure_bootstrap_admin(db)
            count = db.query(UserModel).count()
        self.assertEqual(count, 1)

    def test_me_reports_unauthenticated_without_session(self):
        res = self.client.get("/api/auth/me")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["authenticated"], False)

    def test_login_sets_httponly_session_cookie(self):
        res = self._login()
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["role"], "admin")
        cookie = res.headers.get("set-cookie", "")
        self.assertIn("trac_console_session=", cookie)
        self.assertIn("HttpOnly", cookie)

    def test_wrong_password_rejected(self):
        res = self._login(password="definitely-wrong")
        self.assertEqual(res.status_code, 401)

    def test_me_reports_session_after_login(self):
        self._login()
        res = self.client.get("/api/auth/me")
        self.assertEqual(res.json()["authenticated"], True)
        self.assertEqual(res.json()["username"], "admin")
        self.assertEqual(res.json()["role"], "admin")

    def test_upload_requires_authentication(self):
        res = self.client.post(
            "/api/samples/upload",
            files={"file": ("sample.bin", io.BytesIO(b"MZ\x90\x00" + b"\x00" * 64), "application/octet-stream")},
        )
        self.assertEqual(res.status_code, 401)

    def test_upload_succeeds_for_signed_in_analyst_role(self):
        from m7_core.models.user import UserModel
        from m7_core.api.auth import get_password_hash

        with self.session_factory() as db:
            db.add(
                UserModel(
                    username="analyst_one",
                    hashed_password=get_password_hash("analyst-pass-123"),
                    role="analyst",
                )
            )
            db.commit()

        self._login(username="analyst_one", password="analyst-pass-123")
        res = self.client.post(
            "/api/samples/upload",
            files={"file": ("sample.bin", io.BytesIO(b"MZ\x90\x00" + b"\x00" * 64), "application/octet-stream")},
        )
        # A garbage non-PE payload still passes authentication; the pipeline
        # decides the verdict. 4xx would mean auth rejected the request.
        self.assertNotEqual(res.status_code, 401)
        self.assertNotEqual(res.status_code, 403)

    def test_logout_clears_session(self):
        self._login()
        self.client.post("/api/auth/logout")
        res = self.client.get("/api/auth/me")
        self.assertEqual(res.json()["authenticated"], False)


if __name__ == "__main__":
    unittest.main()
