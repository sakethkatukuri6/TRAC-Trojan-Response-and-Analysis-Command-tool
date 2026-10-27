"""Pytest fixtures for M7 Core tests."""
import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from m7_core.database import Base, get_db
from m7_core.api.app import app
from m7_core.api.auth import create_module_token, create_user_token, get_password_hash
from m7_core.models.user import UserModel

TEST_DB_URL = "sqlite:///./test_m7.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    # Seed default test users
    db = TestingSessionLocal()
    if not db.query(UserModel).filter(UserModel.username == "admin_user").first():
        db.add(UserModel(
            username="admin_user",
            hashed_password=get_password_hash("adminpass123"),
            role="admin"
        ))
        db.add(UserModel(
            username="analyst_user",
            hashed_password=get_password_hash("analystpass123"),
            role="analyst"
        ))
        db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_m7.db"):
        try:
            os.remove("./test_m7.db")
        except Exception:
            pass


@pytest.fixture
def db_session():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def m6_token():
    return create_module_token("M6")


@pytest.fixture
def m5_token():
    return create_module_token("M5")


@pytest.fixture
def analyst_token():
    return create_user_token("analyst_user", "analyst")


@pytest.fixture
def admin_token():
    return create_user_token("admin_user", "admin")
