import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

# Set environment variables for testing
os.environ["SECRET_KEY"] = "testsecret"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["FRONTEND_URL"] = "https://frontend.example"

import main
from main import app, limiter
from database import Base, get_db
import models
import auth

# Setup test database
engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    storage = getattr(limiter, "_storage", None)
    if storage and hasattr(storage, "reset"):
        storage.reset()
    yield

def create_user(
    email: str = "user@example.com",
    password: str = "password123",
    is_verified: bool = True,
    **overrides,
):
    db = TestingSessionLocal()
    user = models.User(
        email=email,
        full_name=overrides.pop("full_name", "Test User"),
        hashed_password=auth.get_password_hash(password),
        is_verified=is_verified,
        **overrides,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_register_success():
    response = client.post(
        "/register",
        json={
            "email": "test@example.com",
            "password": "strongpassword123",
            "full_name": "Test User"
        }
    )
    assert response.status_code == 200
    assert "If the email is not verified" in response.json()["message"]

def test_verify_otp_success_logs_user_in():
    raw_otp = "123456"
    create_user(
        email="otp@example.com",
        is_verified=False,
        otp_code=auth.get_password_hash(raw_otp),
        otp_expires_at=datetime.utcnow() + timedelta(minutes=10),
    )

    response = client.post("/verify-otp", json={"email": "otp@example.com", "otp": raw_otp})

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]

    db = TestingSessionLocal()
    user = db.query(models.User).filter(models.User.email == "otp@example.com").one()
    assert user.is_verified is True
    assert user.otp_code is None
    assert user.otp_expires_at is None
    db.close()

def test_register_weak_password():
    response = client.post(
        "/register",
        json={
            "email": "test2@example.com",
            "password": "weak",
            "full_name": "Test User"
        }
    )
    assert response.status_code == 422 # Pydantic validation error

def test_rate_limiting():
    # Send 6 requests, the 6th should be rate limited (limit is 5/minute)
    for _ in range(5):
        client.post(
            "/register",
            json={
                "email": "test3@example.com",
                "password": "strongpassword123",
                "full_name": "Test User"
            }
        )
    
    response = client.post(
        "/register",
        json={
            "email": "test4@example.com",
            "password": "strongpassword123",
            "full_name": "Test User"
        }
    )
    assert response.status_code == 429 # Too Many Requests

def test_login_verified_user_success():
    create_user(email="login@example.com", password="oldpassword123", is_verified=True)

    response = client.post(
        "/login",
        data={"username": "login@example.com", "password": "oldpassword123"}
    )

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["access_token"]
    assert response.json()["refresh_token"]


def test_login_unverified_user_rejected():
    create_user(email="pending@example.com", password="password123", is_verified=False)

    response = client.post(
        "/login",
        data={"username": "pending@example.com", "password": "password123"}
    )

    assert response.status_code == 401
    assert "Email not verified" in response.json()["detail"]


# ── Password Recovery Tests ────────────────────────────────────────────────────

def test_forgot_password_always_200():
    """Endpoint always returns 200 regardless of whether the email exists."""
    # Non-existent email — must still return 200 (no enumeration)
    response = client.post("/forgot-password", json={"email": "nobody@example.com"})
    assert response.status_code == 200
    assert "reset link" in response.json()["message"]


def test_forgot_password_existing_unverified_user():
    """Unverified users should NOT receive a reset link (token not set)."""
    # Register without verifying
    client.post(
        "/register",
        json={"email": "unverified@example.com", "password": "password123", "full_name": "Unverified"}
    )
    response = client.post("/forgot-password", json={"email": "unverified@example.com"})
    # Still returns 200 (enumeration protection), but no token set for unverified user
    assert response.status_code == 200
    db = TestingSessionLocal()
    user = db.query(models.User).filter(models.User.email == "unverified@example.com").one()
    assert user.reset_token is None
    assert user.reset_token_expires_at is None
    db.close()


def test_forgot_password_reset_link_includes_token(monkeypatch):
    sent = {}

    def fake_send_password_reset_email(to_email: str, reset_link: str, reset_token: str):
        sent["to_email"] = to_email
        sent["reset_link"] = reset_link
        sent["reset_token"] = reset_token

    monkeypatch.setattr("main.send_password_reset_email", fake_send_password_reset_email)
    create_user(email="forgot@example.com", is_verified=True)

    response = client.post("/forgot-password", json={"email": "forgot@example.com"})

    assert response.status_code == 200
    assert sent["to_email"] == "forgot@example.com"
    parsed = urlparse(sent["reset_link"])
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "https://frontend.example/reset-password"
    assert parse_qs(parsed.query)["token"] == [sent["reset_token"]]


def test_reset_password_invalid_token():
    """Submitting a bogus token returns 400."""
    response = client.post(
        "/reset-password",
        json={"token": "completely-invalid-token-1234567890", "new_password": "newpassword123"}
    )
    assert response.status_code == 400
    assert "Invalid" in response.json()["detail"]


def test_reset_password_valid_token():
    """Full happy-path: register → verify → forgot → reset → login with new password."""
    # 1. Create a verified user directly in the test DB
    db = TestingSessionLocal()
    hashed_pw = auth.get_password_hash("oldpassword123")
    user = models.User(
        email="resetme@example.com",
        full_name="Reset User",
        hashed_password=hashed_pw,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # 2. Simulate what /forgot-password does: write a raw token into the DB
    raw_token = "test-reset-token-abc123456789012345"
    user.reset_token = auth.get_password_hash(raw_token)
    user.reset_token_expires_at = datetime.utcnow() + timedelta(minutes=15)
    db.commit()
    db.close()

    # 3. Call /reset-password with the raw token
    response = client.post(
        "/reset-password",
        json={"token": raw_token, "new_password": "newpassword456"}
    )
    assert response.status_code == 200
    assert "Password updated" in response.json()["message"]

    # 4. Confirm the old password no longer works
    old_login = client.post(
        "/login",
        data={"username": "resetme@example.com", "password": "oldpassword123"}
    )
    assert old_login.status_code == 401

    # 5. Confirm the new password works
    new_login = client.post(
        "/login",
        data={"username": "resetme@example.com", "password": "newpassword456"}
    )
    assert new_login.status_code == 200
    assert "access_token" in new_login.json()


def test_reset_password_weak_password():
    """Password shorter than 8 chars is rejected by Pydantic (422)."""
    response = client.post(
        "/reset-password",
        json={"token": "any-token", "new_password": "short"}
    )
    assert response.status_code == 422


def test_cashfree_order_uses_dotenv_credentials(monkeypatch):
    monkeypatch.setenv("CASHFREE_APP_ID", "test_app_id")
    monkeypatch.setenv("CASHFREE_SECRET", "test_secret")
    monkeypatch.setenv("CASHFREE_API_VERSION", "2023-08-01")

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    async def fake_post(self, url, headers, json):
        assert headers["x-client-id"] == os.getenv("CASHFREE_APP_ID")
        assert headers["x-client-secret"] == os.getenv("CASHFREE_SECRET")
        return FakeResponse({"order_id": "order_123", "status": "OK"})

    monkeypatch.setattr(main.httpx.AsyncClient, "post", fake_post)

    response = client.post(
        "/cashfree-orders",
        json={"order_id": "order_123"},
    )

    assert response.status_code == 200
    assert response.json() == {"order_id": "order_123", "status": "OK"}


def test_meetup_registration_stores_cashfree_transaction_id():
    create_user(email="meetup@example.com", password="password123", is_verified=True)
    token_response = auth.create_token_pair("meetup@example.com")

    response = client.post(
        "/meetup-registration",
        headers={"Authorization": f"Bearer {token_response['access_token']}"},
        json={
            "adults": 2,
            "children_6_12": 1,
            "children_under_6": 0,
            "amount_paid": 650,
            "cashfree_transaction_id": "2211547434",
        },
    )

    assert response.status_code == 200

    db = TestingSessionLocal()
    user = db.query(models.User).filter(models.User.email == "meetup@example.com").one()
    assert user.registration_status is True
    assert user.registered_adults == 2
    assert user.cashfree_transaction_id == "2211547434"
    db.close()
