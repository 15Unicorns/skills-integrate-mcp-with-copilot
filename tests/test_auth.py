import json
import time

import pytest
from fastapi.testclient import TestClient

from src import auth
from src.app import app


@pytest.fixture()
def client(monkeypatch):
    password_hash = auth.hash_password("correct-password")
    monkeypatch.setenv(
        "AUTH_USERS_JSON",
        json.dumps(
            {
                "teacher@mergington.edu": {
                    "password_hash": password_hash,
                    "role": "staff",
                    "tenant_id": "mergington-high-school",
                },
                "other-school@example.com": {
                    "password_hash": password_hash,
                    "role": "staff",
                    "tenant_id": "other-school",
                },
            }
        ),
    )
    auth.active_tokens.clear()
    auth.token_expirations.clear()
    return TestClient(app)


def login(client, username="teacher@mergington.edu"):
    response = client.post(
        "/auth/login",
        json={"username": username, "password": "correct-password"},
    )
    return response.json()["access_token"]


def test_login_returns_bearer_token(client):
    response = client.post(
        "/auth/login",
        json={
            "username": "teacher@mergington.edu",
            "password": "correct-password",
        },
    )

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["role"] == "staff"


def test_invalid_login_does_not_reveal_which_credential_failed(client):
    response = client.post(
        "/auth/login",
        json={"username": "teacher@mergington.edu", "password": "wrong"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_activity_mutation_requires_authentication(client):
    response = client.post(
        "/activities/Chess%20Club/signup",
        params={"email": "student@mergington.edu"},
    )

    assert response.status_code == 401


def test_authenticated_staff_can_register(client):
    token = login(client)
    response = client.post(
        "/activities/Chess%20Club/signup",
        params={"email": "student@mergington.edu"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200


def test_token_expiration_is_enforced(client, monkeypatch):
    token = login(client)
    auth.token_expirations[token] = time.time() - 1

    response = client.post(
        "/activities/Chess%20Club/signup",
        params={"email": "student@mergington.edu"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_other_tenant_cannot_access_this_app(client):
    token = login(client, "other-school@example.com")

    response = client.post(
        "/activities/Chess%20Club/signup",
        params={"email": "student@mergington.edu"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403