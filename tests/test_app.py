from fastapi.testclient import TestClient
import jwt

from app import app, keystore

client = TestClient(app)

def test_jwks_only_unexpired_key_served():
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert len(data["keys"]) == 1
    assert data["keys"][0]["kid"] == keystore.active.kid

def test_auth_returns_jwt_with_kid_header():
    r = client.post("/auth")
    assert r.status_code == 200
    token = r.json()["token"]
    header = jwt.get_unverified_header(token)
    assert "kid" in header
    assert header["kid"] == keystore.active.kid

def test_auth_expired_true_returns_expired_token():
    r = client.post("/auth?expired=true")
    assert r.status_code == 200
    token = r.json()["token"]
    payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    assert payload["exp"] == keystore.expired.exp
