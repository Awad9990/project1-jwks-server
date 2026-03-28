# Program Name: JWKS Server
# Name: Awad Aljaidi
# Purpose: This program creates a JWKS server that returns public keys
# and generates JWT tokens.

import base64
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

app = FastAPI()
DB_FILE = str(Path(__file__).resolve().parent / "totally_not_my_privateKeys.db")


# Convert integer values into base64url format for JWK fields
def b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# Open a connection to the SQLite database
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


# Create the keys table if it does not already exist
def init_db() -> None:
    with closing(get_db_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )
        conn.commit()


# Turn a private key into bytes so it can be stored in the database
def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


# Load a private key back from the database
def deserialize_private_key(key_data: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(key_data, password=None)


@dataclass
class KeyEntry:
    kid: str
    exp: int
    private_key: rsa.RSAPrivateKey

    # Build the public JWK from the private key
    def public_jwk(self) -> Dict[str, str]:
        pub = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": b64url_uint(pub.n),
            "e": b64url_uint(pub.e),
        }


class KeyStore:
    def __init__(self) -> None:
        init_db()
        self.seed_keys_if_needed()
        self._load_cached_keys()

    # Generate a new RSA private key
    def _generate_private_key(self) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    # Add one valid key and one expired key
    # when the database is empty
    def seed_keys_if_needed(self) -> None:
        with closing(get_db_connection()) as conn:
            count_row = conn.execute(
                "SELECT COUNT(*) AS count FROM keys"
            ).fetchone()
            if count_row["count"] > 0:
                return

            now = int(time.time())

            valid_key = self._generate_private_key()
            expired_key = self._generate_private_key()

            conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (serialize_private_key(valid_key), now + 3600),
            )
            conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (serialize_private_key(expired_key), now - 3600),
            )
            conn.commit()

    # Load one active key and one expired key from the database
    def _load_cached_keys(self) -> None:
        now = int(time.time())

        with closing(get_db_connection()) as conn:
            active_row = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY exp ASC
                LIMIT 1
                """,
                (now,),
            ).fetchone()

            expired_row = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp <= ?
                ORDER BY exp DESC
                LIMIT 1
                """,
                (now,),
            ).fetchone()

        if active_row is None or expired_row is None:
            raise ValueError(
                "Database must contain both an active key "
                "and an expired key."
            )

        self.active = KeyEntry(
            kid=str(active_row["kid"]),
            exp=active_row["exp"],
            private_key=deserialize_private_key(active_row["key"]),
        )

        self.expired = KeyEntry(
            kid=str(expired_row["kid"]),
            exp=expired_row["exp"],
            private_key=deserialize_private_key(expired_row["key"]),
        )

    # Return only the valid public keys in JWKS format
    def jwks(self) -> Dict[str, List[Dict[str, str]]]:
        now = int(time.time())
        keys: List[Dict[str, str]] = []

        if self.active.exp > now:
            keys.append(self.active.public_jwk())

        return {"keys": keys}

    # Choose which key to use for token generation
    def pick_for_auth(self, want_expired: bool) -> KeyEntry:
        return self.expired if want_expired else self.active


# Create the keystore when the app starts
keystore = KeyStore()


@app.get("/.well-known/jwks.json")
def jwks():
    return JSONResponse(content=keystore.jwks())


# Extra route in case the tester uses /jwks
@app.get("/jwks")
def jwks_alias():
    return jwks()


@app.post("/auth")
def auth(expired: bool = Query(False)):
    # Pick either the valid key or the expired key
    key = keystore.pick_for_auth(expired)

    payload = {
        "sub": "user",
        "iat": int(time.time()),
        "exp": key.exp,
    }

    # Create and sign the JWT
    token = jwt.encode(
        payload,
        serialize_private_key(key.private_key),
        algorithm="RS256",
        headers={"kid": str(key.kid)},
    )

    return {"token": token}
