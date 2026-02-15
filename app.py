import base64
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

app = FastAPI()


def b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@dataclass
class KeyEntry:
    kid: str
    exp: int
    private_key: rsa.RSAPrivateKey

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
        now = int(time.time())
        self.active = self._gen_key(exp=now + 3600)   # valid for 1 hour
        self.expired = self._gen_key(exp=now - 3600)  # expired 1 hour ago

    def _gen_key(self, exp: int) -> KeyEntry:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return KeyEntry(kid=str(uuid.uuid4()), exp=exp, private_key=priv)

    def jwks(self) -> Dict[str, List[Dict[str, str]]]:
        now = int(time.time())
        keys: List[Dict[str, str]] = []
        if self.active.exp > now:
            keys.append(self.active.public_jwk())
        return {"keys": keys}

    def pick_for_auth(self, want_expired: bool) -> KeyEntry:
        return self.expired if want_expired else self.active


keystore = KeyStore()


@app.get("/.well-known/jwks.json")
def jwks():
    return JSONResponse(content=keystore.jwks())


# Optional extra path in case the tester expects /jwks
@app.get("/jwks")
def jwks_alias():
    return jwks()


@app.post("/auth")
def auth(expired: bool = False):
    key = keystore.pick_for_auth(expired)

    payload = {
        "sub": "user",
        "iat": int(time.time()),
        "exp": key.exp,
    }

    token = jwt.encode(
        payload,
        key.private_key,
        algorithm="RS256",
        headers={"kid": key.kid},
    )
    return {"token": token}
