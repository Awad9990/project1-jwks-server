\# Project 1 - JWKS Server (CSCE 3550)



\## Overview

FastAPI JWKS server that:

\- Generates RSA key pairs with `kid` and expiry (`exp`)

\- Serves a JWKS at `/.well-known/jwks.json` containing only unexpired public keys

\- Issues JWTs at `/auth` (POST)

\- If `?expired=true` is provided, returns a JWT signed with an expired key



\## Requirements

\- Python 3.13+

\- Install dependencies:

&nbsp; pip install -r requirements.txt



\## Run the server

python -m uvicorn app:app --host 127.0.0.1 --port 8080



\## Endpoints

\- `GET /.well-known/jwks.json` -> JWKS (unexpired keys only)

\- `POST /auth` -> valid JWT

\- `POST /auth?expired=true` -> expired JWT



\## Run tests + coverage

pytest --cov=. --cov-report=term-missing



