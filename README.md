# Project 1 / Project 2 - JWKS Server (CSCE 3550)

## Name
Awad Aljaidi

## Overview
This project implements a JWKS server using FastAPI and SQLite.

The server:
- generates RSA key pairs with unique `kid` values and expiration times
- stores private keys in a SQLite database
- serves a JWKS at `/.well-known/jwks.json` containing only unexpired public keys
- issues JWTs at `/auth` using a valid key by default
- issues a JWT signed with an expired key when `?expired=true` is provided

For Project 2, the same project was extended and tested against the provided blackbox testing client.

## Features
- FastAPI REST API
- SQLite-backed key storage
- RSA key generation and serialization
- JWKS endpoint for valid public keys
- JWT generation endpoint
- support for expired JWT generation
- parameterized SQL queries
- linted code
- automated tests with coverage above 80%

## Requirements
- Python 3.13+
- Install dependencies with:

```bash
pip install -r requirements.txt

## Note

I tested this project with the provided gradebot. The required local checks passed successfully, including `/auth`, JWKS, database existence, and parameterized SQL. The only remaining item was the `Quality` check, which returned `503 Service Unavailable` during testing.