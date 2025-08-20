import base64
import os
import time

import jwt

from hackerx import crypto


def test_hash_and_verify_password_roundtrip():
    ph = crypto.hash_password("Tr0ub4dor&3")
    stored = ph.to_storage()
    assert crypto.verify_password("Tr0ub4dor&3", stored)
    assert not crypto.verify_password("wrong", stored)


def test_constant_time_compare():
    a = b"A" * 32
    b = b"A" * 31 + b"B"
    assert crypto.constant_time_compare(a, a)
    assert not crypto.constant_time_compare(a, b)


def test_verify_jwt_hs256_only():
    key = "secret"
    payload = {"sub": "u1", "exp": int(time.time()) + 30}
    token = jwt.encode(payload, key, algorithm="HS256")
    decoded = crypto.verify_jwt(token, key)
    assert decoded and decoded["sub"] == "u1"
    # Wrong key
    assert crypto.verify_jwt(token, "wrong") is None
