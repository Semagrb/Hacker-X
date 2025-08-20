"""Cryptography hygiene tasks: hashing, constant-time compare, JWT verify.

Use only standard and vetted primitives. No custom crypto.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Optional

import jwt


@dataclass
class PasswordHash:
    salt: bytes
    iterations: int
    hash: bytes

    def to_storage(self) -> str:
        return f"pbkdf2$sha256${self.iterations}${base64.urlsafe_b64encode(self.salt).decode()}${base64.urlsafe_b64encode(self.hash).decode()}"

    @staticmethod
    def from_storage(s: str) -> "PasswordHash":
        algo, digest, it_s, salt_b64, hash_b64 = s.split("$")
        if algo != "pbkdf2" or digest != "sha256":
            raise ValueError("Unsupported storage format")
        return PasswordHash(
            salt=base64.urlsafe_b64decode(salt_b64),
            iterations=int(it_s),
            hash=base64.urlsafe_b64decode(hash_b64),
        )


def hash_password(password: str, *, iterations: int = 210000, salt: Optional[bytes] = None) -> PasswordHash:
    """Task: Derive a password hash with PBKDF2-HMAC-SHA256.

    - Use at least 210k iterations by default.
    - Generate a 16-byte random salt if not provided.
    - Return structured result suitable for storage.
    """
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)
    return PasswordHash(salt=salt, iterations=iterations, hash=dk)


def verify_password(password: str, stored: str) -> bool:
    """Task: Verify a password against stored representation.

    - Must use constant-time compare for the derived hash bytes.
    - Accept only our own storage format.
    """
    try:
        ph = PasswordHash.from_storage(stored)
    except Exception:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), ph.salt, ph.iterations, dklen=32)
    return hmac.compare_digest(dk, ph.hash)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Task: Provide a constant-time bytes comparison wrapper.
    """
    return hmac.compare_digest(a, b)


def verify_jwt(token: str, key: str, *, audience: Optional[str] = None, issuer: Optional[str] = None) -> Optional[dict]:
    """Task: Verify a JWT using HS256 and optional audience/issuer checks.

    - Accept only HS256 algorithm.
    - On any verification failure, return None.
    - On success, return the decoded claims dict.
    """
    try:
        return jwt.decode(
            token,
            key,
            algorithms=["HS256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp"]},
        )
    except Exception:
        return None
