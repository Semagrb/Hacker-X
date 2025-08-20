"""Web security tasks: escaping, parameterization, and CSRF tokens.

Each function includes a docstring describing the task and constraints.
All are pure Python and safe to run locally.
"""
from __future__ import annotations

import html
import hmac
import os
import secrets
import time
from hashlib import sha256
from typing import Dict, Tuple
import re


def escape_for_html(user_input: str) -> str:
    """Task: Implement proper output encoding for HTML contexts.

    Requirements:
    - Must convert special chars (<, >, &, ", ') to HTML entities.
    - Should be idempotent (double-escaping avoided).

    Hint: Prefer stdlib helpers to manual replacement.
    """
    # Implement idempotent escaping: escape bare ampersands only, then <, >, and quotes.
    # Do not double-escape existing entities like &amp; or &quot;.
    amp_pattern = re.compile(r"&(?!#\d+;|#x[0-9A-Fa-f]+;|\w+;)")
    s = amp_pattern.sub("&amp;", user_input)
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace('"', "&quot;").replace("'", "&#x27;")
    return s


def sql_parameterize(query: str, params: Tuple[object, ...]) -> Tuple[str, Tuple[object, ...]]:
    """Task: Return a parameterized SQL statement and parameters tuple.

    Constraints:
    - Do not interpolate params into the string.
    - Use positional placeholders (e.g., ? for SQLite or %s for others).
    - Keep this function DB-agnostic by not executing anything.

    Example:
    >>> sql_parameterize("SELECT * FROM users WHERE name = ? AND age > ?", ("alice", 20))
    ("SELECT * FROM users WHERE name = ? AND age > ?", ("alice", 20))
    """
    if "%s" in query and "?" in query:
        raise ValueError("Mixed placeholder styles are not allowed")
    return query, params


def csrf_issue_token(session_id: str, secret_key: bytes) -> str:
    """Task: Create a CSRF token bound to a session_id using HMAC-SHA256.

    - Token format: base64-url of: random_16_bytes || '.' || hex(hmac(secret, session_id || '.' || random))
    - Use time-safe comparison when validating (see validator).
    """
    rnd = secrets.token_urlsafe(16)
    mac = hmac.new(secret_key, f"{session_id}.{rnd}".encode(), sha256).hexdigest()
    return f"{rnd}.{mac}"


def csrf_validate_token(session_id: str, secret_key: bytes, token: str, ttl_seconds: int | None = 3600) -> bool:
    """Task: Validate a CSRF token.

    - Recompute HMAC for provided session_id and token's random part.
    - Use hmac.compare_digest for constant-time comparison.
    - Optionally support TTL by embedding a timestamp in the random part (here we simulate via a signed timestamp suffix).
    """
    try:
        rnd, mac_hex = token.split(".", 1)
    except ValueError:
        return False

    # Optional TTL support: if rnd contains a timestamp suffix (rnd|ts), enforce it.
    if "|" in rnd and ttl_seconds is not None:
        try:
            rnd_core, ts_s = rnd.split("|", 1)
            ts = int(ts_s)
        except Exception:
            return False
        now = int(time.time())
        if now - ts > ttl_seconds:
            return False
        # When a timestamp suffix is present, the MAC covers the full rnd including timestamp
        rnd_check = rnd
    else:
        rnd_check = rnd

    mac = hmac.new(secret_key, f"{session_id}.{rnd_check}".encode(), sha256).hexdigest()
    return hmac.compare_digest(mac_hex, mac)


def make_ttl_token(session_id: str, secret_key: bytes, ttl_seconds: int) -> str:
    """Helper: issue a CSRF token with timestamp suffix for TTL validation.
    """
    rnd = secrets.token_urlsafe(16)
    ts = int(time.time())
    rnd_with_ts = f"{rnd}|{ts}"
    mac = hmac.new(secret_key, f"{session_id}.{rnd_with_ts}".encode(), sha256).hexdigest()
    return f"{rnd_with_ts}.{mac}"
