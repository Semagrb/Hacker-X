import base64
import hmac
import time
from hashlib import sha256

import pytest

from hackerx import web


def test_escape_for_html_basic_and_idempotent():
    s = '<script>alert("x");</script>'
    escaped = web.escape_for_html(s)
    assert escaped == '&lt;script&gt;alert(&quot;x&quot;);&lt;/script&gt;'
    # Idempotent
    assert web.escape_for_html(escaped) == escaped


def test_sql_parameterize_no_interpolation_and_mixed_style_rejected():
    q, p = web.sql_parameterize("SELECT * FROM t WHERE a = ? AND b > ?", ("x", 1))
    assert q.endswith("? AND b > ?") and p == ("x", 1)
    with pytest.raises(ValueError):
        web.sql_parameterize("SELECT * FROM t WHERE a = %s AND b > ?", ("x", 1))


def test_csrf_tokens_issue_and_validate():
    secret = b"k"
    sid = "sess-1"
    token = web.csrf_issue_token(sid, secret)
    assert web.csrf_validate_token(sid, secret, token)
    # tampered
    bad = token[:-1] + ("0" if token[-1] != "0" else "1")
    assert not web.csrf_validate_token(sid, secret, bad)


def test_csrf_ttl_token_expires():
    secret = b"k"
    sid = "sess-2"
    token = web.make_ttl_token(sid, secret, ttl_seconds=1)
    assert web.csrf_validate_token(sid, secret, token, ttl_seconds=5)
    # Simulate expiry by crafting an old token
    rnd, mac = token.split(".")
    rnd_core, ts_s = rnd.split("|")
    old_ts = str(int(ts_s) - 10)
    old_token = f"{rnd_core}|{old_ts}.{hmac.new(secret, f'{sid}.{rnd_core}|{old_ts}'.encode(), sha256).hexdigest()}"
    assert not web.csrf_validate_token(sid, secret, old_token, ttl_seconds=5)
