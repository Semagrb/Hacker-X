import os
import tempfile
import time
import zipfile

from hackerx import io_utils, security


def test_safe_extract_zip_prevents_traversal(tmp_path):
    zpath = tmp_path / "sample.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("innocent.txt", b"ok")
        zf.writestr("../evil.txt", b"nope")
        zf.writestr("sub/../pivot.txt", b"pivot")
    out = tmp_path / "out"
    extracted = io_utils.safe_extract_zip(str(zpath), str(out))
    assert (out / "innocent.txt").exists()
    assert (out / "pivot.txt").exists()
    assert not (out.parent / "evil.txt").exists()


def test_sha256_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"abc")
    h = io_utils.sha256_file(str(p))
    assert h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_token_bucket_allows_then_limits():
    tb = security.TokenBucket.create(capacity=2, refill_rate_per_sec=1)
    assert tb.allow()
    assert tb.allow()
    # now empty
    assert not tb.allow()
    time.sleep(1.1)
    assert tb.allow()
