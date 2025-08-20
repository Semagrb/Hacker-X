"""I/O safety tasks, including zip-slip prevention and file hashing.
"""
from __future__ import annotations

import hashlib
import os
import zipfile
from typing import Iterable, Optional


def safe_extract_zip(zip_path: str, dest_dir: str) -> list[str]:
    """Task: Extract a zip file safely preventing Zip Slip.

    - Reject members whose normalized paths escape dest_dir.
    - Create directories as needed.
    - Return list of extracted absolute paths.
    """
    extracted: list[str] = []
    base = os.path.abspath(dest_dir)
    os.makedirs(base, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            # Normalize path
            normalized = os.path.normpath(member.filename)
            target = os.path.abspath(os.path.join(base, normalized))
            if os.path.commonpath([base]) != os.path.commonpath([base, target]):
                # Attempted traversal
                continue
            if member.is_dir() or member.filename.endswith("/"):
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(member, "r") as src, open(target, "wb") as dst:
                dst.write(src.read())
            extracted.append(target)
    return extracted


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Task: Compute SHA-256 of a file in chunks.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()
