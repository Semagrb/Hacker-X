"""App security tasks: SSRF-safe URL validation, path safety, and rate limiting.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from time import monotonic
from typing import Dict, Iterable, Optional
from urllib.parse import urlparse


PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_url_safe_for_fetch(url: str, *, allow_schemes=("http", "https"), allow_ports=(80, 443)) -> bool:
    """Task: Validate URLs to mitigate SSRF.

    - Scheme must be http/https.
    - Resolve host to an IP and deny private/link-local/loopback ranges.
      We allow hostnames but deny obvious IP literals in private ranges.
    - Explicit port must be in allow_ports.
    - No credentials in netloc.

    Note: For safety and offline use, we do not perform DNS resolution here.
    Instead, we conservatively block literal private IPs and known bad schemes.
    """
    p = urlparse(url)
    if p.scheme not in allow_schemes:
        return False
    if p.username or p.password:
        return False
    # Deny non-default ports unless explicitly allowed
    if p.port and p.port not in allow_ports:
        return False

    host = p.hostname or ""
    # Block if host is an IP in private ranges
    try:
        ip = ipaddress.ip_address(host)
        if any(ip in net for net in PRIVATE_NETS):
            return False
    except ValueError:
        # not an IP literal, allow hostname format
        pass

    return True


def canonicalize_safe_path(base_dir: str, user_path: str) -> Optional[str]:
    """Task: Prevent path traversal by canonicalizing within base_dir.

    - Join base_dir with user_path and normalize.
    - If resulting path escapes base_dir, return None.
    """
    combined = os.path.normpath(os.path.join(base_dir, user_path))
    base = os.path.abspath(base_dir)
    combined_abs = os.path.abspath(combined)
    if os.path.commonpath([base]) != os.path.commonpath([base, combined_abs]):
        return None
    return combined_abs


@dataclass
class TokenBucket:
    capacity: int
    refill_rate_per_sec: float
    tokens: float
    last: float

    @classmethod
    def create(cls, capacity: int, refill_rate_per_sec: float) -> "TokenBucket":
        now = monotonic()
        return cls(capacity=capacity, refill_rate_per_sec=refill_rate_per_sec, tokens=float(capacity), last=now)

    def allow(self, cost: float = 1.0) -> bool:
        now = monotonic()
        # Refill
        elapsed = now - self.last
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate_per_sec)
        self.last = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False
