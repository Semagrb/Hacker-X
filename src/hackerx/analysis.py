"""Analysis tasks: detect brute-force attempts and port scan signatures from logs.

These are simulations built over simple log formats to practice detection logic.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, List, Tuple


@dataclass
class AuthLog:
    ts: datetime
    ip: str
    user: str
    success: bool


@dataclass
class PortLog:
    ts: datetime
    ip: str
    port: int


def detect_bruteforce(logs: Iterable[AuthLog], *, window: timedelta = timedelta(minutes=5), threshold: int = 5) -> List[Tuple[str, str]]:
    """Task: Detect (ip, user) pairs exceeding failed attempts threshold within a sliding window.

    Return a list of tuples (ip, user) flagged.
    """
    failures: Dict[Tuple[str, str], Deque[datetime]] = defaultdict(deque)
    flagged: set[Tuple[str, str]] = set()
    for log in sorted(logs, key=lambda x: x.ts):
        key = (log.ip, log.user)
        if log.success:
            # Reset on success (common lockout policy strategy)
            failures[key].clear()
            continue
        dq = failures[key]
        dq.append(log.ts)
        cutoff = log.ts - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= threshold:
            flagged.add(key)
    return sorted(flagged)


def detect_port_scan(logs: Iterable[PortLog], *, window: timedelta = timedelta(seconds=30), unique_ports: int = 20) -> List[str]:
    """Task: Detect hosts that touched N or more unique ports within the window.
    Return a sorted list of IPs flagged.
    """
    by_ip: Dict[str, Deque[Tuple[datetime, int]]] = defaultdict(deque)
    flagged: set[str] = set()
    for log in sorted(logs, key=lambda x: x.ts):
        dq = by_ip[log.ip]
        dq.append((log.ts, log.port))
        cutoff = log.ts - window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if len({p for _, p in dq}) >= unique_ports:
            flagged.add(log.ip)
    return sorted(flagged)
