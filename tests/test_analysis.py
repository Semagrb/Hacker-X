from datetime import datetime, timedelta

from hackerx import analysis


def test_detect_bruteforce_sliding_window():
    ts = datetime(2024, 1, 1, 0, 0, 0)
    logs = []
    for i in range(6):
        logs.append(analysis.AuthLog(ts=ts + timedelta(seconds=i * 30), ip="1.1.1.1", user="a", success=False))
    flagged = analysis.detect_bruteforce(logs, window=timedelta(minutes=3), threshold=5)
    assert ("1.1.1.1", "a") in flagged


def test_detect_port_scan_unique_ports():
    ts = datetime(2024, 1, 1, 0, 0, 0)
    logs = [analysis.PortLog(ts=ts + timedelta(seconds=i), ip="2.2.2.2", port=1000 + i) for i in range(20)]
    flagged = analysis.detect_port_scan(logs, window=timedelta(seconds=30), unique_ports=20)
    assert "2.2.2.2" in flagged
