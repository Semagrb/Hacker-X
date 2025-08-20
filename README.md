# Hacker-X

Ethical hacking learning repo with hands-on, code-first tasks and tests. Everything runs locally and avoids real targets or networks. Focus is on safe techniques, secure coding, and detection logic.

## What’s inside

- src/hackerx/
  - web.py — XSS escaping, SQL parameterization, CSRF tokens
  - crypto.py — password hashing (PBKDF2), constant-time compare, JWT verify
  - analysis.py — log analysis for brute-force and port scans (simulated)
  - security.py — SSRF-safe URL validation, rate limiting, path canonicalization
  - io_utils.py — safe ZIP extraction (zip-slip), file hashing
- tests/ — pytest suites for each module

All tasks include docstrings explaining the goal. Tests act as acceptance criteria.

## Ethics and Safety

- For education. Use only on systems you own or have explicit permission to test.
- No scanning, exploitation, or traffic to external hosts is performed.
- Tasks simulate patterns and focus on defensive and safe offensive techniques.

## Quick start

- Requirements: Python 3.9+
- Install dev deps and run tests

```powershell
python -m venv .venv ; .\.venv\Scripts\Activate.ps1 ; pip install -r requirements.txt ; pytest -q
```

## Topics covered

- Input validation and output encoding (preventing XSS, SQLi)
- Cryptography hygiene (hashing, HMAC, constant-time ops)
- Token-based protections (CSRF)
- Log and artifact analysis (brute-force detection)
- Supply-chain/file safety (zip slip, file integrity)
- SSRF and URL allowlisting; private IP blocking
- Safe path handling
- Simple rate limiting

## Contributing

- Add new tasks under `src/hackerx/` and tests in `tests/`.
- Keep tasks safe and self-contained. Prefer simulations over live targets.
