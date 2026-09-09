# PQC Crypto-Vulnerability Scanner

A static analysis tool that scans Python codebases for use of classical
cryptographic algorithms that are vulnerable to quantum attacks (via
Shor's algorithm), and flags them with a plain-language explanation
and a NIST PQC migration recommendation.

This is project 1 of a 3-part self-directed project series building
toward hands-on PQC engineering skills, informed by NIST's 2024
post-quantum cryptography standards (FIPS 203/204/205). Project 2 will
use this scanner's findings to drive an actual RSA -> ML-KEM migration
demo; project 3 will build a hybrid classical/PQC system on top of that.

## What it detects

| Algorithm | Why it matters | Migration target |
|---|---|---|
| RSA (key generation) | Broken by Shor's algorithm (factoring) | ML-KEM (FIPS 203) |
| ECDSA / ECDH | Broken by Shor's algorithm (discrete log) | ML-DSA (FIPS 204) / ML-KEM |
| Diffie-Hellman | Broken by Shor's algorithm | ML-KEM (FIPS 203) |
| MD5 / SHA-1 usage | Not quantum-specific, but a signal of an unmodernized codebase | SHA-256 / SHA-3 |

Supports both the `cryptography` library and `pycryptodome`, and
resolves import aliases (e.g. `from ... import rsa as keygen`) rather
than relying on exact function names.

It also flags RSA keys below NIST's recommended 3072-bit minimum,
as a secondary (non-quantum) finding.

## How it works

Static analysis via Python's `ast` module, not regex. The scanner:

1. Parses each `.py` file into an AST.
2. Builds a table of import aliases so renamed imports still resolve
   correctly.
3. Walks all function call nodes and checks them against a rule table
   (`detectors.py`) of known quantum-vulnerable call signatures.
4. Reports file, line number, algorithm, key size (where determinable),
   why it matters, and what to migrate to.

## Usage

```bash
cd scanner
python3 scan.py <path-to-scan> --json report.json
```

Example:

```bash
python3 scan.py ../test_fixtures --json ../reports/test_report.json
```

## Validation

- `test_fixtures/` contains intentionally vulnerable sample code
  (RSA, ECDSA, DH, MD5, SHA-1 usage) plus a negative control
  (SHA-256) that should *not* be flagged. Run the scanner against
  it to confirm detection is working (8 findings expected, 0 false
  positives on the negative control).
- Also validated against the real `pyca/cryptography` library's own
  test suite (a production Python codebase that legitimately
  generates RSA/EC/DH keys): correctly surfaced 112 findings across
  11 files with no crashes. Not included in this repo due to size;
  reproduce with:
  ```bash
  git clone --depth 1 https://github.com/pyca/cryptography.git
  python3 scan.py cryptography/tests --json real_world_report.json
  ```

## Current scope / honest limitations

This is a v1 static scanner, built as a portfolio/learning project —
not a production security tool. Known limitations:

- **Python only.** No support yet for other languages, binaries, or
  network traffic analysis (e.g. TLS handshake inspection).
- **No severity nuance yet.** Every quantum-vulnerable finding is
  currently rated "High" regardless of context (a root CA key and an
  ephemeral session key are treated the same). Project 3 (hybrid
  system) is intended to address this with context-aware severity
  based on data lifetime.
- **Call-site detection only.** It flags where vulnerable algorithms
  are *generated*, not every place a resulting key is subsequently
  used.
- **No CI/CD integration yet** (e.g. pre-commit hook, GitHub Action).

## Roadmap

- [ ] Project 2: RSA -> ML-KEM migration demo, using this scanner's
      output to drive the migration.
- [ ] Project 3: Hybrid classical/PQC system, incorporating
      context-aware severity scoring.
- [ ] Expand detection to more languages / config-based key generation.
- [ ] Package as a pre-commit hook.
