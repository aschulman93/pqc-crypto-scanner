"""
detectors.py

Defines what we're looking for and why it matters for PQC migration.
Each detector is a rule: a library+function signature that indicates
use of a quantum-vulnerable algorithm, plus metadata used in reporting.

Keeping this as data (not scattered logic) makes it easy to add more
algorithms later without touching the AST-walking code.
"""

from dataclasses import dataclass


@dataclass
class Finding:
    file: str
    line: int
    algorithm: str
    detail: str
    severity: str
    reason: str
    recommendation: str


# --- Rule definitions -------------------------------------------------
# Each rule matches a specific function call pattern.
# `module` + `func` identify the call (e.g. rsa.generate_private_key).
# `key_size_arg` names the kwarg to inspect for key size, if relevant.

CRYPTOGRAPHY_LIB_RULES = [
    {
        "module_hint": "rsa",
        "func": "generate_private_key",
        "algorithm": "RSA",
        "key_size_arg": "key_size",
        "reason": "RSA relies on integer factorization, which Shor's algorithm "
                  "breaks in polynomial time on a sufficiently large quantum computer.",
        "recommendation": "Migrate to ML-KEM (FIPS 203) for key exchange, or a hybrid "
                           "RSA+ML-KEM scheme during the transition period.",
    },
    {
        "module_hint": "ec",
        "func": "generate_private_key",
        "algorithm": "ECDSA/ECDH",
        "key_size_arg": None,  # uses curve object, not an int
        "reason": "Elliptic curve cryptography relies on the discrete log problem, "
                  "which is also broken by Shor's algorithm.",
        "recommendation": "Migrate signatures to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); "
                           "migrate key exchange to ML-KEM (FIPS 203).",
    },
    {
        "module_hint": "dh",
        "func": "generate_parameters",
        "algorithm": "Diffie-Hellman",
        "key_size_arg": "key_size",
        "reason": "Classical DH key exchange is broken by Shor's algorithm in the "
                  "same way as RSA.",
        "recommendation": "Migrate to ML-KEM (FIPS 203) for key establishment.",
    },
]

PYCRYPTODOME_RULES = [
    {
        "module_hint": "RSA",
        "func": "generate",
        "algorithm": "RSA",
        "key_size_arg": None,  # first positional arg is bits
        "reason": "RSA relies on integer factorization, which Shor's algorithm "
                  "breaks in polynomial time on a sufficiently large quantum computer.",
        "recommendation": "Migrate to ML-KEM (FIPS 203) for key exchange, or a hybrid "
                           "RSA+ML-KEM scheme during the transition period.",
    },
    {
        "module_hint": "ECC",
        "func": "generate",
        "algorithm": "ECDSA/ECDH",
        "key_size_arg": None,
        "reason": "Elliptic curve cryptography relies on the discrete log problem, "
                  "which is also broken by Shor's algorithm.",
        "recommendation": "Migrate signatures to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); "
                           "migrate key exchange to ML-KEM (FIPS 203).",
    },
]

# Weak hash usage — not quantum-specific (Grover's algorithm only halves
# effective hash strength), but worth flagging since it often shows up
# alongside classical-only crypto and signals a codebase that hasn't
# been modernized.
WEAK_HASH_FUNCS = {
    "md5": "MD5 is cryptographically broken (collision attacks) and should not "
           "be used for signing or integrity verification.",
    "sha1": "SHA-1 is deprecated for signing/certificates due to practical "
            "collision attacks.",
}

# NIST-recommended minimum classical key sizes, used to flag undersized
# keys as an *additional* finding even before PQC migration.
MIN_RECOMMENDED_RSA_BITS = 3072
