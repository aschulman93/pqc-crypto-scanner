"""
pycryptodome-style usage, to confirm the scanner isn't tied to just
one crypto library.
"""

from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC


def generate_key():
    key = RSA.generate(2048)
    return key


def generate_ecc_key():
    key = ECC.generate(curve="P-256")
    return key


def safe_hash(data: bytes) -> str:
    # Negative control: this should NOT be flagged
    import hashlib
    return hashlib.sha256(data).hexdigest()
