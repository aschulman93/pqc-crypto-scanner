"""
Intentionally vulnerable sample code used to validate the scanner.
Mirrors realistic usage patterns you'd find in production codebases.
"""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec as ec_module
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1


def generate_server_key():
    # Undersized AND quantum-vulnerable
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key


def generate_root_ca_key():
    # Correctly sized by classical standards, still quantum-vulnerable
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return key


def generate_ecdsa_signing_key():
    key = ec_module.generate_private_key(SECP384R1())
    return key


def generate_dh_params():
    params = dh.generate_parameters(generator=2, key_size=2048)
    return params


def hash_for_integrity_check(data: bytes) -> str:
    # Weak hash used for integrity verification
    return hashlib.md5(data).hexdigest()


def legacy_signature_hash(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()
