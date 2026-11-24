"""
crypto.py - the ONLY module that touches cryptographic primitives.

Every other module calls these thin wrappers, so the whole cryptographic
surface of the project can be audited in one ~100-line file.

Primitive            | Standard        | Library            | Purpose
---------------------+-----------------+--------------------+----------------------------
ML-KEM-768 (Kyber)   | NIST FIPS 203   | liboqs (C) *       | quantum-resistant key exchange
ML-DSA-65 (Dilithium)| NIST FIPS 204   | liboqs (C) *       | quantum-resistant signatures
AES-256-GCM          | NIST SP 800-38D | cryptography       | authenticated payload encryption
HKDF-SHA256          | RFC 5869        | cryptography       | KEM secret -> AES key
SHA-256              | NIST FIPS 180-4 | hashlib            | block hashing, Merkle tree
scrypt               | RFC 7914        | cryptography       | passphrase-protected keystore

* Backend selection (automatic): liboqs via `liboqs-python` (Open Quantum Safe, C, constant-time) when it
  imports; otherwise the pure-Python fallback kyber-py / dilithium-py (educational, NOT constant-time).
  Force the fallback with the environment variable PQC_BACKEND=python.  `crypto.BACKEND` says which is active.
  NOTE: the first `import oqs` may take several minutes - liboqs-python builds the C library (needs git,
  cmake and a C compiler). Later runs are instant.
Randomness: liboqs uses the OS CSPRNG; the fallback uses os.urandom.
"""
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

oqs = None
if os.environ.get("PQC_BACKEND", "").lower() != "python":
    try:
        import oqs  # liboqs-python: may auto-build the liboqs C library on first import
        if "ML-KEM-768" not in oqs.get_enabled_kem_mechanisms() or \
                "ML-DSA-65" not in oqs.get_enabled_sig_mechanisms():
            oqs = None  # old liboqs build that only knows Kyber768/Dilithium3
    except Exception:
        oqs = None

if oqs is not None:
    BACKEND = f"liboqs {oqs.oqs_version()} (C, via liboqs-python)"

    class _OqsKEM:
        """Adapter giving liboqs the same keygen/encaps/decaps interface as kyber-py."""
        def __init__(self, name):
            self.name = name

        def keygen(self):
            with oqs.KeyEncapsulation(self.name) as k:
                ek = k.generate_keypair()
                return ek, k.export_secret_key()

        def encaps(self, ek):
            with oqs.KeyEncapsulation(self.name) as k:
                ct, ss = k.encap_secret(ek)
                return ss, ct

        def decaps(self, dk, ct):
            with oqs.KeyEncapsulation(self.name, secret_key=dk) as k:
                return k.decap_secret(ct)

    class _OqsDSA:
        """Adapter giving liboqs the same keygen/sign/verify interface as dilithium-py."""
        def __init__(self, name):
            self.name = name

        def keygen(self):
            with oqs.Signature(self.name) as s:
                pk = s.generate_keypair()
                return pk, s.export_secret_key()

        def sign(self, sk, msg):
            with oqs.Signature(self.name, secret_key=sk) as s:
                return s.sign(msg)

        def verify(self, pk, msg, sig):
            with oqs.Signature(self.name) as s:
                return s.verify(msg, sig, pk)

    ALL_KEMS = {n: _OqsKEM(n) for n in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")}
    ALL_DSAS = {n: _OqsDSA(n) for n in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")}
else:
    from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    BACKEND = "pure-Python fallback (kyber-py / dilithium-py) - educational, not constant-time"
    ALL_KEMS = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}
    ALL_DSAS = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}

# ---- Parameter sets used by the ledger (NIST security category 3 ~ AES-192) ----
KEM = ALL_KEMS["ML-KEM-768"]
DSA = ALL_DSAS["ML-DSA-65"]
KEM_NAME = "ML-KEM-768 (FIPS 203)"
DSA_NAME = "ML-DSA-65 (FIPS 204)"

# Domain-separation label for HKDF: binds derived keys to THIS application.
HKDF_INFO = b"MACS902-PQC-LEDGER|v1|AES-256-GCM"


class DecryptionError(Exception):
    """AES-GCM authentication failed: wrong key, wrong AAD, or modified ciphertext."""


# ------------------------------------------------------------------ hashing
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ------------------------------------------------------------------ ML-KEM
def kem_keygen():
    """Returns (encapsulation_key, decapsulation_key)."""
    return KEM.keygen()


def kem_encaps(ek: bytes):
    """Sender side: returns (shared_secret[32], kem_ciphertext)."""
    return KEM.encaps(ek)


def kem_decaps(dk: bytes, ct: bytes) -> bytes:
    """Recipient side. NOTE: ML-KEM uses *implicit rejection* - a wrong dk or a
    tampered ciphertext does not raise; it yields a pseudorandom secret, so the
    failure surfaces later as an AES-GCM tag mismatch."""
    return KEM.decaps(dk, ct)


# ------------------------------------------------------------------ ML-DSA
def sig_keygen():
    """Returns (public_key, secret_key)."""
    return DSA.keygen()


def sign(sk: bytes, message: bytes) -> bytes:
    return DSA.sign(sk, message)


def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """Never raises: malformed keys/signatures simply verify as False."""
    try:
        return bool(DSA.verify(pk, message, signature))
    except Exception:
        return False


# ------------------------------------------------------------------ AES-256-GCM
def derive_aes_key(shared_secret: bytes) -> bytes:
    """HKDF-SHA256: 32-byte ML-KEM secret -> 256-bit AES key (domain separated)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(shared_secret)


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes):
    """Returns (nonce[12], ciphertext||tag[16]). Fresh random 96-bit nonce per message."""
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("AES-GCM authentication tag mismatch") from exc
