"""
wallet.py - node identities, passphrase-protected keystore, and the public
key registry (our simplified PKI).

Each node owns TWO independent post-quantum key pairs:
  * ML-DSA-65 signing pair   -> authentication + non-repudiation
  * ML-KEM-768 KEM pair      -> confidentiality (receiving encrypted payloads)
Using separate keys for separate purposes is standard key-hygiene practice.
"""
import json
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import os

from . import crypto


@dataclass
class Node:
    name: str
    sig_pk: bytes
    sig_sk: bytes
    kem_ek: bytes
    kem_dk: bytes
    key_version: int = 1
    # Retired ML-KEM decapsulation keys, kept ONLY so old records stay readable until they are
    # re-encrypted. discard_old_keys() destroys them (crypto-shredding of the old ciphertexts).
    old_kem_dks: list = field(default_factory=list)

    @classmethod
    def generate(cls, name: str, version: int = 1) -> "Node":
        sig_pk, sig_sk = crypto.sig_keygen()
        kem_ek, kem_dk = crypto.kem_keygen()
        return cls(name, sig_pk, sig_sk, kem_ek, kem_dk, version)

    def rotate_keys(self) -> None:
        """Generate brand-new key pairs. The old KEM secret key is ARCHIVED (not lost) so records
        encrypted to it can be re-encrypted; call discard_old_keys() afterwards."""
        self.old_kem_dks.append(self.kem_dk)
        fresh = Node.generate(self.name, self.key_version + 1)
        self.sig_pk, self.sig_sk = fresh.sig_pk, fresh.sig_sk
        self.kem_ek, self.kem_dk = fresh.kem_ek, fresh.kem_dk
        self.key_version = fresh.key_version

    def discard_old_keys(self) -> None:
        """Destroy archived KEM secret keys: anything still encrypted to them becomes unreadable."""
        self.old_kem_dks.clear()

    def fingerprint(self) -> str:
        """Short SHA-256 fingerprint of the signing public key (human-checkable)."""
        return crypto.sha256(self.sig_pk).hex()[:16]

    # ------------------------------------------------ encrypted keystore
    def save_keystore(self, path: str, passphrase: str) -> None:
        """Secret keys are encrypted at rest: scrypt(passphrase) -> AES-256-GCM."""
        salt, n, r, p = os.urandom(16), 2 ** 15, 8, 1
        key = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode())
        secret = json.dumps({"sig_sk": self.sig_sk.hex(), "kem_dk": self.kem_dk.hex(),
                             "old_kem_dks": [k.hex() for k in self.old_kem_dks]}).encode()
        aad = f"{self.name}|{self.key_version}".encode()
        nonce, ct = crypto.aes_encrypt(key, secret, aad)
        blob = {
            "name": self.name, "key_version": self.key_version,
            "sig_pk": self.sig_pk.hex(), "kem_ek": self.kem_ek.hex(),
            "kdf": {"name": "scrypt", "n": n, "r": r, "p": p, "salt": salt.hex()},
            "cipher": "AES-256-GCM", "nonce": nonce.hex(), "ciphertext": ct.hex(),
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as fh:
            json.dump(blob, fh, indent=1)
        try:
            os.chmod(path, 0o600)  # owner read/write only (no-op on Windows)
        except OSError:
            pass

    @classmethod
    def load_keystore(cls, path: str, passphrase: str) -> "Node":
        with open(path) as fh:
            b = json.load(fh)
        k = b["kdf"]
        key = Scrypt(salt=bytes.fromhex(k["salt"]), length=32, n=k["n"], r=k["r"], p=k["p"]).derive(
            passphrase.encode())
        aad = f"{b['name']}|{b['key_version']}".encode()
        secret = json.loads(crypto.aes_decrypt(key, bytes.fromhex(b["nonce"]),
                                               bytes.fromhex(b["ciphertext"]), aad))
        return cls(b["name"], bytes.fromhex(b["sig_pk"]), bytes.fromhex(secret["sig_sk"]),
                   bytes.fromhex(b["kem_ek"]), bytes.fromhex(secret["kem_dk"]), b["key_version"],
                   [bytes.fromhex(k) for k in secret.get("old_kem_dks", [])])


@dataclass
class KeyRecord:
    """Public information about one version of a node's keys."""
    version: int
    sig_pk: bytes
    kem_ek: bytes
    status: str = "active"  # active | retired (rotated) | revoked


@dataclass
class NodeRegistry:
    """Public-key directory. In production this would itself live on-chain
    (registration transactions) or be anchored to a permissioned-network CA."""
    _nodes: dict = field(default_factory=dict)

    def register(self, node: Node) -> None:
        if node.name in self._nodes:
            raise ValueError(f"{node.name} already registered")
        self._nodes[node.name] = [KeyRecord(node.key_version, node.sig_pk, node.kem_ek)]

    def rotate(self, node: Node) -> None:
        history = self._nodes[node.name]
        history[-1].status = "retired"
        history.append(KeyRecord(node.key_version, node.sig_pk, node.kem_ek))

    def revoke(self, name: str) -> None:
        self._nodes[name][-1].status = "revoked"

    def latest(self, name: str):
        h = self._nodes.get(name)
        return h[-1] if h else None

    def get_version(self, name: str, version: int):
        for rec in self._nodes.get(name, []):
            if rec.version == version:
                return rec
        return None

    def names(self):
        return list(self._nodes)
