"""
ledger.py - transactions, blocks and the blockchain.

Transaction pipeline (encrypt-then-sign, "hybrid" KEM-DEM):
  1. (ss, kem_ct) = ML-KEM-768.Encaps(recipient.ek)         quantum-safe key transport
  2. key          = HKDF-SHA256(ss)                          256-bit AES key
  3. (nonce, ct)  = AES-256-GCM(key, payload, AAD=metadata)  confidentiality + integrity
  4. signature    = ML-DSA-65.Sign(sender.sk, all fields)    authentication + non-repudiation

Signing the *ciphertext* means miners/validators can authenticate a transaction
without ever being able to read it.
"""
import json
import os
import time
from dataclasses import dataclass, field, fields
from typing import List, Optional

from . import crypto
from .wallet import Node, NodeRegistry

MAX_CLOCK_SKEW = 600  # seconds


class TransactionRejected(Exception):
    """Raised when a transaction fails validation; message = reason."""


class RecordErased(Exception):
    """Off-chain ciphertext is gone (right-to-erasure) - the on-chain hash is all that remains."""


class OffChainStore:
    """Mutable storage for encrypted payloads in off-chain mode (stand-in for a hospital database).
    The ledger keeps only SHA-256(nonce||ciphertext); erasing the blob here makes the record
    unrecoverable while the chain stays valid (GDPR Art.17 / HIPAA retention compatible)."""

    def __init__(self):
        self._blobs = {}

    def put(self, payload_hash: str, nonce: bytes, ct: bytes) -> None:
        self._blobs[payload_hash] = (nonce, ct)

    def get(self, payload_hash: str):
        if payload_hash not in self._blobs:
            raise RecordErased("off-chain record erased or missing; only its hash remains on-chain")
        return self._blobs[payload_hash]

    def erase(self, payload_hash: str) -> bool:
        return self._blobs.pop(payload_hash, None) is not None

    def __len__(self):
        return len(self._blobs)


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ================================================================ Transaction
@dataclass
class Transaction:
    sender: str
    recipient: str
    record_type: str
    timestamp: int
    tx_nonce: str          # 128-bit random value -> replay protection
    key_version: int       # which version of the sender's signing key was used
    kem_ct: bytes          # ML-KEM ciphertext (encapsulated secret)
    aes_nonce: bytes       # 96-bit AES-GCM nonce
    ciphertext: bytes      # AES-GCM ciphertext || 16-byte tag
    signature: bytes = b""  # ML-DSA-65 signature
    payload_hash: str = ""  # off-chain mode: SHA-256(aes_nonce||ciphertext); the data itself is NOT on-chain

    def aad(self) -> bytes:
        """Associated data authenticated (not encrypted) by AES-GCM."""
        return _canon({"s": self.sender, "r": self.recipient, "t": self.timestamp,
                       "n": self.tx_nonce, "rt": self.record_type})

    def signing_bytes(self) -> bytes:
        """Canonical byte string covered by the ML-DSA signature."""
        return _canon({"sender": self.sender, "recipient": self.recipient,
                       "record_type": self.record_type, "timestamp": self.timestamp,
                       "tx_nonce": self.tx_nonce, "key_version": self.key_version,
                       "kem_ct": self.kem_ct.hex(), "aes_nonce": self.aes_nonce.hex(),
                       "ciphertext": self.ciphertext.hex(),
                       "payload_hash": self.payload_hash})

    # ---- wire / storage format (used by network.py)
    _BYTES = ("kem_ct", "aes_nonce", "ciphertext", "signature")

    def to_dict(self) -> dict:
        return {f.name: (getattr(self, f.name).hex() if f.name in self._BYTES else getattr(self, f.name))
                for f in fields(self)}

    @classmethod
    def from_dict(cls, d: dict) -> "Transaction":
        kw = {f.name: d[f.name] for f in fields(cls) if f.name in d}
        for k in cls._BYTES:
            if k in kw:
                kw[k] = bytes.fromhex(kw[k])
        return cls(**kw)

    def leaf_hash(self) -> bytes:
        return crypto.sha256(self.signing_bytes() + self.signature)

    @property
    def tx_id(self) -> str:
        return self.leaf_hash().hex()

    @property
    def replay_key(self) -> str:
        return f"{self.sender}:{self.tx_nonce}"


def create_transaction(sender_node: Node, registry: NodeRegistry, recipient: str, record: dict,
                       record_type: str = "medical_record", claimed_sender: Optional[str] = None,
                       trace=None, store: Optional[OffChainStore] = None) -> Transaction:
    """Build, encrypt and sign a transaction. `claimed_sender` lets the attack
    demos forge an identity; `trace(label, value)` lets the CLI show each step."""
    t = trace or (lambda *_: None)
    rec = registry.latest(recipient)
    if rec is None:
        raise TransactionRejected(f"unknown recipient '{recipient}'")

    plaintext = json.dumps(record, sort_keys=True).encode()
    t("plaintext payload", plaintext)

    shared_secret, kem_ct = crypto.kem_encaps(rec.kem_ek)           # step 1
    t("ML-KEM-768 ciphertext", kem_ct)
    t("ML-KEM shared secret (demo only!)", shared_secret)

    aes_key = crypto.derive_aes_key(shared_secret)                    # step 2
    t("HKDF-SHA256 -> AES-256 key (demo only!)", aes_key)

    tx = Transaction(sender=claimed_sender or sender_node.name, recipient=recipient,
                     record_type=record_type, timestamp=int(time.time()),
                     tx_nonce=os.urandom(16).hex(), key_version=sender_node.key_version,
                     kem_ct=kem_ct, aes_nonce=b"", ciphertext=b"")
    tx.aes_nonce, tx.ciphertext = crypto.aes_encrypt(aes_key, plaintext, tx.aad())   # step 3
    t("AES-256-GCM nonce", tx.aes_nonce)
    t("AES-256-GCM ciphertext+tag", tx.ciphertext)
    if store is not None:   # off-chain mode: ledger keeps only a commitment to the ciphertext
        tx.payload_hash = crypto.sha256(tx.aes_nonce + tx.ciphertext).hex()
        store.put(tx.payload_hash, tx.aes_nonce, tx.ciphertext)
        tx.aes_nonce, tx.ciphertext = b"", b""

    tx.signature = crypto.sign(sender_node.sig_sk, tx.signing_bytes())  # step 4
    t("ML-DSA-65 signature", tx.signature)
    return tx


def decrypt_transaction(tx: Transaction, node: Node, store: Optional[OffChainStore] = None,
                        include_archived: bool = True) -> dict:
    """Recipient-side decryption. Tries the current KEM key, then archived (pre-rotation) keys.
    Raises crypto.DecryptionError on failure, RecordErased if the off-chain blob is gone."""
    nonce, ct = tx.aes_nonce, tx.ciphertext
    if tx.payload_hash:
        if store is None:
            raise RecordErased("off-chain record: no store supplied")
        nonce, ct = store.get(tx.payload_hash)
        if crypto.sha256(nonce + ct).hex() != tx.payload_hash:
            raise crypto.DecryptionError("off-chain data does not match the hash stored on-chain")
    keys = [node.kem_dk] + (list(reversed(node.old_kem_dks)) if include_archived else [])
    for dk in keys:
        key = crypto.derive_aes_key(crypto.kem_decaps(dk, tx.kem_ct))
        try:
            return json.loads(crypto.aes_decrypt(key, nonce, ct, tx.aad()))
        except crypto.DecryptionError:
            continue
    raise crypto.DecryptionError("no current or archived key can decrypt this transaction")


def reencrypt_records(chain: List["Block"], registry: NodeRegistry, node: Node,
                      store: Optional[OffChainStore] = None) -> List[Transaction]:
    """After `node` rotated its KEM key: decrypt every record still encrypted to an OLD key and
    re-encrypt it to the NEW key as a fresh self-addressed transaction (the chain is immutable, so
    the old transaction stays; it becomes unreadable once node.discard_old_keys() is called).
    In off-chain mode the old encrypted blob is erased from `store`. Caller adds+mines the result."""
    mine = [tx for b in chain for tx in b.transactions if tx.recipient == node.name]

    def plain(tx, archived):
        try:
            return decrypt_transaction(tx, node, store, include_archived=archived)
        except (crypto.DecryptionError, RecordErased):
            return None

    done = set()                       # records already readable with the CURRENT key
    for tx in mine:
        rec = plain(tx, False)
        if rec is not None:
            done.add(rec.get("re_encrypted_from", tx.tx_id))
    out = []
    for tx in mine:
        if plain(tx, False) is not None:
            continue
        rec = plain(tx, True)
        if rec is None:
            continue
        origin = rec.get("re_encrypted_from", tx.tx_id)
        if origin in done:
            continue
        done.add(origin)
        data = rec["data"] if "re_encrypted_from" in rec else rec
        out.append(create_transaction(node, registry, node.name, {"re_encrypted_from": origin, "data": data},
                                      "re_encrypted", store=store))
        if store is not None and tx.payload_hash:
            store.erase(tx.payload_hash)
    return out


# ===================================================================== Block
def merkle_root(txs: List[Transaction]) -> str:
    level = [t.leaf_hash() for t in txs] or [crypto.sha256(b"")]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [crypto.sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


@dataclass
class Block:
    index: int
    timestamp: int
    prev_hash: str
    merkle_root: str
    difficulty: int
    transactions: List[Transaction] = field(default_factory=list)
    nonce: int = 0
    hash: str = ""
    tries: int = 0

    def compute_hash(self) -> str:
        header = f"{self.index}|{self.timestamp}|{self.prev_hash}|{self.merkle_root}|" \
                 f"{self.difficulty}|{self.nonce}"
        return crypto.sha256(header.encode()).hex()

    def mine(self) -> int:
        """Proof-of-work: find nonce so SHA-256(header) has `difficulty` leading hex zeros."""
        target = "0" * self.difficulty
        while True:
            self.hash = self.compute_hash()
            if self.hash.startswith(target):
                return self.nonce + 1
            self.nonce += 1


# ================================================================= Blockchain
class Blockchain:
    def __init__(self, registry: NodeRegistry, difficulty: int = 4):
        self.registry = registry
        self.difficulty = difficulty
        self.chain: List[Block] = []
        self.mempool: List[Transaction] = []
        self._seen = set()  # replay keys of every accepted tx

    def create_genesis(self) -> Block:
        g = Block(0, int(time.time()), "0" * 64, merkle_root([]), self.difficulty)
        g.mine()
        self.chain.append(g)
        return g

    # -------------------------------------------------- admission control
    def verify_transaction(self, tx: Transaction) -> None:
        """Full admission check. Raises TransactionRejected with the reason."""
        sender = self.registry.latest(tx.sender)
        if sender is None:
            raise TransactionRejected(f"unknown sender '{tx.sender}' (not in registry)")
        if sender.status == "revoked":
            raise TransactionRejected(f"sender '{tx.sender}' keys are REVOKED")
        if tx.key_version != sender.version:
            raise TransactionRejected(
                f"stale key: tx signed with v{tx.key_version}, current is v{sender.version}")
        if self.registry.latest(tx.recipient) is None:
            raise TransactionRejected(f"unknown recipient '{tx.recipient}'")
        if abs(time.time() - tx.timestamp) > MAX_CLOCK_SKEW:
            raise TransactionRejected("timestamp outside allowed window")
        if tx.replay_key in self._seen or any(m.replay_key == tx.replay_key for m in self.mempool):
            raise TransactionRejected("REPLAY detected: (sender, nonce) already used")
        if not crypto.verify(sender.sig_pk, tx.signing_bytes(), tx.signature):
            raise TransactionRejected(f"ML-DSA signature INVALID for claimed sender '{tx.sender}'")

    def add_transaction(self, tx: Transaction) -> None:
        self.verify_transaction(tx)
        self.mempool.append(tx)

    # -------------------------------------------------- mining
    def mine_pending(self) -> Block:
        if not self.mempool:
            raise ValueError("mempool is empty")
        txs, self.mempool = self.mempool, []
        prev = self.chain[-1]
        block = Block(prev.index + 1, int(time.time()), prev.hash, merkle_root(txs),
                      self.difficulty, txs)
        block.tries = block.mine()
        self.chain.append(block)
        for t in txs:
            self._seen.add(t.replay_key)
        return block

    # -------------------------------------------------- whole-chain audit
    def validate_chain(self, chain: Optional[List[Block]] = None):
        """Re-verify everything from scratch. Returns a list of (block_index, problem)."""
        chain = chain if chain is not None else self.chain
        issues, seen = [], set()
        for i, b in enumerate(chain):
            if b.compute_hash() != b.hash:
                issues.append((b.index, "block hash != SHA-256(header)  -> header modified"))
            if not b.hash.startswith("0" * b.difficulty):
                issues.append((b.index, "proof-of-work target not met"))
            if i > 0 and b.prev_hash != chain[i - 1].hash:
                issues.append((b.index, "prev_hash link broken (previous block changed)"))
            if merkle_root(b.transactions) != b.merkle_root:
                issues.append((b.index, "Merkle root mismatch -> transaction data altered"))
            for tx in b.transactions:
                rec = self.registry.get_version(tx.sender, tx.key_version)
                if rec is None:
                    issues.append((b.index, f"tx {tx.tx_id[:10]}: unknown sender key"))
                elif not crypto.verify(rec.sig_pk, tx.signing_bytes(), tx.signature):
                    issues.append((b.index, f"tx {tx.tx_id[:10]}: ML-DSA signature INVALID"))
                if tx.replay_key in seen:
                    issues.append((b.index, f"tx {tx.tx_id[:10]}: duplicate (replay)"))
                seen.add(tx.replay_key)
        return issues

    def find_tx(self, tx_id_prefix: str):
        for b in self.chain:
            for tx in b.transactions:
                if tx.tx_id.startswith(tx_id_prefix):
                    return b, tx
        return None, None
