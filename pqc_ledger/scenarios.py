"""
scenarios.py - the interactive demos. Each `demo_*` function is one menu item.

Use case: a QUANTUM-RESISTANT MEDICAL-RECORD LEDGER. Hospitals, labs and
pharmacies exchange confidential patient data. Records are encrypted for the
recipient only, signed by the sender, and anchored in an immutable chain.
"""
import copy
import os
import random
import tempfile

from . import benchmark, crypto, ui
from .ledger import (Blockchain, OffChainStore, RecordErased, Transaction, TransactionRejected,
                     create_transaction, decrypt_transaction, merkle_root, reencrypt_records)
from .network import NodeServer, send_message, send_transaction
from .wallet import Node, NodeRegistry

RECORD_ORDER = {"patient_id": "P-884213", "name": "Jane Citizen", "dob": "1988-04-17",
                "order": "HbA1c + lipid panel", "priority": "routine", "ordering_physician": "Dr. A. Rahman"}
RECORD_RESULT = {"patient_id": "P-884213", "hba1c": "5.9 %", "ldl": "3.1 mmol/L",
                 "note": "pre-diabetic range; recommend diet review", "lab_tech": "T. Nguyen"}


class Demo:
    """Holds the simulated network: registry, ledger and four nodes."""

    def __init__(self, difficulty=4):
        self.registry = NodeRegistry()
        self.ledger = Blockchain(self.registry, difficulty)
        ui.info("Generating ML-DSA-65 + ML-KEM-768 key pairs for each node (a few seconds)...")
        self.nodes = {}
        for name in ("Hospital_A", "Lab_B", "Pharmacy_C", "Eve"):
            self.nodes[name] = Node.generate(name)
            self.registry.register(self.nodes[name])
        self.ledger.create_genesis()

    def send(self, sender, recipient, record, trace=None, record_type="medical_record"):
        tx = create_transaction(self.nodes[sender], self.registry, recipient, record, record_type, trace=trace)
        self.ledger.add_transaction(tx)
        return tx

    def ensure_blocks(self, n=2):
        """Make sure at least n mined blocks exist (used by demos that need history)."""
        plan = [("Hospital_A", "Lab_B", RECORD_ORDER, "lab_order"),
                ("Lab_B", "Hospital_A", RECORD_RESULT, "lab_result")]
        while len(self.ledger.chain) - 1 < n:
            s, r, rec, rt = plan[(len(self.ledger.chain) - 1) % 2]
            self.send(s, r, rec, record_type=rt)
            self.ledger.mine_pending()

    def first_tx_for(self, recipient):
        for b in self.ledger.chain:
            for tx in b.transactions:
                if tx.recipient == recipient:
                    return b, tx
        return None, None


def _show(label, value):
    ui.kv(label, ui.hexs(value) if isinstance(value, bytes) and label.find("plaintext") < 0
          else value.decode() if isinstance(value, bytes) else value)


# ------------------------------------------------------------------ 1
def demo_valid(d: Demo):
    ui.banner("DEMO 1: Valid PQC transaction  (ML-KEM encrypt -> ML-DSA sign -> mine)")
    ui.step(1, "Hospital_A prepares a confidential lab order for Lab_B")
    ui.info("Payload below is plaintext and exists ONLY on Hospital_A's machine.")
    for k, v in RECORD_ORDER.items():
        ui.kv("  " + k, v)
    ui.pause()

    ui.step(2, "Hybrid encryption + signing (ML-KEM-768, HKDF, AES-256-GCM, ML-DSA-65)")
    tx = create_transaction(d.nodes["Hospital_A"], d.registry, "Lab_B", RECORD_ORDER, "lab_order", trace=_show)
    ui.pause()

    ui.step(3, "Transaction broadcast -> every node verifies sender identity & ML-DSA signature")
    d.ledger.add_transaction(tx)
    ui.ok(f"signature valid for sender '{tx.sender}' (key v{tx.key_version}); nonce fresh; tx accepted into mempool")
    ui.kv("tx_id (SHA-256)", tx.tx_id[:48] + "...")
    ui.pause()

    ui.step(4, f"Mining block (SHA-256 proof-of-work, difficulty = {d.ledger.difficulty} leading hex zeros)")
    b = d.ledger.mine_pending()
    ui.kv("block index", b.index)
    ui.kv("prev_hash", b.prev_hash[:32] + "...")
    ui.kv("merkle_root", b.merkle_root[:32] + "...")
    ui.kv("nonce (hashes tried)", f"{b.nonce:,}")
    ui.kv("block hash", ui.green(b.hash))
    ui.pause()

    ui.step(5, "Lab_B (holder of the ML-KEM decapsulation key) decrypts the payload")
    plain = decrypt_transaction(tx, d.nodes["Lab_B"])
    ui.ok("decrypted successfully:")
    for k, v in plain.items():
        ui.kv("  " + k, v)
    ui.ok("Chain audit: " + ("VALID" if not d.ledger.validate_chain() else "INVALID"))


# ------------------------------------------------------------------ 2
def demo_tamper(d: Demo):
    ui.banner("DEMO 2: Tamper detection  (integrity of blocks & transactions)")
    d.ensure_blocks(2)
    ui.step(1, "Baseline audit of the untouched ledger")
    issues = d.ledger.validate_chain()
    ui.ok("Chain valid - 0 problems") if not issues else ui.bad(str(issues))
    ui.pause()

    ui.step(2, "ATTACK A: attacker flips ONE byte of the encrypted payload stored in block 1")
    evil = copy.deepcopy(d.ledger.chain)  # work on a copy so later demos still have a clean chain
    ct = bytearray(evil[1].transactions[0].ciphertext)
    ct[0] ^= 0x01
    evil[1].transactions[0].ciphertext = bytes(ct)
    for idx, msg in d.ledger.validate_chain(evil):
        ui.bad(f"block {idx}: {msg}")
    ui.pause()

    ui.step(3, "ATTACK B (smart attacker): also recompute Merkle root, block hash and re-mine block 1")
    ui.info("The attacker has unlimited compute for SHA-256 but does NOT own Hospital_A's ML-DSA secret key.")
    evil[1].merkle_root = merkle_root(evil[1].transactions)
    evil[1].nonce = 0
    evil[1].mine()
    for idx, msg in d.ledger.validate_chain(evil):
        ui.bad(f"block {idx}: {msg}")
    print()
    ui.ok("Hash chain + Merkle tree detect structural edits; ML-DSA detects content edits even after re-mining.")
    ui.ok("Original chain on this node is untouched: " + ("VALID" if not d.ledger.validate_chain() else "INVALID"))


# ------------------------------------------------------------------ 3
def demo_forgery(d: Demo):
    ui.banner("DEMO 3: Forged identity / invalid signature rejection  (authentication)")
    ui.step(1, "Eve (a registered node) pretends to be Hospital_A, signing with HER OWN ML-DSA key")
    forged = create_transaction(d.nodes["Eve"], d.registry, "Pharmacy_C",
                                {"patient_id": "P-884213", "rx": "OXYCODONE 80mg x 500"},
                                "prescription", claimed_sender="Hospital_A")
    ui.kv("claimed sender", forged.sender)
    ui.kv("actually signed by", "Eve")
    try:
        d.ledger.add_transaction(forged)
        ui.bad("forged transaction ACCEPTED (this must never happen)")
    except TransactionRejected as e:
        ui.ok(f"REJECTED: {e}")
    ui.pause()

    ui.step(2, "A legitimate transaction whose signature gets corrupted in transit (1 bit flipped)")
    good = create_transaction(d.nodes["Hospital_A"], d.registry, "Pharmacy_C", {"rx": "Metformin 500mg"}, "prescription")
    sig = bytearray(good.signature)
    sig[100] ^= 0x01
    good.signature = bytes(sig)
    try:
        d.ledger.add_transaction(good)
        ui.bad("corrupted signature ACCEPTED")
    except TransactionRejected as e:
        ui.ok(f"REJECTED: {e}")
    ui.pause()

    ui.step(3, "An outsider who was never registered tries to join the network")
    mallory = Node.generate("Mallory")
    try:
        d.ledger.add_transaction(create_transaction(mallory, d.registry, "Lab_B", {"x": 1}))
        ui.bad("unknown node ACCEPTED")
    except TransactionRejected as e:
        ui.ok(f"REJECTED: {e}")
    ui.info(f"Mempool size after all attacks: {len(d.ledger.mempool)} (nothing malicious got in)")


# ------------------------------------------------------------------ 4
def demo_unauthorized_decrypt(d: Demo):
    ui.banner("DEMO 4: Unauthorized decryption failure  (confidentiality)")
    d.ensure_blocks(1)
    block, tx = d.first_tx_for("Lab_B")
    ui.step(1, "The ledger is PUBLIC. Eve downloads the encrypted transaction addressed to Lab_B")
    ui.kv("ciphertext (what Eve sees)", ui.hexs(tx.ciphertext, 20))
    ui.kv("ML-KEM ciphertext", ui.hexs(tx.kem_ct, 20))
    ui.pause()

    ui.step(2, "Eve decapsulates with HER OWN ML-KEM key")
    ui.info("ML-KEM implicit rejection: she gets a pseudorandom (wrong) secret -> AES-GCM tag check fails.")
    try:
        decrypt_transaction(tx, d.nodes["Eve"])
        ui.bad("Eve decrypted the record!")
    except crypto.DecryptionError:
        ui.ok("DECRYPTION FAILED for Eve (wrong shared secret)")
    ui.pause()

    ui.step(3, "Eve brute-forces: tries 2,000 random AES-256 keys")
    hits = 0
    for _ in range(2000):
        try:
            crypto.aes_decrypt(os.urandom(32), tx.aes_nonce, tx.ciphertext, tx.aad())
            hits += 1
        except crypto.DecryptionError:
            pass
    ui.ok(f"{hits} successes out of 2,000 guesses  (search space 2^256; Grover only reduces it to 2^128)")
    ui.pause()

    ui.step(4, "Control: the legitimate recipient Lab_B decrypts the same transaction")
    plain = decrypt_transaction(tx, d.nodes["Lab_B"])
    ui.ok(f"Lab_B reads: {plain}")


# ------------------------------------------------------------------ 5
def demo_benchmark(d: Demo):
    benchmark.run(n=3)


# ------------------------------------------------------------------ 6
def demo_nonrepudiation(d: Demo):
    ui.banner("DEMO 6: Non-repudiation  (third-party audit using only PUBLIC data)")
    d.ensure_blocks(1)
    block, tx = d.first_tx_for("Lab_B")
    ui.step(1, "Hospital_A later denies: 'I never ordered that lab test!'")
    ui.info("An independent auditor (professor/court/regulator) holds only the ledger + public registry.")
    ui.pause()
    ui.step(2, "Auditor extracts evidence")
    rec = d.registry.get_version(tx.sender, tx.key_version)
    ui.kv("tx_id", tx.tx_id[:40] + "...")
    ui.kv("recorded in block", f"#{block.index}  hash {block.hash[:24]}...")
    ui.kv("claimed sender / key version", f"{tx.sender} / v{tx.key_version}")
    ui.kv("sender public key fingerprint", crypto.sha256(rec.sig_pk).hex()[:32])
    ui.kv("ML-DSA signature", ui.hexs(tx.signature, 20))
    ui.pause()
    ui.step(3, "Auditor verifies ML-DSA-65 signature with Hospital_A's PUBLIC key (no secrets needed)")
    valid = crypto.verify(rec.sig_pk, tx.signing_bytes(), tx.signature)
    ui.ok("Signature VALID -> only the holder of Hospital_A's secret signing key could have produced it") \
        if valid else ui.bad("invalid")
    ui.ok("Hospital_A cannot repudiate the transaction. Block timestamp + hash chain fix WHEN it was sent.")
    ui.info("Caveat (real deployments): non-repudiation assumes the secret key was not stolen; "
            "HSMs and key revocation limit that risk.")


# ------------------------------------------------------------------ 7
def demo_replay(d: Demo):
    ui.banner("DEMO 7: Replay attack rejection")
    d.ensure_blocks(1)
    _, tx = d.first_tx_for("Lab_B")
    ui.step(1, "Eve copies a genuine, correctly-signed transaction from the ledger and re-broadcasts it")
    try:
        d.ledger.add_transaction(tx)
        ui.bad("replayed transaction ACCEPTED")
    except TransactionRejected as e:
        ui.ok(f"REJECTED: {e}")
    ui.step(2, "Eve changes the timestamp/nonce to dodge the replay check")
    clone = copy.deepcopy(tx)
    clone.tx_nonce = os.urandom(16).hex()
    try:
        d.ledger.add_transaction(clone)
        ui.bad("modified replay ACCEPTED")
    except TransactionRejected as e:
        ui.ok(f"REJECTED: {e}  (signature covers the nonce)")


# ------------------------------------------------------------------ 8
def demo_ledger(d: Demo):
    ui.banner("LEDGER VIEW")
    for b in d.ledger.chain:
        print(ui.bold(f"\n  Block #{b.index}") + ui.dim(f"   mined with {b.tries:,} hashes" if b.tries else ""))
        ui.kv("hash", ui.green(b.hash))
        ui.kv("prev_hash", b.prev_hash[:40] + "...")
        ui.kv("merkle_root", b.merkle_root[:40] + "...")
        for tx in b.transactions:
            ui.kv(f"  tx {tx.tx_id[:10]}", f"{tx.sender} -> {tx.recipient} [{tx.record_type}] "
                  f"ct={len(tx.ciphertext)}B sig={len(tx.signature):,}B")
    print()
    ui.ok("Chain audit: " + ("VALID" if not d.ledger.validate_chain() else "INVALID"))


# ------------------------------------------------------------------ 9
def demo_keys(d: Demo):
    ui.banner("DEMO 9: Key management  (storage, rotation, revocation)")
    ui.step(1, "Public key material of each node (secret keys never leave the node)")
    for n in ("Hospital_A", "Lab_B", "Pharmacy_C", "Eve"):
        node = d.nodes[n]
        ui.kv(f"{n}", f"sig_pk {ui.hexs(node.sig_pk, 8)} | fp {node.fingerprint()}")
    ui.info(f"ML-DSA-65 secret key = {len(d.nodes['Hospital_A'].sig_sk):,} B, "
            f"ML-KEM-768 decapsulation key = {len(d.nodes['Hospital_A'].kem_dk):,} B")
    ui.pause()

    ui.step(2, "Encrypted keystore: scrypt(passphrase) -> AES-256-GCM")
    path = os.path.join(tempfile.mkdtemp(prefix="pqc_keystore_"), "Hospital_A.keystore.json")
    d.nodes["Hospital_A"].save_keystore(path, "correct horse battery staple")
    ui.kv("file", path)
    with open(path) as fh:
        raw = fh.read()
    # NB: ML-DSA sk starts with the public seed rho, so test a slice from the secret part
    ui.ok("secret key bytes are NOT present in file: " + str(d.nodes["Hospital_A"].sig_sk.hex()[400:464] not in raw))
    restored = Node.load_keystore(path, "correct horse battery staple")
    ui.ok("correct passphrase -> keys restored: " + str(restored.sig_sk == d.nodes["Hospital_A"].sig_sk))
    try:
        Node.load_keystore(path, "wrong passphrase")
        ui.bad("wrong passphrase accepted")
    except crypto.DecryptionError:
        ui.ok("wrong passphrase -> keystore refuses to open")
    ui.pause()

    ui.step(3, "Key rotation & revocation using a new node 'Clinic_D'")
    clinic = Node.generate("Clinic_D")
    d.registry.register(clinic)
    old_tx = create_transaction(clinic, d.registry, "Lab_B", {"n": "before rotation"})
    d.ledger.add_transaction(old_tx)
    ui.ok("v1 key: transaction accepted")
    clinic.rotate_keys()
    d.registry.rotate(clinic)
    stale = create_transaction(Node(clinic.name, clinic.sig_pk, clinic.sig_sk, clinic.kem_ek, clinic.kem_dk, 1),
                               d.registry, "Lab_B", {"n": "signed with old version label"})
    try:
        d.ledger.add_transaction(stale)
    except TransactionRejected as e:
        ui.ok(f"stale/mismatched key version rejected: {e}")
    d.ledger.add_transaction(create_transaction(clinic, d.registry, "Lab_B", {"n": "after rotation"}))
    ui.ok("v2 key: transaction accepted; old v1 transaction remains verifiable against archived v1 public key")
    d.registry.revoke("Clinic_D")
    try:
        d.ledger.add_transaction(create_transaction(clinic, d.registry, "Lab_B", {"n": "post-revocation"}))
    except TransactionRejected as e:
        ui.ok(f"after revocation: {e}")
    d.ledger.mempool.clear()
    ui.pause()

    ui.step(4, "Re-encrypt old records on rotation: 'Clinic_E' rotates its ML-KEM key")
    clinic_e = Node.generate("Clinic_E")
    d.registry.register(clinic_e)
    old_tx = create_transaction(d.nodes["Hospital_A"], d.registry, "Clinic_E", RECORD_RESULT, "lab_result")
    d.ledger.add_transaction(old_tx)
    d.ledger.mine_pending()
    ui.ok("record encrypted to Clinic_E's v1 KEM key and mined")
    clinic_e.rotate_keys()
    d.registry.rotate(clinic_e)
    try:
        decrypt_transaction(old_tx, clinic_e, include_archived=False)
    except crypto.DecryptionError:
        ui.ok("new v2 key alone can NOT read the old record (old key archived separately)")
    new_txs = reencrypt_records(d.ledger.chain, d.registry, clinic_e)
    for t in new_txs:
        d.ledger.add_transaction(t)
    d.ledger.mine_pending()
    ui.ok(f"{len(new_txs)} record re-encrypted to the v2 key as a new signed transaction (chain is immutable)")
    clinic_e.discard_old_keys()
    ui.ok("old v1 decapsulation key destroyed")
    try:
        decrypt_transaction(old_tx, clinic_e)
        ui.bad("old ciphertext still readable")
    except crypto.DecryptionError:
        ui.ok("old on-chain ciphertext is now UNREADABLE (its only key was destroyed - crypto-shredding)")
    ui.ok(f"re-encrypted copy readable with v2 key: patient_id = "
          f"{decrypt_transaction(new_txs[0], clinic_e)['data']['patient_id']}")
    ui.ok("Chain audit: " + ("VALID" if not d.ledger.validate_chain() else "INVALID"))


# ------------------------------------------------------------------ B
def demo_network(d: Demo):
    ui.banner("DEMO B: Real TCP network  (node-to-node transaction exchange over sockets)")
    ui.step(1, "Lab_B starts a node: TCP server on 127.0.0.1 with its OWN ledger copy")
    srv_ledger = Blockchain(d.registry, d.ledger.difficulty)
    srv_ledger.create_genesis()
    server = NodeServer(srv_ledger).start()
    try:
        ui.ok(f"Lab_B node listening on 127.0.0.1:{server.port}")
        ui.pause()
        ui.step(2, "Hospital_A encrypts + signs a record and SENDS it over the socket")
        tx = create_transaction(d.nodes["Hospital_A"], d.registry, "Lab_B", RECORD_ORDER, "lab_order")
        ui.kv("bytes on the wire (JSON/hex)", f"{len(str(tx.to_dict())):,}")
        reply = send_transaction("127.0.0.1", server.port, tx)
        ui.ok(f"server reply: {reply}") if reply["ok"] else ui.bad(str(reply))
        ui.kv("Lab_B mempool size", len(srv_ledger.mempool))
        ui.pause()
        ui.step(3, "Eve forges a transaction 'from Hospital_A' over the network")
        forged = create_transaction(d.nodes["Eve"], d.registry, "Pharmacy_C", {"rx": "fake"}, "prescription",
                                    claimed_sender="Hospital_A")
        r = send_transaction("127.0.0.1", server.port, forged)
        ui.ok(f"REJECTED over the wire: {r['reason']}") if not r["ok"] else ui.bad("forgery accepted")
        ui.step(4, "Eve replays Hospital_A's genuine transaction")
        r = send_transaction("127.0.0.1", server.port, tx)
        ui.ok(f"REJECTED over the wire: {r['reason']}") if not r["ok"] else ui.bad("replay accepted")
        ui.step(5, "Eve sends garbage / malformed JSON")
        r = send_message("127.0.0.1", server.port, {"type": "tx", "tx": {"junk": 1}})
        ui.ok(f"REJECTED over the wire: {r['reason']}") if not r["ok"] else ui.bad("garbage accepted")
        ui.pause()
        ui.step(6, "Lab_B mines the received transaction and decrypts it")
        srv_ledger.mine_pending()
        ui.ok(f"Lab_B ledger audit: {'VALID' if not srv_ledger.validate_chain() else 'INVALID'}")
        ui.ok(f"Lab_B reads: {decrypt_transaction(tx, d.nodes['Lab_B'])}")
    finally:
        server.stop()
    ui.info("Payload is E2E encrypted + signed, so the socket carries no plaintext (TLS not added - see network.py).")


# ------------------------------------------------------------------ C
def demo_erasure(d: Demo):
    ui.banner("DEMO C: Off-chain mode  (right to erasure - GDPR Art.17 / HIPAA)")
    store = OffChainStore()
    ui.step(1, "Hospital_A sends a record in OFF-CHAIN mode: ledger keeps only a hash")
    tx = create_transaction(d.nodes["Hospital_A"], d.registry, "Lab_B", RECORD_ORDER, "lab_order", store=store)
    d.ledger.add_transaction(tx)
    d.ledger.mine_pending()
    ui.kv("on-chain ciphertext bytes", len(tx.ciphertext))
    ui.kv("on-chain payload_hash", tx.payload_hash[:48] + "...")
    ui.kv("off-chain store records", len(store))
    ui.pause()
    ui.step(2, "Lab_B fetches the blob from the off-chain store and decrypts it")
    ui.ok(f"decrypted: {decrypt_transaction(tx, d.nodes['Lab_B'], store)}")
    ui.pause()
    ui.step(3, "Integrity: attacker modifies the off-chain blob")
    nonce, ct = store.get(tx.payload_hash)
    store.put(tx.payload_hash, nonce, bytes([ct[0] ^ 1]) + ct[1:])
    try:
        decrypt_transaction(tx, d.nodes["Lab_B"], store)
        ui.bad("modified blob accepted")
    except crypto.DecryptionError as e:
        ui.ok(f"DETECTED: {e}")
    store.put(tx.payload_hash, nonce, ct)
    ui.pause()
    ui.step(4, "Patient exercises right to erasure -> hospital deletes the off-chain blob")
    store.erase(tx.payload_hash)
    ui.kv("off-chain store records", len(store))
    try:
        decrypt_transaction(tx, d.nodes["Lab_B"], store)
        ui.bad("record still readable")
    except RecordErased as e:
        ui.ok(f"record unrecoverable: {e}")
    ui.ok("Ledger still VALID (signature + Merkle root cover the hash): "
          + ("VALID" if not d.ledger.validate_chain() else "INVALID"))
    ui.info("Nothing personal remains on the immutable chain - only a hash and an unusable KEM ciphertext.")


# ------------------------------------------------------------------ run-all
def run_all(d: Demo):
    for fn in (demo_valid, demo_tamper, demo_forgery, demo_unauthorized_decrypt, demo_nonrepudiation,
               demo_replay, demo_benchmark, demo_ledger, demo_keys, demo_network, demo_erasure):
        fn(d)
        ui.pause("Press Enter for the next demo...")
