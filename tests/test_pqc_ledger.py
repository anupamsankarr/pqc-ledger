"""Run with:  python -m unittest -v"""
import copy, os, tempfile, unittest
from pqc_ledger import crypto
from pqc_ledger.ledger import (Blockchain, OffChainStore, RecordErased, TransactionRejected, create_transaction,
                               decrypt_transaction, merkle_root, reencrypt_records)
from pqc_ledger.network import NodeServer, send_message, send_transaction
from pqc_ledger.wallet import Node, NodeRegistry


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg = NodeRegistry()
        cls.n = {x: Node.generate(x) for x in ("A", "B", "Eve")}
        for node in cls.n.values():
            cls.reg.register(node)

    def setUp(self):
        self.bc = Blockchain(self.reg, difficulty=2)
        self.bc.create_genesis()


class TestCrypto(unittest.TestCase):
    def test_kem_roundtrip(self):
        ek, dk = crypto.kem_keygen(); ss, ct = crypto.kem_encaps(ek)
        self.assertEqual(ss, crypto.kem_decaps(dk, ct)); self.assertEqual(len(ss), 32)

    def test_kem_wrong_key_gives_different_secret(self):
        ek, _ = crypto.kem_keygen(); _, dk2 = crypto.kem_keygen(); ss, ct = crypto.kem_encaps(ek)
        self.assertNotEqual(ss, crypto.kem_decaps(dk2, ct))

    def test_sign_verify_and_sizes(self):
        pk, sk = crypto.sig_keygen(); sig = crypto.sign(sk, b"m")
        self.assertTrue(crypto.verify(pk, b"m", sig)); self.assertFalse(crypto.verify(pk, b"x", sig))
        self.assertEqual((len(pk), len(sig)), (1952, 3309))

    def test_garbage_signature_does_not_raise(self):
        pk, _ = crypto.sig_keygen(); self.assertFalse(crypto.verify(pk, b"m", b"junk"))

    def test_aes_tamper(self):
        k = os.urandom(32); n, ct = crypto.aes_encrypt(k, b"hello", b"aad")
        self.assertEqual(crypto.aes_decrypt(k, n, ct, b"aad"), b"hello")
        with self.assertRaises(crypto.DecryptionError): crypto.aes_decrypt(k, n, ct, b"other-aad")


class TestLedger(Base):
    def test_happy_path_and_decrypt(self):
        tx = create_transaction(self.n["A"], self.reg, "B", {"k": "v"})
        self.bc.add_transaction(tx); self.bc.mine_pending()
        self.assertEqual(decrypt_transaction(tx, self.n["B"]), {"k": "v"})
        self.assertEqual(self.bc.validate_chain(), [])

    def test_eve_cannot_decrypt(self):
        tx = create_transaction(self.n["A"], self.reg, "B", {"k": "v"})
        with self.assertRaises(crypto.DecryptionError): decrypt_transaction(tx, self.n["Eve"])

    def test_forged_sender_rejected(self):
        tx = create_transaction(self.n["Eve"], self.reg, "B", {"k": 1}, claimed_sender="A")
        with self.assertRaisesRegex(TransactionRejected, "INVALID"): self.bc.add_transaction(tx)

    def test_unknown_sender_rejected(self):
        with self.assertRaisesRegex(TransactionRejected, "unknown sender"):
            self.bc.add_transaction(create_transaction(Node.generate("Zed"), self.reg, "B", {}))

    def test_replay_rejected(self):
        tx = create_transaction(self.n["A"], self.reg, "B", {"k": 1})
        self.bc.add_transaction(tx); self.bc.mine_pending()
        with self.assertRaisesRegex(TransactionRejected, "REPLAY"): self.bc.add_transaction(tx)

    def test_tamper_detected_even_after_remine(self):
        for _ in range(2):
            self.bc.add_transaction(create_transaction(self.n["A"], self.reg, "B", {"k": 1})); self.bc.mine_pending()
        evil = copy.deepcopy(self.bc.chain)
        evil[1].transactions[0].ciphertext = b"\x00" + evil[1].transactions[0].ciphertext[1:]
        self.assertTrue(self.bc.validate_chain(evil))
        evil[1].merkle_root = merkle_root(evil[1].transactions); evil[1].nonce = 0; evil[1].mine()
        msgs = " ".join(m for _, m in self.bc.validate_chain(evil))
        self.assertIn("signature INVALID", msgs); self.assertIn("prev_hash", msgs)

    def test_rotation_and_revocation(self):
        node = Node.generate("C"); reg = NodeRegistry(); reg.register(node); reg.register(self.n["B"])
        bc = Blockchain(reg, 2); bc.create_genesis()
        node.rotate_keys(); reg.rotate(node)
        bc.add_transaction(create_transaction(node, reg, "B", {}))
        reg.revoke("C")
        with self.assertRaisesRegex(TransactionRejected, "REVOKED"):
            bc.add_transaction(create_transaction(node, reg, "B", {}))


class TestRotationReencrypt(unittest.TestCase):
    def test_reencrypt_on_rotation(self):
        reg = NodeRegistry(); a, b = Node.generate("A2"), Node.generate("B2")
        reg.register(a); reg.register(b)
        bc = Blockchain(reg, 2); bc.create_genesis()
        old = create_transaction(a, reg, "B2", {"k": 1}); bc.add_transaction(old); bc.mine_pending()
        b.rotate_keys(); reg.rotate(b)
        with self.assertRaises(crypto.DecryptionError): decrypt_transaction(old, b, include_archived=False)
        self.assertEqual(decrypt_transaction(old, b), {"k": 1})      # archived key still works
        new = reencrypt_records(bc.chain, reg, b)
        self.assertEqual(len(new), 1)
        for t in new: bc.add_transaction(t)
        bc.mine_pending()
        self.assertEqual(reencrypt_records(bc.chain, reg, b), [])     # idempotent
        b.discard_old_keys()
        with self.assertRaises(crypto.DecryptionError): decrypt_transaction(old, b)
        self.assertEqual(decrypt_transaction(new[0], b)["data"], {"k": 1})
        self.assertEqual(bc.validate_chain(), [])


class TestNetwork(Base):
    def test_tcp_accept_and_reject(self):
        server = NodeServer(self.bc).start()
        try:
            tx = create_transaction(self.n["A"], self.reg, "B", {"k": 1})
            self.assertTrue(send_transaction("127.0.0.1", server.port, tx)["ok"])
            self.assertEqual(len(self.bc.mempool), 1)
            forged = create_transaction(self.n["Eve"], self.reg, "B", {"k": 1}, claimed_sender="A")
            r = send_transaction("127.0.0.1", server.port, forged)
            self.assertFalse(r["ok"]); self.assertIn("INVALID", r["reason"])
            self.assertIn("REPLAY", send_transaction("127.0.0.1", server.port, tx)["reason"])
            r = send_message("127.0.0.1", server.port, {"type": "tx", "tx": {"junk": 1}})
            self.assertFalse(r["ok"]); self.assertEqual(len(self.bc.mempool), 1)
        finally:
            server.stop()


class TestOffChain(Base):
    def test_erasure_keeps_chain_valid(self):
        store = OffChainStore()
        tx = create_transaction(self.n["A"], self.reg, "B", {"k": "secret"}, store=store)
        self.assertEqual((tx.ciphertext, len(store)), (b"", 1))
        self.bc.add_transaction(tx); self.bc.mine_pending()
        self.assertEqual(decrypt_transaction(tx, self.n["B"], store), {"k": "secret"})
        nonce, ct = store.get(tx.payload_hash)                         # tampered blob is detected
        store.put(tx.payload_hash, nonce, b"\x00" + ct[1:])
        with self.assertRaisesRegex(crypto.DecryptionError, "hash"): decrypt_transaction(tx, self.n["B"], store)
        store.erase(tx.payload_hash)
        with self.assertRaises(RecordErased): decrypt_transaction(tx, self.n["B"], store)
        self.assertEqual(self.bc.validate_chain(), [])


class TestKeystore(Base):
    def test_roundtrip_and_wrong_pass(self):
        p = os.path.join(tempfile.mkdtemp(), "k.json"); self.n["A"].save_keystore(p, "pw")
        self.assertEqual(Node.load_keystore(p, "pw").sig_sk, self.n["A"].sig_sk)
        with self.assertRaises(crypto.DecryptionError): Node.load_keystore(p, "bad")


if __name__ == "__main__":
    unittest.main()
