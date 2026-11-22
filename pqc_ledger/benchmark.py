"""benchmark.py - classical vs post-quantum key/signature sizes and timings."""
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from . import crypto, ui

DER = dict(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _avg_ms(fn, n):
    t = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t) / n * 1000


def classical_rows(n):
    rows, msg = [], b"benchmark message"
    for bits in (2048, 3072):
        k = rsa.generate_private_key(65537, bits)
        sig = k.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        rows.append((f"RSA-{bits} (signature)", len(k.public_key().public_bytes(**DER)), "-", len(sig),
                     _avg_ms(lambda: rsa.generate_private_key(65537, bits), 1),
                     _avg_ms(lambda: k.sign(msg, padding.PKCS1v15(), hashes.SHA256()), n),
                     _avg_ms(lambda: k.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256()), n),
                     "Broken by Shor"))
    k = ec.generate_private_key(ec.SECP256K1())  # curve used by Bitcoin & Ethereum
    sig = k.sign(msg, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig)
    pk = k.public_key().public_bytes(encoding=serialization.Encoding.X962,
                                     format=serialization.PublicFormat.CompressedPoint)
    rows.append(("ECDSA secp256k1 (Bitcoin/ETH)", len(pk), 32, 64,
                 _avg_ms(lambda: ec.generate_private_key(ec.SECP256K1()), n),
                 _avg_ms(lambda: k.sign(msg, ec.ECDSA(hashes.SHA256())), n),
                 _avg_ms(lambda: k.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA256())), n),
                 "Broken by Shor"))
    e = ed25519.Ed25519PrivateKey.generate()
    sig = e.sign(msg)
    rows.append(("Ed25519 (signature)", 32, 32, len(sig),
                 _avg_ms(ed25519.Ed25519PrivateKey.generate, n), _avg_ms(lambda: e.sign(msg), n),
                 _avg_ms(lambda: e.public_key().verify(sig, msg), n), "Broken by Shor"))
    return rows


def pqc_sig_rows(n):
    rows, msg = [], b"benchmark message"
    for name, alg in crypto.ALL_DSAS.items():
        pk, sk = alg.keygen()
        sig = alg.sign(sk, msg)
        rows.append((name, len(pk), len(sk), len(sig), _avg_ms(alg.keygen, n),
                     _avg_ms(lambda: alg.sign(sk, msg), n), _avg_ms(lambda: alg.verify(pk, msg, sig), n),
                     "Quantum-resistant"))
    return rows


def kem_rows(n):
    rows = []
    x = x25519.X25519PrivateKey.generate()
    peer = x25519.X25519PrivateKey.generate().public_key()
    rows.append(("X25519 ECDH", 32, 32, 32, _avg_ms(x25519.X25519PrivateKey.generate, n),
                 _avg_ms(lambda: x.exchange(peer), n), _avg_ms(lambda: x.exchange(peer), n), "Broken by Shor"))
    for name, alg in crypto.ALL_KEMS.items():
        ek, dk = alg.keygen()
        ss, ct = alg.encaps(ek)
        rows.append((name, len(ek), len(dk), len(ct), _avg_ms(alg.keygen, n),
                     _avg_ms(lambda: alg.encaps(ek), n), _avg_ms(lambda: alg.decaps(dk, ct), n),
                     "Quantum-resistant"))
    return rows


def _table(title, cols, rows):
    print("\n  " + ui.bold(title))
    head = f"  {'Algorithm':<31}{cols[0]:>9}{cols[1]:>9}{cols[2]:>11}{'t1 ms':>9}{'t2 ms':>9}{'t3 ms':>9}  Quantum status"
    print(ui.dim(head))
    for r in rows:
        colour = ui.green if r[-1].startswith("Quantum") else ui.red
        print(f"  {r[0]:<31}{r[1]:>9,}{str(r[2]) if r[2]=='-' else format(r[2], ','):>9}{r[3]:>11,}"
              f"{r[4]:>9.2f}{r[5]:>9.2f}{r[6]:>9.2f}  {colour(r[7])}")


def run(n=3):
    ui.banner("BENCHMARK: Classical (ECC/RSA) vs Post-Quantum (ML-DSA / ML-KEM)")
    ui.info(f"sizes in bytes (measured live); times = mean of {n} runs on THIS machine")
    ui.info(f"PQC backend: {crypto.BACKEND}")
    if "pure-Python" in crypto.BACKEND:
        ui.info("Pure-Python PQC is ~10-100x slower than C (liboqs); compare SIZES, not absolute times.")
    classical, pqc = classical_rows(n), pqc_sig_rows(n)
    _table("Digital signatures   (t1=keygen, t2=sign, t3=verify)", ("PubKey", "SecKey", "Signature"),
           classical + pqc)
    _table("Key establishment    (t1=keygen, t2=encaps/ECDH, t3=decaps/ECDH)", ("PubKey", "SecKey", "Ciphertext"),
           kem_rows(n))

    ecdsa = next(r for r in classical if r[0].startswith("ECDSA"))
    dsa = next(r for r in pqc if r[0] == "ML-DSA-65")
    per_tx_c, per_tx_q = ecdsa[1] + ecdsa[3], dsa[1] + dsa[3]
    ntx = 2000
    print("\n  " + ui.bold(f"Blockchain impact: authentication data (pubkey + signature) for a {ntx:,}-tx block"))
    ui.kv("ECDSA secp256k1  (33 B key + 64 B sig)", f"{per_tx_c * ntx / 1024:>9,.1f} KiB")
    ui.kv("ML-DSA-65        (1952 B key + 3309 B sig)", f"{per_tx_q * ntx / 1024:>9,.1f} KiB")
    ui.kv("Expansion factor", ui.yellow(f"~{per_tx_q / per_tx_c:.0f}x  (signature-only: {dsa[3] / ecdsa[3]:.0f}x)"))
    ui.info("Trade-off: PQC costs bandwidth/storage, not security. Mitigations: registry-by-reference "
            "(our prototype stores no pubkey in tx), signature aggregation, off-chain storage.")
