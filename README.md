# PQC-Ledger — Quantum-Resistant Medical Record Blockchain (MACS 902)

Hybrid post-quantum blockchain prototype: **ML-KEM-768 (FIPS 203)** key encapsulation +
**AES-256-GCM** payload encryption + **ML-DSA-65 (FIPS 204)** signatures + **SHA-256** hashing / Merkle tree / proof-of-work.

## Setup (Linux/macOS: liboqs backend; any OS: pure-Python fallback)
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate        macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python main.py              # interactive menu (live demo)
python main.py --auto       # run every demo non-interactively
python main.py --difficulty 3   # faster mining on slow laptops
python -m unittest -v       # 16 unit tests
```

## Project layout
| File | Role |
|---|---|
| `pqc_ledger/crypto.py` | All primitives in one auditable file (ML-KEM, ML-DSA, AES-GCM, HKDF, SHA-256) |
| `pqc_ledger/wallet.py` | Node identities, scrypt+AES-GCM encrypted keystore, public-key registry (rotate / revoke) |
| `pqc_ledger/ledger.py` | Transaction (encrypt-then-sign), Merkle tree, Block, PoW, Blockchain, chain audit |
| `pqc_ledger/network.py` | Real TCP node server/client (length-prefixed JSON), full admission check on receive |
| `pqc_ledger/scenarios.py` | Demo menu items / attack simulations |
| `pqc_ledger/benchmark.py` | Classical vs PQC size & timing comparison |
| `main.py` | CLI menu |
| `tests/` | Unit tests |

## PQC backend: liboqs (preferred) with automatic pure-Python fallback
`pqc_ledger/crypto.py` uses **liboqs** (Open Quantum Safe, C, constant-time) through `liboqs-python` when it
imports, and otherwise falls back to the pure-Python `kyber-py` / `dilithium-py` (FIPS 203/204-conformant but
educational, not constant-time). The active backend is printed at start-up (`crypto.BACKEND`).
* `pip install liboqs-python` installs only a thin wrapper. The **first** `import oqs` clones and builds the liboqs
  C library (needs `git`, `cmake`, a C compiler; about 5-10 minutes once). On Kali/Debian/Ubuntu:
  `sudo apt install git cmake build-essential ninja-build libssl-dev`.
* Force the fallback: `PQC_BACKEND=python python main.py`.
* Both backends give identical key/signature sizes (ML-DSA-65: 1952 B key, 3309 B signature), and all tests pass on both.

## Known simplifications
* Nodes run on one machine (localhost TCP demo, no peer discovery/gossip/consensus between nodes); registry is in memory rather than on-chain.
* Proof-of-work is for illustration; real permissioned ledgers usually use BFT consensus.
* Public ledger stores ciphertext only; one recipient per transaction (multi-recipient = one KEM ciphertext each).
* Key rotation: `reencrypt_records()` re-encrypts old records to the new KEM key as new transactions, then
  `discard_old_keys()` destroys the old key (crypto-shredding). On-chain ciphertext is immutable, so this only
  protects against FUTURE leaks of the old key, not a key that was already stolen. No ratcheting/forward secrecy.
* Off-chain mode (`create_transaction(..., store=OffChainStore())`): only SHA-256(nonce||ciphertext) is on-chain;
  deleting the off-chain blob satisfies erasure requests (GDPR Art.17) while the chain stays valid.
* Network: real TCP sockets on localhost (`network.py`), no TLS - payloads are already E2E encrypted and signed.
* Demo prints shared secrets/AES keys for teaching — never do this in production.
