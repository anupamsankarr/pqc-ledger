#!/usr/bin/env python3
"""
PQC-Ledger - Quantum-Resistant Medical Record Blockchain (MACS 902 group project)

  python main.py            interactive menu (use this in the live demo)
  python main.py --auto     run every demo non-interactively (smoke test)
  python main.py --difficulty 3   faster mining on slow laptops
"""
import argparse
import sys

from pqc_ledger import crypto, scenarios, ui

MENU = f"""
  {{b}}PQC-LEDGER{{r}}  |  {crypto.KEM_NAME} + {crypto.DSA_NAME} + AES-256-GCM + SHA-256
  ------------------------------------------------------------------
   1  Valid transaction: ML-KEM encrypt -> ML-DSA sign -> mine block
   2  Tamper detection (modify block / transaction)
   3  Forged identity / invalid signature rejection
   4  Unauthorized decryption failure
   5  Classical vs PQC benchmark (key & signature sizes)
   6  Non-repudiation: third-party audit of a signature
   7  Replay attack rejection
   8  View ledger
   9  Key management: keystore, rotation, re-encryption, revocation
   B  Real TCP network between nodes (sockets)
   C  Off-chain mode: right to erasure (GDPR/HIPAA)
   A  Run ALL demos in order
   0  Exit
"""

ACTIONS = {"1": scenarios.demo_valid, "2": scenarios.demo_tamper, "3": scenarios.demo_forgery,
           "4": scenarios.demo_unauthorized_decrypt, "5": scenarios.demo_benchmark,
           "6": scenarios.demo_nonrepudiation, "7": scenarios.demo_replay, "8": scenarios.demo_ledger,
           "9": scenarios.demo_keys, "B": scenarios.demo_network,
           "C": scenarios.demo_erasure, "A": scenarios.run_all}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--auto", action="store_true", help="run all demos without pausing")
    ap.add_argument("--difficulty", type=int, default=4, help="PoW leading hex zeros (default 4)")
    args = ap.parse_args()
    ui.AUTO = args.auto

    ui.banner("Quantum-Resistant Medical Record Ledger  -  MACS 902")
    ui.info(f"PQC backend: {crypto.BACKEND}")
    demo = scenarios.Demo(args.difficulty)
    ui.ok(f"Network ready: {', '.join(demo.registry.names())}  | genesis block mined")

    if args.auto:
        scenarios.run_all(demo)
        return 0
    while True:
        print(MENU.format(b=ui.USE_COLOR and "\033[1m" or "", r=ui.USE_COLOR and "\033[0m" or ""))
        choice = input("  Select> ").strip().upper()
        if choice == "0":
            return 0
        action = ACTIONS.get(choice)
        if not action:
            print("  Unknown option.")
            continue
        try:
            action(demo)
        except Exception as exc:  # keep the live demo alive no matter what
            ui.bad(f"Unexpected error: {exc!r}")
        ui.pause("Press Enter to return to the menu...")


if __name__ == "__main__":
    sys.exit(main())
