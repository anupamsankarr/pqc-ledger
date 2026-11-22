"""ui.py - tiny terminal helpers (colours, hex truncation, pausing). Stdlib only."""
import os
import sys

AUTO = False  # set True by `--auto` to skip "press Enter" pauses
if os.name == "nt":
    os.system("")  # enables ANSI escape codes on Windows 10+ terminals
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else str(s)


def green(s): return _c("92", s)
def red(s): return _c("91", s)
def yellow(s): return _c("93", s)
def cyan(s): return _c("96", s)
def bold(s): return _c("1", s)
def dim(s): return _c("2", s)


def banner(title):
    print("\n" + cyan("=" * 78))
    print(cyan("  " + bold(title)))
    print(cyan("=" * 78))


def step(n, text):
    print("\n" + yellow(f"[Step {n}] ") + bold(text))


def ok(text): print("  " + green("[PASS] ") + text)
def bad(text): print("  " + red("[FAIL] ") + text)
def info(text): print("  " + dim("[i] ") + text)


def hexs(b: bytes, n: int = 14) -> str:
    """Hex preview: first n bytes + total length, so keys fit on a projector."""
    if len(b) <= n:
        return b.hex()
    return f"{b[:n].hex()}...  ({len(b):,} bytes)"


def kv(label, value, width=40):
    print(f"    {label:<{width}} {value}")


def pause(msg="Press Enter to continue..."):
    if not AUTO:
        input(dim(f"\n  {msg}"))
