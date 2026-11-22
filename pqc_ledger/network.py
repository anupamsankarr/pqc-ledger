"""
network.py - a minimal REAL network layer: nodes exchange transactions over TCP sockets.

Wire format: 4-byte big-endian length + JSON (bytes fields hex-encoded).
The server validates every received transaction with the full admission check
(registered sender, key version, timestamp, replay, ML-DSA signature) and replies
{"ok": true, "tx_id": ...} or {"ok": false, "reason": ...}.

Security note: payloads are already end-to-end encrypted (ML-KEM + AES-GCM) and signed (ML-DSA),
so the transport leaks no plaintext and a network attacker cannot forge transactions. This
prototype does NOT add TLS (it would only add transport metadata protection); the server binds
to 127.0.0.1 only, caps message size, and applies socket timeouts.
"""
import json
import socket
import socketserver
import struct
import threading

from .ledger import Blockchain, Transaction, TransactionRejected

MAX_MSG = 1_000_000  # bytes; a transaction is ~10 KB hex-encoded


def _send_msg(sock, obj) -> None:
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def _recv_msg(sock):
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > MAX_MSG:
        raise ValueError("message too large")
    return json.loads(_recv_exact(sock, n))


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            msg = _recv_msg(self.request)
            if msg.get("type") != "tx":
                raise ValueError("unknown message type")
            tx = Transaction.from_dict(msg["tx"])
            with self.server.lock:
                self.server.ledger.add_transaction(tx)
            reply = {"ok": True, "tx_id": tx.tx_id}
        except TransactionRejected as exc:
            reply = {"ok": False, "reason": str(exc)}
        except Exception as exc:  # malformed / hostile input must never crash the node
            reply = {"ok": False, "reason": f"malformed message ({type(exc).__name__})"}
        try:
            _send_msg(self.request, reply)
        except OSError:
            pass


class NodeServer(socketserver.ThreadingTCPServer):
    """A node listening for transactions. port=0 -> the OS picks a free port."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, ledger: Blockchain, host: str = "127.0.0.1", port: int = 0):
        super().__init__((host, port), _Handler)
        self.ledger = ledger
        self.lock = threading.Lock()

    @property
    def port(self) -> int:
        return self.server_address[1]

    def start(self) -> "NodeServer":
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


def send_message(host: str, port: int, obj, timeout: float = 5) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as s:
        _send_msg(s, obj)
        return _recv_msg(s)


def send_transaction(host: str, port: int, tx: Transaction, timeout: float = 5) -> dict:
    return send_message(host, port, {"type": "tx", "tx": tx.to_dict()}, timeout)
