"""
Persistent GLiNER daemon — loads the model once, serves predictions via Unix socket.
Stays alive across Claude sessions. Auto-started by the wrapper if not running.
"""

import json
import os
import socket
import sys
import threading

SOCKET_PATH = os.path.expanduser("~/.erebus/gliner.sock")
PID_PATH = os.path.expanduser("~/.erebus/gliner.pid")

GLINER_LABELS = [
    "person", "email address", "phone number", "address",
    "organization", "credit card number", "social security number",
    "iban", "passport number", "ip address", "username",
    "password", "api key", "date of birth", "bank account number",
]


def _load_model():
    import torch
    torch.set_num_threads(4)
    from gliner import GLiNER
    return GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")


def handle_client(conn, model):
    """Handle a single client connection: receive text, return entities."""
    try:
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
            # Protocol: newline-terminated JSON
            if b"\n" in data:
                break

        line = data.split(b"\n", 1)[0]
        if not line:
            return

        req = json.loads(line)
        text = req.get("text", "")
        threshold = req.get("threshold", 0.7)
        labels = req.get("labels", GLINER_LABELS)

        if text:
            entities = model.predict_entities(text, labels, threshold=threshold)
            result = [{"start": e["start"], "end": e["end"], "label": e["label"],
                       "text": e["text"]} for e in entities]
        else:
            result = []

        conn.sendall(json.dumps(result).encode() + b"\n")
    except Exception as e:
        try:
            conn.sendall(json.dumps({"error": str(e)}).encode() + b"\n")
        except Exception:
            pass
    finally:
        conn.close()


def run_daemon():
    """Main daemon loop."""
    # Clean up stale socket
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)

    # Write PID
    with open(PID_PATH, "w") as f:
        f.write(str(os.getpid()))

    # Load model (this is the slow part — only happens once)
    print("Loading GLiNER model...", file=sys.stderr, flush=True)
    model = _load_model()
    print("GLiNER model ready.", file=sys.stderr, flush=True)

    # Listen on Unix socket
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(5)

    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn, model), daemon=True).start()


def is_daemon_running() -> bool:
    """Check if the daemon is alive."""
    if not os.path.exists(PID_PATH):
        return False
    try:
        with open(PID_PATH) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)  # signal 0 = check if alive
        return True
    except (ValueError, ProcessLookupError, PermissionError):
        return False


def ensure_daemon():
    """Start the daemon if not already running."""
    if is_daemon_running():
        return

    # Fork a daemon process
    pid = os.fork()
    if pid > 0:
        # Parent — wait briefly for socket to appear
        import time
        for _ in range(100):  # up to 10s
            if os.path.exists(SOCKET_PATH):
                return
            time.sleep(0.1)
        return

    # Child — become a daemon
    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        os._exit(0)

    # Grandchild — the actual daemon
    # Redirect stdin/stdout to /dev/null (keep stderr for logging)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)  # stdin
    os.dup2(devnull, 1)  # stdout
    os.close(devnull)
    run_daemon()


def predict_via_daemon(text: str, threshold: float = 0.5) -> list[dict] | None:
    """Send text to the daemon, get back entities. Returns None if daemon unavailable."""
    if not os.path.exists(SOCKET_PATH):
        return None

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(SOCKET_PATH)

        req = json.dumps({"text": text, "threshold": threshold}) + "\n"
        sock.sendall(req.encode())
        sock.shutdown(socket.SHUT_WR)

        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk

        sock.close()
        result = json.loads(data)
        if isinstance(result, dict) and "error" in result:
            return None
        return result
    except Exception:
        return None


if __name__ == "__main__":
    run_daemon()
