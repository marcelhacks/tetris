from __future__ import annotations

import base64
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import spnego

OUT = Path(os.environ.get("LAB_TARGET_OUT", "target-out")).resolve()
OUT.mkdir(parents=True, exist_ok=True)
PROOF = OUT / "target-proof.json"
AVAILABILITY = OUT / "availability-marker.txt"
INTEGRITY = OUT / "integrity-marker.txt"
EXECUTION = OUT / "execution-marker.txt"
NONCE = os.environ.get("LAB_NONCE", "missing-nonce")
LOCK = threading.Lock()
CONTEXTS: dict[int, spnego.ContextProxy] = {}
EVENTS: list[dict] = []

AVAILABILITY.write_text("MUST_BE_DELETED_BY_AUTHENTICATED_RELAY", encoding="utf-8")


def record(event: dict) -> None:
    with LOCK:
        event = {"time": time.time(), **event}
        EVENTS.append(event)
        (OUT / "target-events.json").write_text(json.dumps(EVENTS, indent=2), encoding="utf-8")


def perform_authenticated_action(principal: str, headers) -> dict:
    requested = headers.get("X-Lab-Action", "authenticated-default")
    result = {
        "principal": principal,
        "requested_action": requested,
        "nonce": NONCE,
        "availability_existed_before": AVAILABILITY.exists(),
    }
    if AVAILABILITY.exists():
        AVAILABILITY.unlink()
    INTEGRITY.write_text(f"AUTHENTICATED_WRITE:{principal}:{NONCE}", encoding="utf-8")

    # Controlled equivalent of an authenticated administrative execution endpoint.
    # The command and destination are fixed by the lab, not supplied by the network client.
    process = subprocess.run(
        ["/bin/sh", "-c", f"printf %s AUTHENTICATED_COMMAND_EXEC_{NONCE} > '{EXECUTION}'"],
        text=True,
        capture_output=True,
        timeout=10,
    )
    result.update(
        availability_exists_after=AVAILABILITY.exists(),
        integrity_marker=INTEGRITY.read_text(errors="replace") if INTEGRITY.exists() else None,
        command_returncode=process.returncode,
        command_stdout=process.stdout,
        command_stderr=process.stderr,
        execution_marker=EXECUTION.read_text(errors="replace") if EXECUTION.exists() else None,
    )
    PROOF.write_text(json.dumps(result, indent=2), encoding="utf-8")
    record({"event": "authenticated-action", **result})
    return result


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ControlledNTLMTarget/1.0"

    def log_message(self, fmt, *args):
        record({"event": "http-log", "message": fmt % args, "client": self.client_address[0]})

    def _send(self, status: int, body: bytes = b"", authenticate: str | None = None):
        self.send_response(status)
        if authenticate is not None:
            self.send_header("WWW-Authenticate", authenticate)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        if body:
            self.wfile.write(body)
            self.wfile.flush()

    def _handle(self):
        auth = self.headers.get("Authorization", "")
        key = self.connection.fileno()
        record({"event": "request", "method": self.command, "path": self.path,
                "has_authorization": bool(auth), "client": self.client_address[0]})
        if not auth.startswith("NTLM "):
            self._send(401, b"{}", "NTLM")
            return
        try:
            incoming = base64.b64decode(auth[5:])
            with LOCK:
                context = CONTEXTS.get(key)
                if context is None:
                    context = spnego.server(protocol="ntlm")
                    CONTEXTS[key] = context
            outgoing = context.step(incoming)
            if not context.complete:
                challenge = "NTLM " + base64.b64encode(outgoing or b"").decode()
                self._send(401, b"{}", challenge)
                return
            principal = str(context.client_principal or "unknown")
            result = perform_authenticated_action(principal, self.headers)
            body = json.dumps({"authenticated": True, **result}).encode()
            self._send(200, body)
        except Exception as exc:
            record({"event": "auth-error", "error": repr(exc)})
            body = json.dumps({"authenticated": False, "error": repr(exc)}).encode()
            self._send(403, body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_OPTIONS = _handle
    do_PROPFIND = _handle


if __name__ == "__main__":
    port = int(os.environ.get("LAB_TARGET_PORT", "8080"))
    record({"event": "server-start", "port": port, "nonce": NONCE})
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
