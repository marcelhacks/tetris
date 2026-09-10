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
CONTEXTS = {}
EVENTS = []
AVAILABILITY.write_text("MUST_BE_DELETED_BY_AUTHENTICATED_RELAY", encoding="utf-8")


def record(value):
    with LOCK:
        value = {"time": time.time(), **value}
        EVENTS.append(value)
        (OUT / "target-events.json").write_text(json.dumps(EVENTS, indent=2), encoding="utf-8")


def action(principal, headers):
    result = {
        "action_time": time.time(),
        "principal": principal,
        "requested_action": headers.get("X-Lab-Action"),
        "nonce": NONCE,
        "availability_existed_before": AVAILABILITY.exists(),
    }
    if AVAILABILITY.exists():
        AVAILABILITY.unlink()
    INTEGRITY.write_text(f"AUTHENTICATED_WRITE:{principal}:{NONCE}", encoding="utf-8")
    process = subprocess.run(
        ["cmd.exe", "/d", "/c", f">\"{EXECUTION}\" echo|set /p=AUTHENTICATED_COMMAND_EXEC_{NONCE}"],
        text=True, capture_output=True, timeout=10,
    ) if os.name == "nt" else subprocess.run(
        ["/bin/sh", "-c", f"printf %s AUTHENTICATED_COMMAND_EXEC_{NONCE} > '{EXECUTION}'"],
        text=True, capture_output=True, timeout=10,
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
    def log_message(self, fmt, *args):
        record({"event":"http-log","message":fmt % args,"client":self.client_address[0]})
    def send_body(self, status, body=b"", challenge=None):
        self.send_response(status)
        if challenge is not None: self.send_header("WWW-Authenticate", challenge)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        if body: self.wfile.write(body); self.wfile.flush()
    def handle_auth(self):
        auth=self.headers.get("Authorization","")
        key=id(self.connection)
        record({"event":"request","method":self.command,"path":self.path,
                "has_authorization":bool(auth),"client":self.client_address[0]})
        if not auth.startswith("NTLM "):
            self.send_body(401,b"{}","NTLM"); return
        try:
            incoming=base64.b64decode(auth[5:])
            with LOCK:
                context=CONTEXTS.get(key)
                if context is None:
                    context=spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
                    CONTEXTS[key]=context
            outgoing=context.step(incoming)
            if not context.complete:
                self.send_body(401,b"{}","NTLM "+base64.b64encode(outgoing or b"").decode()); return
            principal=str(context.client_principal or "unknown")
            result=action(principal,self.headers)
            self.send_body(200,json.dumps({"authenticated":True,**result}).encode())
        except Exception as exc:
            record({"event":"auth-error","error":repr(exc)})
            self.send_body(403,json.dumps({"error":repr(exc)}).encode())
    do_GET=handle_auth
    do_POST=handle_auth
    do_PUT=handle_auth
    do_DELETE=handle_auth
    do_OPTIONS=handle_auth
    do_PROPFIND=handle_auth

if __name__=="__main__":
    port=int(os.environ.get("LAB_TARGET_PORT","8080"))
    record({"event":"server-start","port":port,"nonce":NONCE,"user_file":os.environ.get("NTLM_USER_FILE")})
    ThreadingHTTPServer(("127.0.0.1",port),Handler).serve_forever()
