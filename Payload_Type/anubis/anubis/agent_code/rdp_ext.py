    def rdp_ext(self, task_id, target="", port=3389, username="", password="",
                domain="", socks_port=7005):
        if not target:
            return "rdp_ext: target required"

        import socket

        rdp_port = int(port) if port else 3389
        s_port   = int(socks_port) if socks_port else 7005

        # ── TCP probe: verifica se target:port é alcançável pelo agente ──────
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, rdp_port))
            sock.close()
            reachable = True
        except Exception as e:
            reachable = False
            probe_err = str(e)

        if not reachable:
            return (
                "[-] TCP {}:{} — UNREACHABLE pelo agente\n"
                "    Erro: {}\n"
                "[!] Verifique se RDP está habilitado no alvo e se a rota de rede existe."
            ).format(target, rdp_port, probe_err)

        # ── monta blocos de credencial ────────────────────────────────────────
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

        xf_target = " /v:{}".format(target)
        if rdp_port != 3389:
            xf_target = " /v:{}:{}".format(target, rdp_port)

        return (
            "[+] TCP {}:{} — REACHABLE\n"
            "[+] SOCKS5 iniciado na porta {} do servidor Mythic\n"
            "    (Se já estava rodando, ignore aviso de porta em uso)\n\n"
            "╔══ CONFIGURAÇÃO PROXYCHAINS ══════════════════════════════════╗\n"
            "║  /etc/proxychains4.conf  (ou ~/.proxychains/proxychains.conf)\n"
            "║  [ProxyList]\n"
            "║  socks5  127.0.0.1  {}\n"
            "╚══════════════════════════════════════════════════════════════╝\n\n"
            "── rdesktop (via proxychains) ─────────────────────────────────\n"
            "  proxychains rdesktop {}{} -g 1920x1080 -K\n\n"
            "── xfreerdp (via proxychains) ─────────────────────────────────\n"
            "  proxychains xfreerdp{}{} /cert-ignore +clipboard /dynamic-resolution\n\n"
            "── xfreerdp (SOCKS5 nativo — sem proxychains) ─────────────────\n"
            "  xfreerdp /proxy:socks5://127.0.0.1:{}{}{} /cert-ignore +clipboard /dynamic-resolution\n\n"
            "[*] Usuário : {}\n"
            "[*] Alvo    : {}:{}"
        ).format(
            target, rdp_port,
            s_port,
            s_port,
            target, rd_creds,
            xf_target, xf_creds,
            s_port, xf_target, xf_creds,
            user_display or "(não fornecido)",
            target, rdp_port
        )
