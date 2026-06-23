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
| EXE blocked by AppLocker / WDAC | Deliver as `.py` / `.pyw` or via Python Embeddable (no installation required) |
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
- `RevertToSelf()` is called after any SYSTEM token impersonation

---

## Considerações de OPSEC (PT-BR)

### Comunicações
- Use jitter no beacon para evitar padrões previsíveis: `sleep 60 20`
- O agente usa encoding base64url-safe para evitar corrupção de parâmetros GET por proxies Cloudflare
- Desative verificação de certificado TLS no build se usar self-signed ou tunnel

### Armazenamento e Entrega do Payload
- Use formato `base64` + obfuscação XOR para reduzir detecção estática em disco
- Se EXE for bloqueado por AppLocker/WDAC, entregue como `.py`/`.pyw` ou via Python Embeddable
- Carregue capacidades adicionais via `load` após acesso inicial, reduzindo footprint inicial

### Execução e Injeção
- `shell` (cmd.exe): **alto risco** — criação de processo monitorada (Event ID 4688)
- `shinject` (VirtualAllocEx+RWX): **alto risco** — alocação RWX flagada pela maioria dos EDR
- `dump_lsass` (fork NtCreateProcessEx): **risco médio** — bypassa hooks por PID do LSASS, mas OpenProcess ainda é logado; Credential Guard bloqueia completamente

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
