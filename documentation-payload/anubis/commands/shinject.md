+++
title = "shinject"
chapter = false
weight = 100
hidden = false
+++

## Summary

Injects shellcode into a remote process using the classic `VirtualAllocEx + WriteProcessMemory + CreateRemoteThread` technique. The shellcode is retrieved from Mythic via the file upload channel and injected into the specified PID.

- **Platform**: Windows only
- **Needs Admin**: No (for user-accessible processes; elevation required for system processes)
- **MITRE ATT&CK**: T1055 — Process Injection
- **UI Feature**: `process_browser:inject`
- **Version**: 1.0
- **Author**: @wtechsec

{{% notice warning %}}
Match the architecture of your shellcode to the target process (x86 → x86 process, x64 → x64 process).
{{% /notice %}}

### Arguments

#### shellcode
- Description: File upload of shellcode to inject (upload via Mythic file manager)
- Required: Yes

#### process_id
- Description: PID of the target process to inject into
- Required: Yes

## Usage

```
shinject <file_id> <pid>
```

## MITRE ATT&CK Mapping

- **T1055** — Process Injection

## Detailed Summary

```
1. Retrieve shellcode from Mythic via chunked upload protocol (file_id)
2. OpenProcess(PROCESS_ALL_ACCESS, target_pid)
3. VirtualAllocEx(PAGE_EXECUTE_READWRITE) → allocate RWX memory in remote process
4. WriteProcessMemory → write shellcode bytes to allocated region
5. CreateRemoteThread → create thread at shellcode address in target process
```

{{% notice info %}}
`PAGE_EXECUTE_READWRITE` allocation is detectable by most EDR products. For improved evasion, consider using a reflective loader DLL via `load_dll` or loading shellcode in stages.
{{% /notice %}}

From Mythic's Process Browser, right-click any process and select **Inject** to task `shinject` directly with the selected PID.

---

## Resumo em Português (PT-BR)

Injeta shellcode em um processo remoto via `VirtualAllocEx + WriteProcessMemory + CreateRemoteThread`. O shellcode é baixado do Mythic via file_id e injetado no PID alvo.

**Atenção OPSEC:** alocação `PAGE_EXECUTE_READWRITE` é detectada pela maioria dos EDR. Para maior evasão, use um loader reflectivo via `load_dll`.

Disponível no Process Browser do Mythic: clique direito em qualquer processo → **Inject**.
