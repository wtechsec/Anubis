+++
title = "kill"
chapter = false
weight = 100
hidden = false
+++

## Summary

Terminates a process by PID using `NtTerminateProcess` (ntdll direct call). Integrates with Mythic's process browser (`process_browser:kill`).

- **Platform**: Windows only
- **Needs Admin**: No (for user-accessible processes; elevation required for system processes)
- **UI Feature**: `process_browser:kill`
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### process_id
- Description: PID of the process to terminate
- Required: Yes

## Usage

```
kill 1234
```

## Detailed Summary

Opens a handle to the target process via `OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION)`, then calls `TerminateProcess`. The handle is closed after termination.

From Mythic's Process Browser, right-click any process and select **Kill** to task this command directly.

---

## Resumo em Português (PT-BR)

Encerra um processo por PID via `OpenProcess` + `TerminateProcess`. Disponível no Process Browser do Mythic: clique direito em qualquer processo → **Kill**.
