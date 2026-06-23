+++
title = "ps_full"
chapter = false
weight = 100
hidden = false
+++

## Summary

Returns a full process listing on Windows, including process name, PID, parent PID, architecture (x86/x64), command line, and executable path. Integrates with Mythic's process browser UI.

- **Platform**: Windows only
- **Needs Admin**: No (some process details may be unavailable without elevation)
- **MITRE ATT&CK**: T1057 — Process Discovery, T1106 — Native API
- **UI Feature**: `process_browser:list`
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

None.

## Usage

```
ps_full
```

## MITRE ATT&CK Mapping

- **T1057** — Process Discovery
- **T1106** — Native API

## Detailed Summary

Uses `Psapi.EnumProcesses` to enumerate all PIDs, then opens each process with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` to read the PEB and retrieve process parameters via `NtQueryInformationProcess`. Architecture is determined via `IsWow64Process`.

Per-process fields returned:

| Field | Description |
|---|---|
| `process_id` | PID |
| `parent_process_id` | PPID |
| `name` | Process executable name |
| `bin_path` | Full path to executable |
| `architecture` | `x86` or `x64` |
| `command_line` | Full command line string |
| `integrity_level` | Session ID |

The process list populates Mythic's Process Browser, where operators can directly task `kill` (terminate process) and `shinject` (inject shellcode) on selected entries.

---

## Resumo em Português (PT-BR)

Retorna listagem completa de processos no Windows usando `Psapi.EnumProcesses` + `NtQueryInformationProcess` para ler o PEB de cada processo. Inclui: nome, PID, PPID, arquitetura (x86/x64), path do executável e linha de comando completa.

Popula o Process Browser do Mythic — a partir da UI é possível acionar `kill` (terminar) e `shinject` (injetar shellcode) diretamente por processo.
