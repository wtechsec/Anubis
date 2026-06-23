+++
title = "load_dll"
chapter = false
weight = 100
hidden = false
+++

## Summary

Loads a DLL from disk into the agent's process using `ctypes.WinDLL` (LoadLibrary) and optionally calls a specified export function.

- **Platform**: Windows only
- **Needs Admin**: No
- **MITRE ATT&CK**: T1059.006 / T1127
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### path
- Description: Full or relative path to the DLL on the target system
- Required: Yes

#### export *(optional)*
- Description: Name of the export function to call after loading
- Required: No

## Usage

```
load_dll C:\Windows\Temp\implant.dll
load_dll C:\Windows\Temp\loader.dll Run
```

## MITRE ATT&CK Mapping

- **T1059.006** — Command and Scripting Interpreter: Python
- **T1127** — Trusted Developer Utilities Proxy Execution

## Notes

- The export function must return an integer value and **must not** call `ExitProcess` — that would also terminate the agent process.
- Useful for loading reflective DLL implants or custom loaders without spawning a new process.
- Combine with `upload` to stage the DLL to the target first, then load it.

---

## Resumo em Português (PT-BR)

Carrega uma DLL do disco no processo do agente via `ctypes.WinDLL` (LoadLibrary) e, opcionalmente, chama um export especificado.

**Importante:** o export não deve chamar `ExitProcess` — isso encerraria também o processo do agente.

Fluxo típico: `upload` → `load_dll` para staging e execução sem criar novo processo.
