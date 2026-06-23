+++
title = "load"
chapter = false
weight = 100
hidden = false
+++

## Summary

Dynamically loads a new command into the running agent via the C2 channel. The command code is fetched from Mythic and injected into the agent class at runtime, extending capabilities without redeployment.

- **Platform**: Windows / Linux / macOS
- **Needs Admin**: No
- **MITRE ATT&CK**: T1030, T1129
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### cmd_to_load
- Description: Name of the Anubis command to load (must exist in Mythic's command list for this agent)
- Required: Yes

## Usage

```
load watch_dir
load shinject
load dump_lsass
```

## MITRE ATT&CK Mapping

- **T1030** — Data Transfer Size Limits
- **T1129** — Shared Modules

## Notes

- The command Python file is Base64-encoded and sent down in chunks; `load` supports large command files via chunked transfer.
- After loading, the command is available as a method on the agent class and registered with Mythic's command list.
- Use `unload` to remove a dynamically loaded command and reduce the agent's capability footprint.

---

## Resumo em Português (PT-BR)

Carrega um novo comando no agente em runtime via canal C2. O código do comando é baixado do Mythic em chunks, decodificado e injetado como método na classe do agente — sem necessidade de redeployment.

Use `unload` para remover o comando após uso e reduzir a superfície de capacidades expostas.
