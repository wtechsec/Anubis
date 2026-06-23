+++
title = "unload"
chapter = false
weight = 100
hidden = false
+++

## Summary

Removes a previously dynamically-loaded command from the running agent, reducing the capability footprint in memory.

- **Platform**: Windows / Linux / macOS
- **Needs Admin**: No
- **MITRE ATT&CK**: T1030, T1129
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### function
- Description: Name of the command to unload
- Required: Yes

## Usage

```
unload watch_dir
unload dump_lsass
```

## Notes

- Only unloads the function from the running agent instance — does not affect the on-disk script.
- Recommended pattern: `load` → use → `unload` to minimize exposure window.
- Attempting to unload a built-in (non-dynamically-loaded) command will raise an error.

---

## Resumo em Português (PT-BR)

Remove um comando previamente carregado dinamicamente do agente em runtime. Reduz a superfície de capacidades expostas após uso.

Padrão recomendado: `load` → usar → `unload` para minimizar a janela de exposição.
