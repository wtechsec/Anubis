+++
title = "exit"
chapter = false
weight = 100
hidden = false
+++

## Summary

Terminates the Anubis agent process immediately.

- **Platform**: Windows / Linux / macOS
- **Needs Admin**: No
- **UI Feature**: `callback_table:exit`
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

None.

## Usage

```
exit
```

## Notes

- Available directly from Mythic's callback table (right-click on callback → Exit).
- Uses `os._exit(0)` for immediate termination — no cleanup or graceful shutdown.
- Running jobs are not stopped before exit. If needed, stop them with `jobkill` first.

---

## Resumo em Português (PT-BR)

Encerra o processo do agente imediatamente via `os._exit(0)`. Disponível no callback table do Mythic (clique direito → Exit). Não realiza cleanup — jobs em execução são encerrados abruptamente.
