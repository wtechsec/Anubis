+++
title = "jobs"
chapter = false
weight = 100
hidden = false
+++

## Summary

Lists all currently running long-lived background jobs in the agent.

- **Platform**: Windows / Linux / macOS
- **Needs Admin**: No
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

None.

## Usage

```
jobs
```

## Notes

- Returns a list of `[command_name, task_id]` pairs for each active background job.
- SOCKS internal threads (`a2m`/`m2a`) are excluded — only the main SOCKS task appears.
- Use the returned task ID with `jobkill` to stop a specific job.
- Commands that create background jobs: `download`, `watch_dir`, `socks`, `screenshot2`, `dump_lsass`.

---

## Resumo em Português (PT-BR)

Lista todos os jobs de longa duração em execução no agente. Retorna pares `[nome_do_comando, task_id]` por job ativo. Threads internas do SOCKS (`a2m`/`m2a`) são omitidas.

Use o task_id retornado com `jobkill` para parar um job específico.
