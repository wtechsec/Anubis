+++
title = "jobkill"
chapter = false
weight = 100
hidden = false
+++

## Summary

Sends a stop signal to a running long-lived background job. The targeted job will check for the stop flag at its next iteration and exit gracefully.

- **Platform**: Windows / Linux / macOS
- **Needs Admin**: No
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### task_id
- Description: Task ID of the running job to stop (obtain from `jobs`)
- Required: Yes

## Usage

```
jobkill <task_id>
```

## Notes

- Use `jobs` to list running jobs and obtain their task IDs.
- The stop is cooperative: the job must check the `stopped` flag in its loop. All built-in long-running commands support this.
- Commands that respect `jobkill`: `download`, `watch_dir`, `socks`, `screenshot2`, `dump_lsass`, `load`, `load_module`.

---

## Resumo em Português (PT-BR)

Envia sinal de parada para um job de longa duração em execução. O job verifica a flag `stopped` na próxima iteração do seu loop e encerra de forma limpa.

Use `jobs` para listar os IDs dos jobs ativos antes de usar `jobkill`.

Todos os comandos built-in de longa duração (download, watch_dir, socks, screenshot2, dump_lsass) suportam parada via jobkill.
