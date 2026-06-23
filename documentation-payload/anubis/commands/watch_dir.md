+++
title = "watch_dir"
chapter = false
weight = 100
hidden = false
+++

## Summary

Continuously polls a directory at a configurable interval and reports any changes: new files, modifications, copies, moves, and deletions. Runs as a long-lived background job.

- **Platform**: Windows / Linux / macOS
- **Needs Admin**: No
- **MITRE ATT&CK**: T1083 — File and Directory Discovery
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### path
- Description: Directory to monitor (absolute or relative)
- Required: Yes

#### seconds
- Description: Polling interval in seconds
- Required: Yes

## Usage

```
watch_dir C:\Users\victim\Desktop 5
watch_dir C:\Users\victim\Documents 10
watch_dir \\server\share 30
```

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery

## Detailed Summary

On each poll cycle, the function walks the directory tree and compares MD5 hashes + paths against the previous state. Reports:

- `[*] New File:` — previously unseen file
- `[*] File Updated:` — file hash changed since last poll
- `[*] Copied File:` — new path with same hash as existing file
- `[*] Moved File:` — original path removed, same hash at new path
- `[*] Directory deleted:` — directory no longer present
- `[*] File deleted:` — file no longer present

Runs as a background job. Use `jobs` to get the task ID, `jobkill` to stop it.

---

## Resumo em Português (PT-BR)

Monitora um diretório por mudanças com polling a cada N segundos. Detecta: novos arquivos, modificações (hash MD5), cópias, movimentações e exclusões. Roda como job em background.

Use `jobs` para listar o task ID e `jobkill` para parar. Útil para monitorar diretórios de trabalho de usuários ou shares de rede.
