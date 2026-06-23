+++
title = "ls"
chapter = false
weight = 100
hidden = false
+++

## Summary

Lists files and attributes of a specified path. Integrates with Mythic's file browser (`file_browser:list`), populating the directory tree with per-entry metadata.

- **Platform**: Windows
- **Needs Admin**: No
- **MITRE ATT&CK**: T1083 — File and Directory Discovery
- **UI Feature**: `file_browser:list`
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### path
- Description: Path of file or folder to list. Accepts absolute or relative paths.
- Required: No
- Default: `.` (current directory)

## Usage

```
ls
ls C:\Users
ls C:\Windows\System32
ls ..\Documents
```

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery

## Detailed Summary

Uses Python `os` library functions to stat the target path and enumerate directory contents. Returns per-entry metadata:

| Field | Description |
|---|---|
| `name` | Entry filename |
| `is_file` | Boolean — true for files, false for directories |
| `size` | File size in bytes |
| `permissions` | Octal permission string (e.g. `644`) |
| `access_time` | Last access timestamp (milliseconds epoch) |
| `modify_time` | Last modification timestamp (milliseconds epoch) |

The `file_browser` struct is also pushed to the active task, populating Mythic's file browser UI tree. From the browser, per-entry actions include: **View Permissions**, **List Contents** (`ls`), **Download File** (`download`).

---

## Resumo em Português (PT-BR)

Lista arquivos e atributos de um path. Retorna por entrada: nome, tamanho, permissões (octal), timestamp de acesso e modificação, flag arquivo/diretório. Popula o file browser interativo do Mythic com estes metadados.

Ações disponíveis no file browser por entrada: **View Permissions**, **List Contents** (re-executa `ls`), **Download File** (aciona `download`).
