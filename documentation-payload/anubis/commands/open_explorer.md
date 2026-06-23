+++
title = "open_explorer"
chapter = false
weight = 100
hidden = false
+++

## Summary

Opens a directory in Mythic's interactive file browser. Lists the contents of the specified path and populates the file browser tree, allowing the operator to navigate directories and trigger download/upload/ls actions directly from the UI.

- **Platform**: Windows
- **Needs Admin**: No
- **MITRE ATT&CK**: T1083 — File and Directory Discovery
- **UI Feature**: `file_browser:open`
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### path *(optional)*
- Description: Directory path to open. Accepts absolute or relative paths.
- Required: No
- Default: Current working directory

## Usage

```
open_explorer
open_explorer C:\Users
open_explorer C:\Windows\System32
open_explorer ..\Documents
```

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery

## Notes

- Integrates with Mythic's file browser (`file_browser:open`). Double-clicking a folder in the browser automatically tasks `open_explorer` with that path.
- Per-entry metadata returned: name, size, permissions (octal), access time, modification time, is_file flag.
- The browser_script renders an interactive table with per-entry actions:
  - **Open Folder** — tasks `open_explorer` on the selected directory
  - **List Contents** — tasks `ls` for detailed listing
  - **Download File** — tasks `download` for the selected file

---

## Resumo em Português (PT-BR)

Abre um diretório no file browser interativo do Mythic. Lista o conteúdo do path e popula a árvore de navegação, permitindo ao operador navegar, visualizar e acionar download/upload diretamente pela UI.

Quando o operador clica duas vezes em uma pasta no file browser do Mythic, o comando `open_explorer` é automaticamente acionado com o path selecionado.

Retorna por entrada: nome, tamanho, permissões (octal), timestamp de acesso e modificação, flag de arquivo/diretório.
