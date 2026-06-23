+++
title = "load_module"
chapter = false
weight = 100
hidden = false
+++

## Summary

Installs a Python module into the agent's environment from a zipped library file received via Mythic, without requiring `pip` on the target. The module is loaded entirely in memory via a custom import finder.

- **Platform**: Windows / Linux / macOS
- **Needs Admin**: No
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### file
- Description: Zipped Python library to install (upload via Mythic file manager)
- Required: Yes

#### module_name
- Description: Name of the module being loaded (e.g. `requests`, `dns`, `cryptography`)
- Required: Yes

## Usage

```
load_module (select requests.zip) requests
load_module (select dns.zip) dns
```

## Notes

- Implements a custom `meta_path` finder that serves module imports directly from the in-memory zip file.
- Once loaded, the module can be used in `eval_code` or loaded commands without any on-disk installation.
- Use `unload_module` to remove a loaded module.

---

## Resumo em Português (PT-BR)

Instala um módulo Python no ambiente do agente a partir de um zip enviado pelo Mythic, sem `pip` no target. Implementa um finder customizado em `sys.meta_path` que serve imports diretamente da memória.

Após carregado, o módulo fica disponível para uso em `eval_code` e comandos carregados via `load`. Use `unload_module` para remover.
