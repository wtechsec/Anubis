+++
title = "eval_code"
chapter = false
weight = 100
hidden = false
+++

## Summary

Executes arbitrary Python code in the agent's interpreter using `exec()`. Provides live Python access within the agent context, with full access to agent attributes and imported modules.

- **Platform**: Windows / Linux / macOS
- **Needs Admin**: No
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### code
- Description: Python code to execute in the agent interpreter
- Required: Yes

## Usage

```
eval_code import os; print(os.listdir('C:\\'))
eval_code self.current_directory = 'C:\\Windows'
eval_code import subprocess; print(subprocess.check_output('whoami /all', shell=True).decode())
eval_code print(self.agent_config)
```

## Notes

- Has full access to `self` (the agent object), allowing direct manipulation of agent state, config, and taskings.
- Output is captured via stdout redirection.
- Errors in eval code can cause exceptions in the agent thread — use carefully.
- Useful for ad-hoc operations not covered by existing commands without needing to `load` a new command.

---

## Resumo em Português (PT-BR)

Executa código Python arbitrário no intérprete do agente via `exec()`. Acesso completo ao objeto `self` do agente — permite manipular estado interno, importar módulos e executar lógica customizada sem carregar um novo comando.

Útil para operações pontuais que não justificam um `load` de novo comando. Erros podem lançar exceções na thread do agente — use com cuidado.
