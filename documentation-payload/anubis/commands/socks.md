+++
title = "socks"
chapter = false
weight = 100
hidden = false
+++

## Summary

Starts or stops a reverse SOCKS5 proxy through the C2 channel. Once enabled, the operator can route external tool traffic into the target network through Mythic's SOCKS5 interface.

- **Platform**: Windows / Linux / macOS
- **Needs Admin**: No
- **MITRE ATT&CK**: T1090 — Proxy
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

#### action
- Description: `start` or `stop`
- Required: Yes

#### port
- Description: Local port on the Mythic server to expose as SOCKS5 proxy
- Required: Yes

## Usage

```
socks start 1080
socks stop 1080
```

## MITRE ATT&CK Mapping

- **T1090** — Proxy
- **T1090.002** — External Proxy

## Detailed Summary

The SOCKS5 proxy multiplexes all traffic through the existing encrypted C2 HTTP channel. Incoming connections on the Mythic SOCKS port are tunneled to the target network via the agent.

Configure proxychains or Burp Suite to use `127.0.0.1:<port>` on the Mythic server:

```ini
# /etc/proxychains.conf
[ProxyList]
socks5 127.0.0.1 1080
```

Tunable parameters (in source): `SOCKS_SLEEP_INTERVAL`, `QUEUE_TIMEOUT`, `MAX_THREADS`, `BUFSIZE` — adjust if experiencing sluggish throughput or high CPU.

Use `jobkill` to stop the proxy gracefully.

---

## Resumo em Português (PT-BR)

Inicia ou para um proxy SOCKS5 reverso pelo canal C2. Todo o tráfego SOCKS é multiplexado pelo canal HTTP cifrado existente.

Configure proxychains no servidor Mythic:
```ini
[ProxyList]
socks5 127.0.0.1 1080
```

Use `jobkill` para parar o proxy de forma limpa. Parâmetros ajustáveis no código: `SOCKS_SLEEP_INTERVAL`, `QUEUE_TIMEOUT`, `MAX_THREADS`.
