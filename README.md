<p align="center">
  <img src="https://4c22726d.git-6vm.pages.dev/2sxCepI01.svg" alt="Anubis Logo" width="300">
</p>

<h1 align="center">Anubis C2 Agent</h1>
<p align="center">Python C2 agent for the Mythic framework | Red Team & Adversary Simulation</p>

---

## Overview / Visão Geral

**EN:** Anubis is a cross-platform Python C2 agent for the [Mythic](https://github.com/its-a-feature/Mythic) framework, built for Red Team operations and adversary simulation. Supports Python 3.8 on Windows, Linux, and macOS, with a focus on Windows offensive capabilities including credential access, lateral movement, and RDP session hijacking.

**PT-BR:** Anubis é um agente C2 Python para o framework [Mythic](https://github.com/its-a-feature/Mythic), desenvolvido para operações de Red Team e simulação de adversários. Suporta Python 3.8 em Windows, Linux e macOS, com foco em capacidades ofensivas Windows: acesso a credenciais, movimentação lateral e hijack de sessões RDP.

Na mitologia egípcia, Anúbis era o guardião das passagens entre mundos. Aqui assume o papel de intermediário furtivo entre operador e alvo — operando na fronteira entre segurança e intrusão controlada.

---

## Key Features / Funcionalidades Principais

| Feature | EN | PT-BR |
|---|---|---|
| Encrypted comms | AES-256-CBC + HMAC-SHA256 (pure Python stdlib) | AES-256-CBC + HMAC-SHA256 sem dependências externas |
| Dynamic loading | Load/unload commands at runtime via C2 | Carrega/descarrega comandos em runtime via C2 |
| SOCKS5 proxy | Reverse tunnel through C2 channel | Túnel reverso pelo canal C2 |
| File transfer | Chunked upload/download, stoppable | Upload/download em chunks, interrompível |
| Token impersonation | Steal process tokens for privilege escalation (T1134) | Roubo de token de processo para elevação (T1134) |
| WMI lateral movement | Remote exec via COM vtable — no wmic.exe (T1047) | Execução remota WMI sem wmic.exe (T1047) |
| SCM lateral movement | Remote SYSTEM exec via Service Control Manager — no sc.exe (T1021.002) | Execução SYSTEM via SCM sem sc.exe (T1021.002) |
| RDP session hijacking | Hijack disconnected/active sessions without password (T1563.002) | Hijack sessões RDP sem senha (T1563.002) |
| LSASS dump | NtCreateProcessEx fork evasion (EDR bypass) | Evasão via fork NtCreateProcessEx (bypass EDR) |
| Shellcode injection | VirtualAllocEx + CRT via process browser | Injeção via process browser do Mythic |
| Screenshot | Pure ctypes GDI32/User32 — no pywin32 or Pillow | ctypes puro — sem pywin32 ou Pillow |
| Obfuscation | XOR + Base64 at build time | XOR + Base64 no build |
| Dropper formats | py / base64 / ps1 (Python Embeddable) / exe (PyInstaller) | py / base64 / ps1 (Python Embeddable) / exe (PyInstaller) |
| Jitter | Symmetric beacon jitter | Jitter simétrico no beacon |
| Cloudflare | URL-safe base64 for GET params | base64url-safe para parâmetros GET |

---

## Installation / Instalação

```bash
sudo ./mythic-cli install github https://github.com/wtechsec/Anubis.git
```

---

## Command Reference / Referência de Comandos

### File System

| Command | OS | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|
| `cd` | All | Change working directory | Muda o diretório de trabalho |
| `cwd` | All | Print current working directory | Exibe o diretório atual |
| `ls` | Windows | List files with metadata (file browser) | Lista arquivos e metadados (file browser) |
| `open_explorer` | Windows | Open directory in Mythic file browser | Abre diretório no file browser do Mythic |
| `cat` | All | Read file contents | Lê conteúdo de arquivo |
| `cp` | All | Copy file or directory | Copia arquivo ou diretório |
| `mv` | All | Move file or directory | Move arquivo ou diretório |
| `rm` | Windows | Remove file or directory | Remove arquivo ou diretório |
| `watch_dir` | All | Poll directory for changes (background job) | Monitora diretório por mudanças (job) |

### File Transfer

| Command | OS | MITRE | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|---|
| `download` | Windows | T1105 | Download file to Mythic | Download do target para o Mythic |
| `upload` | Windows | T1105 | Upload file to target | Upload do Mythic para o target |

### Execution

| Command | OS | MITRE | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|---|
| `shell` | All | T1059 | Execute system shell command | Executa comando no shell do sistema |
| `eval_code` | All | — | Execute Python code in agent interpreter | Executa Python no intérprete do agente |

### Process

| Command | OS | MITRE | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|---|
| `ps` | Win/Linux | T1057 | Concise process listing | Listagem resumida de processos |
| `ps_full` | Windows | T1057 | Full process listing (user, arch, path, cmdline) | Listagem completa (usuário, arq., path, cmdline) |
| `kill` | Windows | — | Terminate process by PID | Encerra processo por PID |
| `list_dlls` | Windows | — | List DLLs loaded in a process | Lista DLLs carregadas em um processo |

### Offensive (Windows)

| Command | OS | Admin | MITRE | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|---|---|
| `shinject` | Windows | No | T1055 | Shellcode injection (VirtualAllocEx + CRT) | Injeção de shellcode (VirtualAllocEx + CRT) |
| `load_dll` | Windows | No | T1059.006 | Load DLL from disk via LoadLibrary | Carrega DLL do disco via LoadLibrary |
| `dump_lsass` | Windows | **Yes** | T1003.001 | Fork-dump LSASS (NtCreateProcessEx evasion) | Dump LSASS por fork de processo (evasão EDR) |

### Lateral Movement / Privilege (Windows)

| Command | OS | MITRE | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|---|
| `token_steal` | Windows | T1134 | List / impersonate / exec via stolen process token | Lista / impersona / executa com token de processo |
| `wmi_exec` | Windows | T1047, T1021.003 | Remote exec via WMI COM vtable — no wmic.exe | Execução remota WMI sem wmic.exe — via vtable COM |
| `sc_exec` | Windows | T1021.002, T1543.003 | Remote SYSTEM exec via SCM API — no sc.exe | Execução SYSTEM via SCM API — sem sc.exe |
| `rdp_hijack` | Windows | T1563.002 | List/hijack RDP sessions without password (req. SYSTEM) | Lista/hijacka sessões RDP sem senha (req. SYSTEM) |
| `rdp_ext` | All | T1021.001, T1090 | RDP access via SOCKS5 tunnel — returns xfreerdp/rdesktop commands | Acesso RDP via tunnel SOCKS5 — retorna comandos prontos |

### Reconnaissance

| Command | OS | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|
| `env` | All | List all environment variables | Lista variáveis de ambiente |
| `pip_freeze` | All | List installed Python packages | Lista pacotes Python instalados |
| `list_modules` | All | List Python modules loaded in agent memory | Lista módulos Python no agente |

### Capture

| Command | OS | MITRE | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|---|
| `screenshot2` | Windows | T1113 | Capture screen — pure ctypes, no external deps | Captura tela — ctypes puro, sem deps externas |

### Tunneling / Pivoting

| Command | OS | MITRE | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|---|
| `socks` | All | T1090 | Start/stop reverse SOCKS5 proxy via C2 | Inicia/para proxy SOCKS5 reverso via C2 |

### Agent Management

| Command | OS | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|
| `sleep` | All | Set beacon interval and jitter | Define intervalo e jitter do beacon |
| `jobs` | All | List running background jobs | Lista jobs em execução |
| `jobkill` | All | Stop a running background job | Para um job em execução |
| `exit` | All | Terminate agent process | Encerra o processo do agente |
| `load` | All | Dynamically load a command via C2 | Carrega comando dinamicamente via C2 |
| `unload` | All | Unload a dynamic command | Remove comando dinâmico |
| `load_module` | All | Install Python module without pip | Instala módulo Python sem pip |
| `unload_module` | All | Uninstall a dynamic module | Remove módulo dinâmico |
| `load_script` | All | Load Python script into agent | Carrega script Python no agente |

### macOS Only

| Command | MITRE | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|
| `screenshot` | T1113 | Screen capture (CGDisplay API) | Captura tela via CGDisplay |
| `clipboard` | T1115 | Read clipboard contents | Lê área de transferência |
| `list_apps` | — | List running applications | Lista aplicações em execução |
| `list_tcc` | — | Read TCC privacy database | Lê banco de privacidade TCC |
| `spawn_jxa` | — | Execute JXA/AppleScript | Executa JXA/AppleScript |
| `vscode_list_recent` | — | List recent VSCode files | Arquivos recentes do VSCode |
| `vscode_open_edits` | — | List unsaved VSCode edits | Edições não salvas do VSCode |
| `vscode_watch_edits` | T1083 | Poll VSCode backups for edits | Monitora backups do VSCode |

---

## Build Options / Opções de Build

| Option | Values | Description (EN) | Descrição (PT-BR) |
|---|---|---|---|
| `python_version` | Python 3.8 / 2.7 | Python runtime version | Versão do Python |
| `output` | py / base64 / ps1 / exe | Output format | Formato de saída |
| `python_embed_url` | URL | Python Embeddable zip URL (ps1 format only) | URL do Python Embeddable (formato ps1) |
| `use_non_default_cryptography_lib` | No / Yes | Use `cryptography` pip library | Usar biblioteca `cryptography` |
| `obfuscate_script` | Yes / No | XOR + Base64 obfuscation | Obfuscação XOR + Base64 |
| `https_check` | Yes / No | Verify TLS certificate | Verificar certificado TLS |

### Output Format Details

| Format | Requires Python on target | Description |
|---|---|---|
| `py` | Yes | Plain Python script |
| `base64` | Yes | Base64-encoded blob for one-liner delivery |
| `ps1` | **No** | PowerShell dropper — downloads Python Embeddable (~8 MB), extracts to `%TEMP%\svc<uuid>\`, executes agent hidden |
| `exe` | **No** | Standalone EXE via PyInstaller (`--onefile --noconsole`) — built on Mythic server |

---

## OPSEC Notes / Notas de OPSEC

| Topic | EN | PT-BR |
|---|---|---|
| Beacon | Use jitter: `sleep 60 20` (±20%) | Use jitter: `sleep 60 20` (±20%) |
| Payload on disk | Enable obfuscation at build; use `base64` format | Ative obfuscação no build; use formato `base64` |
| No Python on target | Use `ps1` (Python Embeddable) or `exe` (PyInstaller) format | Use formato `ps1` ou `exe` — sem dependência Python no alvo |
| LSASS dump | Bypasses EDR hook on LSASS PID; `OpenProcess` still logged by Sysmon (Event ID 10) | Bypassa hook EDR por PID; `OpenProcess` ainda logado (Sysmon EID 10) |
| Credential Guard | Completely blocks `dump_lsass` — verify before attempting | Bloqueia completamente `dump_lsass` — verifique antes |
| Injection | RWX alloc flagged by most EDR; use reflective loader for evasion | Alocação RWX flagada pela maioria dos EDR |
| token_steal | Impersonation leaves no logon event; `ImpersonateLoggedOnUser` not monitored by default | Impersonação sem evento de logon; `ImpersonateLoggedOnUser` não monitorado por padrão |
| wmi_exec | No wmic.exe spawned; generates WMI activity log on target (Microsoft-Windows-WMI-Activity/Operational) | Sem wmic.exe; gera log WMI no alvo |
| sc_exec | Generates EID 7045 (service created) on target — service name is randomized | Gera EID 7045 no alvo; nome do serviço é randômico |
| rdp_hijack | Disconnected session hijack generates no EID 4624; only EID 4778 if logon audit enabled | Hijack de sessão desconectada não gera EID 4624 |

---

## Lateral Movement Kill Chain

```
# Token Impersonation → WMI → SCM → RDP Hijack

token_steal                          # List tokens from running processes
token_steal 1884                     # Impersonate domain admin token (no logon event)

wmi_exec 10.12.193.4 "whoami"        # Validate lateral access via WMI (no wmic.exe)

sc_exec 10.12.193.4 \               # Deploy Anubis as SYSTEM on lateral host
  "powershell -ep bypass -f C:\Windows\Temp\a.ps1"

# On new SYSTEM agent at 10.12.193.4:
rdp_hijack                           # List RDP sessions
rdp_hijack 3                         # Hijack disconnected domain admin session
```

---

## Authors / Autores

- **@wtechsec** — Willian Oliveira / Escola Hack3r
