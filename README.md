<p align="center">
  <img src="https://4c22726d.git-6vm.pages.dev/2sxCepI01.svg" alt="Anubis Logo" width="300">
</p>

<h1 align="center">Anubis C2 Agent</h1>
<p align="center">Python C2 agent for the Mythic framework | Red Team & Adversary Simulation</p>

---

## Overview / Visão Geral

**EN:** Anubis is a cross-platform Python C2 agent for the [Mythic](https://github.com/its-a-feature/Mythic) framework, built for Red Team operations and adversary simulation. Supports Python 3.8 on Windows, Linux, and macOS, with a focus on Windows offensive capabilities.

**PT-BR:** Anubis é um agente C2 Python para o framework [Mythic](https://github.com/its-a-feature/Mythic), desenvolvido para operações de Red Team e simulação de adversários. Suporta Python 3.8 em Windows, Linux e macOS, com foco em capacidades ofensivas para Windows.

Na mitologia egípcia, Anúbis era o guardião das passagens entre mundos. Aqui assume o papel de intermediário furtivo entre operador e alvo — operando na fronteira entre segurança e intrusão controlada.

---

## Key Features / Funcionalidades Principais

| Feature | EN | PT-BR |
|---|---|---|
| Encrypted comms | AES-256-CBC + HMAC-SHA256 (pure Python stdlib) | AES-256-CBC + HMAC-SHA256 sem dependências externas |
| Dynamic loading | Load/unload commands at runtime via C2 | Carrega/descarrega comandos em runtime via C2 |
| SOCKS5 proxy | Reverse tunnel through C2 channel | Túnel reverso pelo canal C2 |
| File transfer | Chunked upload/download, stoppable | Upload/download em chunks, interrompível |
| LSASS dump | NtCreateProcessEx fork evasion (EDR bypass) | Evasão via fork NtCreateProcessEx (bypass EDR) |
| Shellcode injection | VirtualAllocEx + CRT via process browser | Injeção via process browser do Mythic |
| Screenshot | Pure ctypes GDI32/User32 — no pywin32 or Pillow | ctypes puro — sem pywin32 ou Pillow |
| Obfuscation | XOR + Base64 at build time | XOR + Base64 no build |
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
| `output` | py / base64 | Output format | Formato de saída |
| `use_non_default_cryptography_lib` | No / Yes | Use `cryptography` pip library | Usar biblioteca `cryptography` |
| `obfuscate_script` | Yes / No | XOR + Base64 obfuscation | Obfuscação XOR + Base64 |
| `https_check` | Yes / No | Verify TLS certificate | Verificar certificado TLS |

---

## OPSEC Notes / Notas de OPSEC

| Topic | EN | PT-BR |
|---|---|---|
| Beacon | Use jitter: `sleep 60 20` (±20%) | Use jitter: `sleep 60 20` (±20%) |
| Payload on disk | Enable obfuscation at build; use `base64` format | Ative obfuscação no build; use formato `base64` |
| EXE blocked | Deliver as `.py`/`.pyw` or Python Embeddable | Entregue como `.py`/`.pyw` ou Python Embeddable |
| LSASS dump | Bypasses EDR hook on LSASS PID; `OpenProcess` still logged by Sysmon (Event ID 10) | Bypassa hook EDR por PID; `OpenProcess` ainda logado (Sysmon EID 10) |
| Credential Guard | Completely blocks `dump_lsass` — verify before attempting | Bloqueia completamente `dump_lsass` — verifique antes |
| Injection | RWX alloc flagged by most EDR; use reflective loader for evasion | Alocação RWX flagada pela maioria dos EDR |

---

## Authors / Autores

- **@wtechsec** — Willian Oliveira / Escola Hack3r
