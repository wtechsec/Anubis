# Anubis
Mythic agent

No silêncio da sessão remota, wtechsec carregou sua criação: um script PowerShell artesanal, que clonava o processo LSASS usando a obscura syscall NtCreateProcessEx. O plano era simples e engenhoso:
**Clonar o LSASS para um novo processo fora da vigilância direta do CrowdStrike.**
**Realizar o dump nesse clone com MiniDumpWriteDump, escapando dos ganchos e alertas comportamentais.**

O script rodou. Nenhum alerta. Nenhum bloqueio. Apenas um dump limpo, salvo em **C:\Users\Public\forked_lsass.dmp.**

wtechsec sorriu. Ele sabia o que tinha em mãos. Um bypass real, discreto e funcional. O dump foi exfiltrado com calma. Ao analisá-lo localmente com o Mimikatz, ele recuperou as credenciais de domínio de um administrador sênior.
O domínio era dele.

**E o CrowdStrike? Silencioso como a noite.**

![Banner do Projeto](Assets/Banner.png)

# Requesitos de Ataque
- Credencial de local admin ou com permissionamento equivalente.
- Usar Winrm - EvilWinrm, Powershell remote, ou reverse shell, dependendo do nivel de comprometimento do alvo e orquestração.
- Alvo Windos,10,11, até versões server.
- CrowdStrike ativo no alvo ou outro EDR monitorando processo e bloqueando dump manual.
- Máquina atacante com pypykats, evil-winrm, netexec e editor de texto para editar o script caso precise.
