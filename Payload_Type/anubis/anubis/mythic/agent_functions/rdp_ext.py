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
                parameter_group_info=[ParameterGroupInfo(required=True)],
                description="IP ou hostname do host com RDP (deve ser alcançável pelo agente).",
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Porta RDP no alvo.",
                default_value=3389,
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Usuário RDP.",
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
                description=(
                    "Porta SOCKS5 a abrir no servidor Mythic. "
                    "Padrão: 7005. Se já estiver rodando na mesma porta, o aviso é seguro."
                ),
                default_value=7005,
            ),
        ]

    async def parse_arguments(self):
        if self.command_line:
            if self.command_line.strip().startswith('{'):
                d = json.loads(self.command_line)
                self.add_arg("target",     d.get("target",     ""))
                self.add_arg("port",       d.get("port",       3389))
                self.add_arg("username",   d.get("username",   ""))
                self.add_arg("password",   d.get("password",   ""))
                self.add_arg("domain",     d.get("domain",     ""))
                self.add_arg("socks_port", d.get("socks_port", 7005))
            else:
                # Posicional: <target> [user] [password] [domain] [socks_port]
                parts = self.command_line.strip().split()
                self.add_arg("target",     parts[0] if len(parts) > 0 else "")
                self.add_arg("username",   parts[1] if len(parts) > 1 else "")
                self.add_arg("password",   parts[2] if len(parts) > 2 else "")
                self.add_arg("domain",     parts[3] if len(parts) > 3 else "")
                self.add_arg("port",       3389)
                self.add_arg("socks_port", 7005)
        else:
            for k, v in [("target",""),("port",3389),("username",""),
                         ("password",""),("domain",""),("socks_port",7005)]:
                self.add_arg(k, v)


class RdpExtCommand(CommandBase):
    cmd         = "rdp_ext"
    needs_admin = False
    help_cmd    = "rdp_ext <target> [username] [password] [domain]"
    description = (
        "Acesso RDP via tunnel SOCKS5 do Anubis — sem Python no host operador.\n\n"
        "Fluxo:\n"
        "  1. Mythic abre porta SOCKS5 no servidor Mythic (padrão: 7005)\n"
        "  2. Agente faz probe TCP em target:3389 para confirmar alcançabilidade\n"
        "  3. Retorna comandos prontos: rdesktop, xfreerdp via proxychains,\n"
        "     e xfreerdp com suporte nativo a SOCKS5 (/proxy:socks5://...)\n\n"
        "O xfreerdp nativo é o método preferido (sem dependência de proxychains):\n"
        "  xfreerdp /proxy:socks5://127.0.0.1:7005 /v:<target> /u:<user> ...\n\n"
        "Pré-requisito no host operador (Kali):\n"
        "  apt install freerdp2-x11   # xfreerdp\n"
        "  apt install rdesktop        # alternativa\n"
        "  apt install proxychains-ng  # se preferir proxychains"
    )
    version               = 1
    author                = "@wtechsec"
    attackmapping         = ["T1021.001", "T1090"]
    supported_ui_features = []
    argument_class        = RdpExtArguments
    attributes            = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[
            SupportedOS.Windows,
            SupportedOS.Linux,
            SupportedOS.MacOS,
        ],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        target     = taskData.args.get_arg("target")     or ""
        username   = taskData.args.get_arg("username")   or ""
        domain     = taskData.args.get_arg("domain")     or ""
        port       = taskData.args.get_arg("port")       or 3389
        socks_port = taskData.args.get_arg("socks_port") or 7005

        # ── inicia SOCKS5 no servidor Mythic via RPC ──────────────────────────
        socks_resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
            TaskID=taskData.Task.ID,
            PortType="socks",
            LocalPort=socks_port,
        ))
        if not socks_resp.Success:
            # Pode falhar se já estiver rodando — é seguro continuar
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=taskData.Task.ID,
                Response=(
                    "[*] SOCKS5 aviso (pode já estar ativo): {}\n".format(socks_resp.Error)
                ).encode()
            ))

        # ── display_params ────────────────────────────────────────────────────
        user_str = ""
        if domain and username:
            user_str = " {}\\{}".format(domain, username)
        elif username:
            user_str = " {}".format(username)

        response.DisplayParams = "target={}:{}{} socks={}".format(
            target, port, user_str, socks_port)
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
