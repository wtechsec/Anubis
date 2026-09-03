from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class TaskXmlExtArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="target",
                type=ParameterType.String,
                description="Host/IP remoto",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Usuario (local ou dominio)",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Senha (schtasks remoto nativo)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="nthash",
                type=ParameterType.String,
                description="NT hash 32 hex (LM:NT ok). schtasks nativo nao usa hash; tenta token atual + fallback atexec",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                description="Dominio (vazio ou . = conta local)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Comando completo no alvo",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="task_name",
                type=ParameterType.String,
                description="Nome da scheduled task",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="window",
                type=ParameterType.String,
                description="hidden | minimized | console",
                default_value="hidden",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="shell",
                type=ParameterType.String,
                description="cmd | powershell | raw",
                default_value="cmd",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="run_level",
                type=ParameterType.String,
                description="highest | limited",
                default_value="highest",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="mode",
                type=ParameterType.String,
                description="create_run_delete | create_run | create_only | run_only",
                default_value="create_run_delete",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="working_dir",
                type=ParameterType.String,
                description="WorkingDirectory da task",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="delete_after",
                type=ParameterType.Boolean,
                description="Remover task apos run",
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="force",
                type=ParameterType.Boolean,
                description="Overwrite task (/F)",
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="socks_port",
                type=ParameterType.Number,
                description="Referencia SOCKS (docs operador)",
                default_value=7005,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        defaults = {
            "target": "",
            "username": "",
            "password": "",
            "nthash": "",
            "domain": "",
            "command": "",
            "task_name": "",
            "window": "hidden",
            "shell": "cmd",
            "run_level": "highest",
            "mode": "create_run_delete",
            "working_dir": "",
            "delete_after": True,
            "force": True,
            "socks_port": 7005,
        }
        if self.command_line and self.command_line.strip().startswith("{"):
            d = json.loads(self.command_line)
            for k, v in defaults.items():
                val = d.get(k, v)
                if isinstance(v, bool):
                    self.add_arg(k, val, ParameterType.Boolean)
                elif isinstance(v, int):
                    self.add_arg(k, val, ParameterType.Number)
                else:
                    self.add_arg(k, val if val is not None else v)
        else:
            # posicional minimo: target username command
            parts = (self.command_line or "").strip().split(" ", 2)
            self.add_arg("target", parts[0] if len(parts) > 0 else "")
            self.add_arg("username", parts[1] if len(parts) > 1 else "")
            self.add_arg("command", parts[2] if len(parts) > 2 else "")
            for k, v in defaults.items():
                if k in ("target", "username", "command"):
                    continue
                if isinstance(v, bool):
                    self.add_arg(k, v, ParameterType.Boolean)
                elif isinstance(v, int):
                    self.add_arg(k, v, ParameterType.Number)
                else:
                    self.add_arg(k, v)


class TaskXmlExtCommand(CommandBase):
    cmd = "task_xml_ext"
    needs_admin = False
    help_cmd = 'task_xml_ext {"target":"...","username":"...","command":"...","password":"...","nthash":"...","window":"hidden|console","shell":"cmd|powershell|raw"}'
    description = (
        "Scheduled Task XML custom no host remoto (lateral exec).\n"
        "Auth: password (schtasks /S /U /P) e/ou nthash (tentativa token atual + fallback atexec).\n"
        "window: hidden|minimized|console | shell: cmd|powershell|raw\n"
        "mode: create_run_delete|create_run|create_only|run_only\n"
        "Nao usa Evil-WinRM interativo; perfil diferente de Impacket atexec (XML/nome proprios)."
    )
    version = 1
    author = "@wtechsec"
    attackmapping = ["T1053.005", "T1021", "T1078"]
    argument_class = TaskXmlExtArguments
    attributes = CommandAttributes(
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
        t = taskData.args.get_arg("target") or "?"
        u = taskData.args.get_arg("username") or "?"
        w = taskData.args.get_arg("window") or "hidden"
        auth = "hash" if taskData.args.get_arg("nthash") else "pass"
        response.DisplayParams = "{} @ {} [{}|{}]".format(u, t, w, auth)
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        raw = ""
        if response is not None:
            raw = (
                response.decode()
                if isinstance(response, (bytes, bytearray))
                else str(response)
            )
        if raw:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID, Response=raw.encode()
                )
            )
        return resp
