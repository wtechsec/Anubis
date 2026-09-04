from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class ScmExtArguments(TaskArguments):
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
                description="Usuario local ou dominio",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Senha (net use + sc \\\\target)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="nthash",
                type=ParameterType.String,
                description="NT hash 32 hex — sc/net use nao aceitam; tenta token atual + fallback",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                description="Dominio (vazio/. = local)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Comando a embutir no binPath (se binpath vazio)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="binpath",
                type=ParameterType.String,
                description="binPath completo do servico (sobrescreve command)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Nome do servico",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="display_name",
                type=ParameterType.String,
                description="DisplayName",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="window",
                type=ParameterType.String,
                description="hidden | console (servico Session 0: UI rara)",
                default_value="hidden",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="mode",
                type=ParameterType.String,
                description="create_start_delete | create_start | create_only | start_only | delete_only",
                default_value="create_start_delete",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="service_type",
                type=ParameterType.String,
                description="own | share",
                default_value="own",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="start_type",
                type=ParameterType.String,
                description="demand | auto | disabled",
                default_value="demand",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="delete_after",
                type=ParameterType.Boolean,
                description="stop+delete apos start",
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="force",
                type=ParameterType.Boolean,
                description="stop+delete antes de create",
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="socks_port",
                type=ParameterType.Number,
                description="Ref SOCKS operador",
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
            "binpath": "",
            "service_name": "",
            "display_name": "",
            "window": "hidden",
            "mode": "create_start_delete",
            "service_type": "own",
            "start_type": "demand",
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


class ScmExtCommand(CommandBase):
    cmd = "scm_ext"
    needs_admin = False
    help_cmd = (
        'scm_ext {"target":"...","username":"...","password":"...","command":"...",'
        '"window":"hidden","mode":"create_start_delete"}'
    )
    description = (
        "Remote exec via Service Control Manager (sc \\\\target create/start/delete).\n"
        "Auth: password (net use IPC$ + sc) | nthash (token atual + fallback smbexec/atexec).\n"
        "Perfil diferente de Impacket psexec (nomes/binPath/XML proprios).\n"
        "MITRE T1543.003 / T1021.002"
    )
    version = 1
    author = "@wtechsec"
    argument_class = ScmExtArguments
    attackmapping = ["T1543.003", "T1021.002", "T1569.002"]
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
        auth = "hash" if taskData.args.get_arg("nthash") else "pass"
        response.DisplayParams = "{} @ {} [{}]".format(u, t, auth)
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
