from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class Screenshot2Command(CommandBase):
    cmd = "screenshot2"
    needs_admin = False
    help_cmd = "screenshot2"
    description = "Captura a tela atual e retorna em base64"
    version = 1
    author = "@seuuser"
    argument_class = CommandArguments
    attributes = CommandAttributes(
        supported_python_versions=["Python 3.8"],   # ou 2.7 se for compatível
        supported_os=[SupportedOS.Windows]         # ajuste conforme EyesC
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        resp = await MythicRPC().execute("create_output", task_id=task.id, output="Executando screenshot2...")
        return task

    async def process_response(self, response: AgentResponse):
        pass
