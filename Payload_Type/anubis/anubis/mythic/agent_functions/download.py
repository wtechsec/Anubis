from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys

class DownloadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(
                    required=True
                )],
                description="Path of file to download",
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                temp_json = json.loads(self.command_line)
                if "host" in temp_json:
                    self.add_arg("path", temp_json["path"] + "\\" + temp_json["file"])  # Windows uses \
                else:
                    self.add_arg("path", temp_json["path"])
            else:
                self.add_arg("path", self.command_line)
        else:
            raise Exception("Path is required for download command")

class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download [/path/to/file]"
    description = "Download a file from the target system"
    version = 1
    author = "@YourName"
    attackmapping = ["T1105"]
    supported_ui_features = ["file_browser:download"]
    is_file_browse = True
    argument_class = DownloadArguments
    browser_script = BrowserScript(script_name="download", author="@its_a_feature_", for_new_ui=True)
    attributes = CommandAttributes(
        supported_python_versions=["Python 2.7", "Python 3.8"],
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("path")
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
