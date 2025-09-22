from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys

class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file_id",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(
                    required=True
                )],
                description="File ID from Mythic",
            ),
            CommandParameter(
                name="remote_path",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(
                    required=True
                )],
                description="Destination path on the target (e.g., C:\\destination\\file.txt)",
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                temp_json = json.loads(self.command_line)
                if "file_id" in temp_json and "remote_path" in temp_json:
                    self.add_arg("file_id", temp_json["file_id"])
                    self.add_arg("remote_path", temp_json["remote_path"])
                else:
                    raise Exception("Missing file_id or remote_path in upload task")
            else:
                raise Exception("Invalid format for upload task")
        else:
            raise Exception("file_id and remote_path are required for upload command")

class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload file_id=<file_id> remote_path=<destination>"
    description = "Upload a file to the target system"
    version = 1
    author = "@YourName"
    attackmapping = ["T1105"]
    supported_ui_features = ["file_browser:upload"]
    is_file_browse = True
    argument_class = UploadArguments
    browser_script = BrowserScript(script_name="upload", author="@its_a_feature_", for_new_ui=True)
    attributes = CommandAttributes(
        supported_python_versions=["Python 2.7", "Python 3.8"],
        supported_os=[SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f"Upload to {task.args.get_arg('remote_path')}"
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
