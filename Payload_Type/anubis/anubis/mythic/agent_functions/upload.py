import json

def upload(self, task, data=None):
    params = {
        "file_id": {"type": "str", "required": True, "description": "File ID from Mythic"},
        "remote_path": {"type": "str", "required": True, "description": "Destination path (e.g., C:\\destination\\file.txt)"}
    }
    if data and "file_id" in data and "remote_path" in data:
        file_id = data["file_id"]
        remote_path = data["remote_path"]
    else:
        return "file_id and remote_path parameters are required"
    task_options = {"command": "upload", "params": json.dumps({"file_id": file_id, "remote_path": remote_path})}
    response = self.create_tasking(task, task_options)
    if response:
        return f"Started task {task['id']} to upload to {remote_path}"
    else:
        return "Failed to start task to upload"

def on_response(self, response, options=None):
    if "user_output" in response:
        return response["user_output"]
    return "No output from upload task"

command = {
    "command": "upload",
    "description": "Uploads a file to the specified path.",
    "author": "YourName",
    "version": "1.0",
    "parameters": [
        {"name": "file_id", "type": "str", "required": True, "description": "The file ID from Mythic"},
        {"name": "remote_path", "type": "str", "required": True, "description": "The destination path (e.g., C:\\destination\\file.txt)"}
    ],
    "dependencies": [],
    "executors": ["default"],
    "file_dependencies": [],
    "supported_os": ["windows"],
    "supported_ui_features": ["file_browser:upload"]
}

def help(self):
    return """
    Command: upload
    Description: Uploads a file to the specified path.
    Usage: upload file_id=<file_id> remote_path=<destination_path>
    Example: upload file_id=123 remote_path=C:\\destination\\file.txt
    """
