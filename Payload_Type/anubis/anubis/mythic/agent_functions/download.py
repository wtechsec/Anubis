import json

def download(self, task, data=None):
    params = {"path": {"type": "str", "required": True, "description": "Path to download (e.g., C:\\file.txt)"}}
    if data and "path" in data:
        path = data["path"]
    else:
        return "Path parameter is required"
    task_options = {"command": "download", "params": json.dumps({"path": path})}
    response = self.create_tasking(task, task_options)
    if response:
        return f"Started task {task['id']} to download {path}"
    else:
        return "Failed to start task to download"

def on_response(self, response, options=None):
    if "download" in response:
        return f"Downloaded {response['download']['full_path']}"
    return "No output from download task"

command = {
    "command": "download",
    "description": "Downloads a file from the specified path.",
    "author": "YourName",
    "version": "1.0",
    "parameters": [{"name": "path", "type": "str", "required": True, "description": "The full path to download (e.g., C:\\file.txt)"}],
    "dependencies": [],
    "executors": ["default"],
    "file_dependencies": [],
    "supported_os": ["windows"],
    "supported_ui_features": ["file_browser:download"]
}

def help(self):
    return """
    Command: download
    Description: Downloads a file from the specified path.
    Usage: download path=<file_path>
    Example: download path=C:\\file.txt
    """
