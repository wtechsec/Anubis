import json

def rm(self, task, data=None):
    params = {"path": {"type": "str", "required": True, "description": "Path to remove (e.g., C:\\file.txt)"}}
    if data and "path" in data:
        path = data["path"]
    else:
        return "Path parameter is required"
    task_options = {"command": "rm", "params": json.dumps({"path": path})}
    response = self.create_tasking(task, task_options)
    if response:
        return f"Started task {task['id']} to remove {path}"
    else:
        return "Failed to start task to remove"

def on_response(self, response, options=None):
    if "removed_files" in response:
        return f"Removed {response['removed_files'][0]['path']}"
    return "No output from rm task"

command = {
    "command": "rm",
    "description": "Removes a file or directory.",
    "author": "YourName",
    "version": "1.0",
    "parameters": [{"name": "path", "type": "str", "required": True, "description": "The full path to remove (e.g., C:\\file.txt)"}],
    "dependencies": [],
    "executors": ["default"],
    "file_dependencies": [],
    "supported_os": ["windows"],
    "supported_ui_features": ["file_browser:remove"]
}

def help(self):
    return """
    Command: rm
    Description: Removes a file or directory.
    Usage: rm path=<file_or_directory_path>
    Example: rm path=C:\\file.txt
    """
