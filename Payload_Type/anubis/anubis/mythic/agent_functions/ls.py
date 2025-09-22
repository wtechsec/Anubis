import json

def ls(self, task, data=None):
    params = {"path": {"type": "str", "default": None, "description": "Path to list (e.g., C:\\Windows)"}}
    if data and "path" in data:
        path = data["path"]
    else:
        path = None
    task_options = {"command": "ls", "params": json.dumps({"path": path}) if path else json.dumps({})}
    response = self.create_tasking(task, task_options)
    if response:
        return f"Started task {task['id']} to list {path or 'current directory'}"
    else:
        return "Failed to start task to list"

def on_response(self, response, options=None):
    if "file_browser" in response:
        return f"Listed {response.get('file_browser', {}).get('name', 'directory')}"
    return "No output from ls task"

command = {
    "command": "ls",
    "description": "Lists files and directories in the specified path.",
    "author": "YourName",
    "version": "1.0",
    "parameters": [{"name": "path", "type": "str", "required": False, "description": "The directory path to list (e.g., C:\\Windows). If omitted, lists the current directory."}],
    "dependencies": [],
    "executors": ["default"],
    "file_dependencies": [],
    "supported_os": ["windows"],
    "supported_ui_features": ["file_browser:list"]
}

def help(self):
    return """
    Command: ls
    Description: Lists files and directories in the specified path.
    Usage: ls [path=<directory_path>]
    Example: ls path=C:\\Windows
             ls (lists current directory)
    """
