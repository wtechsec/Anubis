   def ls(self, task_id, **params):
    try:
        # Extrair o caminho do dicionário de parâmetros, usando None como padrão se não fornecido
        path = params.get('path')
        host = socket.gethostname()
        if path:
            full_path = os.path.abspath(path.replace('/', '\\')) if not path.startswith('\\') else path.replace('/', '\\')
        else:
            full_path = self.current_directory

        if not os.path.exists(full_path):
            return json.dumps({
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": f"Path {full_path} does not exist",
                    "file_browser": {
                        "success": False,
                        "host": host,
                        "parent_path": os.path.dirname(full_path) or "",
                        "name": os.path.basename(full_path)
                    }
                }]
            })

        entries = []
        for item in os.listdir(full_path):
            item_path = os.path.join(full_path, item)
            stat = os.stat(item_path)
            is_file = os.path.isfile(item_path)
            permissions = {
                "read": os.access(item_path, os.R_OK),
                "write": os.access(item_path, os.W_OK),
                "execute": os.access(item_path, os.X_OK)
            }
            entry = {
                "is_file": is_file,
                "permissions": permissions,
                "name": item,
                "access_time": int(stat.st_atime * 1000),
                "modify_time": int(stat.st_mtime * 1000),
                "size": stat.st_size if is_file else 0
            }
            entries.append(entry)

        response = {
            "action": "post_response",
            "responses": [{
                "task_id": task_id,
                "file_browser": {
                    "host": host,
                    "is_file": False,
                    "permissions": {"read": True, "write": True},
                    "name": os.path.basename(full_path) or full_path,
                    "parent_path": os.path.dirname(full_path) or "",
                    "success": True,
                    "access_time": int(os.stat(full_path).st_atime * 1000),
                    "modify_time": int(os.stat(full_path).st_mtime * 1000),
                    "size": 0,
                    "update_deleted": True,
                    "files": entries
                }
            }]
        }
        return json.dumps(response)
    except Exception as e:
        return json.dumps({
            "action": "post_response",
            "responses": [{
                "task_id": task_id,
                "user_output": f"Failed to list directory: {str(e)}",
                "file_browser": {
                    "success": False,
                    "host": host,
                    "parent_path": os.path.dirname(full_path) or "",
                    "name": os.path.basename(full_path)
                }
            }]
        })
