    def open_explorer(self, task_id, path="."):
        try:
            if not path or path in (".", None):
                file_path = self.current_directory
            elif os.path.isabs(path):
                file_path = path
            else:
                file_path = os.path.join(self.current_directory, path)

            file_path = os.path.normpath(file_path)

            if not os.path.exists(file_path):
                return "Path not found: {}".format(file_path)

            st          = os.stat(file_path)
            is_file     = os.path.isfile(file_path)
            target_name = os.path.basename(file_path.rstrip(os.sep)) or os.sep

            file_browser = {
                "host":           socket.gethostname(),
                "is_file":        is_file,
                "permissions":    {"octal": oct(st.st_mode)[-3:]},
                "name":           target_name,
                "parent_path":    os.path.abspath(os.path.join(file_path, os.pardir)),
                "success":        True,
                "access_time":    int(st.st_atime * 1000),
                "modify_time":    int(st.st_mtime * 1000),
                "size":           st.st_size,
                "update_deleted": True,
                "files":          []
            }

            if not is_file:
                files = []
                try:
                    with os.scandir(file_path) as entries:
                        for entry in entries:
                            f = {"name": entry.name, "is_file": entry.is_file()}
                            try:
                                es = os.stat(os.path.join(file_path, entry.name))
                                f["permissions"] = {"octal": oct(es.st_mode)[-3:]}
                                f["access_time"] = int(es.st_atime * 1000)
                                f["modify_time"] = int(es.st_mtime * 1000)
                                f["size"]        = es.st_size
                            except OSError:
                                f["permissions"] = {}
                                f["access_time"] = 0
                                f["modify_time"] = 0
                                f["size"]        = 0
                            files.append(f)
                except PermissionError as e:
                    return "open_explorer: permission denied: {}".format(e)
                file_browser["files"] = files

            with self._taskings_lock:
                task = next((t for t in self.taskings if t["task_id"] == task_id), None)
            if task:
                task["file_browser"] = file_browser

            return json.dumps({
                "files":       file_browser["files"],
                "parent_path": file_browser["parent_path"],
                "name":        target_name
            })
        except Exception as e:
            return "open_explorer error: {}".format(e)
