    def cd(self, task_id, path=""):
        try:
            if path == "..":
                self.current_directory = os.path.dirname(self.current_directory)
            else:
                new_path = path if os.path.isabs(path) else os.path.join(self.current_directory, path)
                self.current_directory = os.path.abspath(new_path)
            return "Directory changed to: {}".format(self.current_directory)
        except Exception as e:
            return "cd error: {}".format(e)
