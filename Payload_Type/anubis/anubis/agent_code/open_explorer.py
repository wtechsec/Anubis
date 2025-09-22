import json

def open_explorer(self, task, data=None):
    """
    Registra e envia uma tarefa para abrir o Explorador de Arquivos (Windows Explorer) no diretório especificado
    ou no diretório atual do agente.
    
    Args:
        task: Objeto de tarefa do Mythic.
        data (dict, optional): Dados adicionais da tarefa, incluindo parâmetros como 'path'.
    
    Returns:
        str: Mensagem de confirmação ou erro.
    """
    # Parâmetros esperados
    params = {
        "path": {"type": "str", "default": None, "description": "Optional path to open in Explorer (e.g., 'C:\\Windows')"}
    }

    # Verifica se os parâmetros estão corretos
    if data and "path" in data:
        path = data["path"]
    else:
        path = None  # Usa o diretório atual do agente por padrão

    # Monta a tarefa para enviar ao agente
    task_options = {
        "command": "open_explorer",
        "params": json.dumps({"path": path}) if path else json.dumps({})
    }

    # Envia a tarefa ao agente e retorna a resposta
    response = self.create_tasking(task, task_options)
    if response:
        return f"Started task {task['id']} to open Explorer{' at ' + path if path else ' in current directory'}"
    else:
        return "Failed to start task to open Explorer"

def on_response(self, response, options=None):
    """
    Processa a resposta retornada pelo agente após a execução do comando.
    
    Args:
        response: Resposta do agente.
        options: Opções adicionais (não utilizadas aqui).
    
    Returns:
        str: Mensagem formatada com o resultado.
    """
    if "user_output" in response:
        return f"Explorer opened: {response['user_output']}"
    return "No output from Explorer task"

# Registro do comando (meta informações para o Mythic)
command = {
    "command": "open_explorer",
    "description": "Opens Windows Explorer in the specified directory or the agent's current directory.",
    "author": "YourName",
    "version": "1.0",
    "parameters": [
        {
            "name": "path",
            "type": "str",
            "required": False,
            "description": "The directory path to open in Explorer (e.g., 'C:\\Windows'). If omitted, opens the agent's current directory."
        }
    ],
    "dependencies": [],
    "executors": ["default"],
    "file_dependencies": [],
    "supported_os": ["windows"],
    "supported_ui_features": []  # Não se integra ao file_browser por padrão; adicione ["file_browser:open"] se estender a UI
}

def help(self):
    """
    Fornece ajuda sobre o uso do comando.
    
    Returns:
        str: Documentação do comando.
    """
    return """
    Command: open_explorer
    Description: Opens Windows Explorer in the specified directory or the agent's current directory.
    Usage: open_explorer [path=<directory_path>]
    Example: open_explorer path=C:\\Windows
             open_explorer (opens current directory)
    """
