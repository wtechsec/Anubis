import json

# Função principal do comando open_explorer
def open_explorer(self, task, data=None):
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
        "params": json.dumps({"path": path}) if path else json.dumps({})  # Envia caminho se fornecido
    }

    # Envia a tarefa ao agente e retorna a resposta
    response = self.create_tasking(task, task_options)
    if response:
        return f"Started task {task['id']} to open Explorer{' at ' + path if path else ' in current directory'}"
    else:
        return "Failed to start task to open Explorer"

# Função de processamento da resposta (opcional, dependendo da implementação do Mythic)
def on_response(self, response, options=None):
    # Processa a resposta do agente (ex.: "Opened Explorer at C:\Windows")
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
    "dependencies": [],  # Não há dependências adicionais
    "executors": ["default"],  # Compatível com o executor padrão do agente
    "file_dependencies": [],  # Nenhum arquivo adicional necessário
    "supported_os": ["windows"]  # Só funciona em Windows
}

# Função de ajuda (opcional, para documentação no Mythic)
def help(self):
    return """
    Command: open_explorer
    Description: Opens Windows Explorer in the specified directory or the agent's current directory.
    Usage: open_explorer [path=<directory_path>]
    Example: open_explorer path=C:\\Windows
             open_explorer (opens current directory)
    """
