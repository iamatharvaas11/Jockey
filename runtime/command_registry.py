from typing import Callable, Any

class CommandRegistry:
    def __init__(self):
        self._commands: dict[str, Callable] = {}

    def register(self, command_name: str, handler_func: Callable) -> None:
        """Register a new command handler."""
        self._commands[command_name.upper()] = handler_func

    def execute(self, command_name: str, **kwargs) -> Any:
        """Execute a registered command."""
        cmd = command_name.upper()
        if cmd not in self._commands:
            raise ValueError(f"Command not registered: {command_name}")
        return self._commands[cmd](**kwargs)

    def list_commands(self) -> list[str]:
        """List all registered commands."""
        return list(self._commands.keys())

    def register_adapter(self, adapter) -> None:
        """Auto-register all forensic commands from an adapter."""
        self.register('SCAN_PROCESSES', adapter.scan_processes)
        self.register('SCAN_FILES', adapter.scan_files)
        self.register('SCAN_NETWORK', adapter.scan_network)
        self.register('SCAN_EVENTLOGS', adapter.scan_eventlogs)
        self.register('SCAN_REGISTRY', adapter.scan_registry)
