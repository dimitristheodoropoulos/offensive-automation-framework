from abc import ABC, abstractmethod
from typing import Type
from core.schemas import ToolExecutionResult

class BaseToolAdapter(ABC):
    """Abstract Base Class for all OSAF execution tools and proprietary adapters."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def execute(self, target: str, **kwargs) -> ToolExecutionResult:
        """Executes the tool logic and returns standardized Pydantic models."""
        pass


class ToolRegistry:
    """Registry pattern to dynamically load and manage tool adapters without hardcoding."""
    
    def __init__(self):
        self._adapters: dict[str, BaseToolAdapter] = {}

    def register(self, adapter: BaseToolAdapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> BaseToolAdapter:
        if name not in self._adapters:
            raise KeyError(f"Adapter '{name}' is not registered in OSAF.")
        return self._adapters[name]

    def list_available(self) -> list[str]:
        return list(self._adapters.keys())

# Global registry instance
global_registry = ToolRegistry()