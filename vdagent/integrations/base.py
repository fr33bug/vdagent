import abc
from pathlib import Path
from typing import List, Optional
from ..core.agent import FunctionInfo


class ReverseEngineeringTool(abc.ABC):
    """Base class for reverse engineering tool integrations."""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self._initialized = False

    @abc.abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the tool connection.

        Returns:
            True if initialization successful, False otherwise.
        """
        pass

    @abc.abstractmethod
    def decompile_functions(self, binary_path: Path, max_functions: int = 100) -> List[FunctionInfo]:
        """
        Decompile functions from a binary file.

        Args:
            binary_path: Path to the binary file.
            max_functions: Maximum number of functions to decompile.

        Returns:
            List of decompiled functions.
        """
        pass

    @abc.abstractmethod
    def get_function_count(self, binary_path: Path) -> int:
        """
        Get total number of functions in the binary.

        Args:
            binary_path: Path to the binary file.

        Returns:
            Number of functions.
        """
        pass

    @abc.abstractmethod
    def get_binary_info(self, binary_path: Path) -> dict:
        """
        Get basic information about the binary.

        Args:
            binary_path: Path to the binary file.

        Returns:
            Dictionary with binary information.
        """
        pass

    @abc.abstractmethod
    def cleanup(self):
        """Clean up resources."""
        pass

    def _validate_binary_path(self, binary_path: Path) -> bool:
        """Validate that the binary file exists and is readable."""
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        if not binary_path.is_file():
            raise ValueError(f"Path is not a file: {binary_path}")

        # Check if file is readable
        try:
            with open(binary_path, 'rb') as f:
                f.read(1)
        except IOError as e:
            raise IOError(f"Cannot read binary file: {e}")

        return True