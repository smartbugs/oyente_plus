"""
Mock subprocess operations for testing.

This module provides mock implementations for subprocess operations,
preventing actual external command execution during tests and allowing
controlled behavior for testing error conditions.
"""

from __future__ import annotations

import subprocess
from typing import Any
from typing import Union
from unittest.mock import patch


class MockCompletedProcess:
    """Mock subprocess.CompletedProcess for testing."""

    def __init__(
        self,
        args: list[str],
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
        encoding: Union[str, None] = None,
    ):
        self.args = args
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.encoding = encoding

    def check_returncode(self):
        """Check if the return code indicates success."""
        if self.returncode != 0:
            raise subprocess.CalledProcessError(self.returncode, self.args, self.stdout, self.stderr)


class MockSubprocess:
    """Mock subprocess module for testing."""

    def __init__(self):
        self.commands: dict[str, dict[str, Any]] = {}
        self.default_result = {
            "returncode": 0,
            "stdout": "",
            "stderr": "",
        }
        self.call_history: list[dict[str, Any]] = []

    def add_command(
        self,
        command: Union[str, list[str]],
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
        side_effect: Union[Exception, None] = None,
    ):
        """
        Add a command and its expected result.

        Args:
            command: Command as string or list
            returncode: Return code for the command
            stdout: Standard output
            stderr: Standard error
            side_effect: Exception to raise when command is called
        """
        cmd_key = " ".join(command) if isinstance(command, list) else command
        self.commands[cmd_key] = {
            "returncode": returncode,
            "stdout": stdout,
            "stderr": stderr,
            "side_effect": side_effect,
        }

    def run(
        self,
        args: Union[str, list[str]],
        *,
        capture_output: bool = False,
        text: bool = False,
        shell: bool = False,
        timeout: Union[float, None] = None,
        check: bool = False,
        **kwargs,
    ) -> MockCompletedProcess:
        """Mock subprocess.run implementation."""
        # Record the call
        call_info = {
            "args": args,
            "capture_output": capture_output,
            "text": text,
            "shell": shell,
            "timeout": timeout,
            "check": check,
            "kwargs": kwargs,
        }
        self.call_history.append(call_info)

        # Get command key
        cmd_key = " ".join(args) if isinstance(args, list) else args

        # Look up command result
        if cmd_key in self.commands:
            cmd_info = self.commands[cmd_key]
        else:
            # Try to match partial command
            cmd_info = None
            for registered_cmd, info in self.commands.items():
                if cmd_key.startswith(registered_cmd) or registered_cmd in cmd_key:
                    cmd_info = info
                    break

            if cmd_info is None:
                cmd_info = self.default_result

        # Handle side effects
        if cmd_info.get("side_effect"):
            raise cmd_info["side_effect"]

        # Handle timeout
        if timeout and cmd_info.get("timeout_exceeded"):
            raise subprocess.TimeoutExpired(args, timeout)

        # Create result
        result = MockCompletedProcess(
            args=args,
            returncode=cmd_info["returncode"],
            stdout=cmd_info["stdout"],
            stderr=cmd_info["stderr"],
            encoding="utf-8" if text else None,
        )

        # Check return code if requested
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, args, result.stdout, result.stderr)

        return result

    def check_output(
        self, args: Union[str, list[str]], *, shell: bool = False, timeout: float | None = None, **kwargs
    ) -> bytes:
        """Mock subprocess.check_output implementation."""
        result = self.run(args, capture_output=True, check=True, shell=shell, timeout=timeout, **kwargs)
        return result.stdout.encode() if isinstance(result.stdout, str) else result.stdout

    def check_call(
        self, args: Union[str, list[str]], *, shell: bool = False, timeout: float | None = None, **kwargs
    ) -> int:
        """Mock subprocess.check_call implementation."""
        result = self.run(args, check=True, shell=shell, timeout=timeout, **kwargs)
        return result.returncode

    def reset(self):
        """Reset the mock subprocess state."""
        self.commands.clear()
        self.call_history.clear()

    def assert_called_with(self, args: Union[str, list[str]]):
        """Assert that subprocess was called with specific arguments."""
        expected = args if isinstance(args, list) else [args]
        for call in self.call_history:
            if call["args"] == expected:
                return True
        raise AssertionError(f"subprocess.run not called with {expected}")

    def assert_not_called(self):
        """Assert that no subprocess calls were made."""
        if self.call_history:
            raise AssertionError(f"Expected no calls, but got {len(self.call_history)} calls")


# Common command mocks for Oyente testing
class OyenteCommandMocks:
    """Pre-configured mocks for common Oyente commands."""

    @staticmethod
    def mock_evm_version() -> dict[str, Any]:
        """Mock evm --version command."""
        return {
            "returncode": 0,
            "stdout": "evm version 1.10.16-stable",
            "stderr": "",
        }

    @staticmethod
    def mock_solc_version() -> dict[str, Any]:
        """Mock solc --version command."""
        return {
            "returncode": 0,
            "stdout": "solc, the solidity compiler commandline interface\nVersion: 0.8.19+commit.7dd6d404.Linux.g++",
            "stderr": "",
        }

    @staticmethod
    def mock_solc_compile_success(bytecode: str = "608060405234801561001057600080fd5b50") -> dict[str, Any]:
        """Mock successful solc compilation."""
        return {
            "returncode": 0,
            "stdout": f'{{"contracts": {{"Test.sol:Test": {{"bin": "{bytecode}"}}}}}}',
            "stderr": "",
        }

    @staticmethod
    def mock_solc_compile_error() -> dict[str, Any]:
        """Mock solc compilation error."""
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": "Error: Source file not found",
        }

    @staticmethod
    def mock_mythril_analysis() -> dict[str, Any]:
        """Mock mythril analysis output."""
        return {
            "returncode": 0,
            "stdout": '{"success": true, "issues": []}',
            "stderr": "",
        }

    @staticmethod
    def mock_solc_malformed_json() -> dict[str, Any]:
        """Mock solc compilation with malformed JSON output."""
        return {
            "returncode": 0,
            "stdout": '{"contracts": {"Test.sol:Test": {"bin": "60806040',  # Truncated/malformed JSON
            "stderr": "",
        }

    @staticmethod
    def mock_compilation_timeout() -> dict[str, Any]:
        """Mock compilation that times out."""
        return {
            "returncode": 124,  # Timeout exit code
            "stdout": "",
            "stderr": "Compilation timed out",
            "timeout_exceeded": True,
        }

    @staticmethod
    def mock_permission_denied() -> dict[str, Any]:
        """Mock permission denied error."""
        return {
            "returncode": 126,
            "stdout": "",
            "stderr": "Permission denied",
        }


def create_mock_subprocess(commands: Union[dict[str, dict[str, Any]], None] = None) -> MockSubprocess:
    """Create a mock subprocess with pre-configured commands."""
    mock = MockSubprocess()

    # Add default commands
    default_commands = {
        "evm --version": OyenteCommandMocks.mock_evm_version(),
        "solc --version": OyenteCommandMocks.mock_solc_version(),
    }

    if commands:
        default_commands.update(commands)

    for cmd, result in default_commands.items():
        mock.add_command(cmd, **result)

    return mock


def patch_subprocess(commands: Union[dict[str, dict[str, Any]], None] = None):
    """
    Decorator to patch subprocess with mock implementation.

    Usage:
        @patch_subprocess({
            'evm --version': {'returncode': 0, 'stdout': 'evm version 1.10.16'}
        })
        def test_something(mock_subprocess):
            # Test code here
            pass
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            mock = create_mock_subprocess(commands)

            with (
                patch("subprocess.run", side_effect=mock.run),
                patch("subprocess.check_output", side_effect=mock.check_output),
                patch("subprocess.check_call", side_effect=mock.check_call),
            ):
                # Add mock to function arguments
                return func(mock, *args, **kwargs)

        return wrapper

    return decorator


# Context manager for subprocess mocking
class MockSubprocessContext:
    """Context manager for subprocess mocking."""

    def __init__(self, commands: Union[dict[str, dict[str, Any]], None] = None):
        self.mock = create_mock_subprocess(commands)
        self.patches = []

    def __enter__(self):
        # Create patches
        self.patches = [
            patch("subprocess.run", side_effect=self.mock.run),
            patch("subprocess.check_output", side_effect=self.mock.check_output),
            patch("subprocess.check_call", side_effect=self.mock.check_call),
        ]

        # Start all patches
        for p in self.patches:
            p.__enter__()

        return self.mock

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Stop all patches
        for p in self.patches:
            p.__exit__(exc_type, exc_val, exc_tb)
