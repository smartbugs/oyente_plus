"""
Mock filesystem operations for testing.

This module provides mock implementations for filesystem operations,
allowing tests to run without actual file I/O and in isolation.
"""

from __future__ import annotations

import os
import tempfile
from io import StringIO
from pathlib import Path
from typing import Union
from unittest.mock import Mock
from unittest.mock import mock_open
from unittest.mock import patch


class MockFile:
    """Mock file object for testing file operations."""

    def __init__(self, content: str = "", mode: str = "r"):
        self.content = content
        self.mode = mode
        self.closed = False
        self.position = 0
        self._buffer = StringIO(content)

    def read(self, size: int = -1) -> str:
        """Read from the file."""
        if self.closed:
            raise ValueError("I/O operation on closed file")
        return self._buffer.read(size)

    def write(self, data: str) -> int:
        """Write to the file."""
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if "w" not in self.mode and "a" not in self.mode:
            raise OSError("File not open for writing")
        return self._buffer.write(data)

    def close(self):
        """Close the file."""
        self.closed = True
        self._buffer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class MockFilesystem:
    """Mock filesystem for testing."""

    def __init__(self):
        self.files: dict[str, str] = {}
        self.directories: list[str] = []

    def add_file(self, path: Union[str, Path], content: str = ""):
        """Add a file to the mock filesystem."""
        path = str(path)
        self.files[path] = content
        # Ensure parent directories exist
        parent = os.path.dirname(path)
        while parent and parent != "/":
            if parent not in self.directories:
                self.directories.append(parent)
            parent = os.path.dirname(parent)

    def add_directory(self, path: Union[str, Path]):
        """Add a directory to the mock filesystem."""
        path = str(path)
        if path not in self.directories:
            self.directories.append(path)

    def exists(self, path: Union[str, Path]) -> bool:
        """Check if path exists."""
        path = str(path)
        return path in self.files or path in self.directories

    def is_file(self, path: Union[str, Path]) -> bool:
        """Check if path is a file."""
        return str(path) in self.files

    def is_dir(self, path: Union[str, Path]) -> bool:
        """Check if path is a directory."""
        return str(path) in self.directories

    def read_file(self, path: Union[str, Path]) -> str:
        """Read file content."""
        path = str(path)
        if path not in self.files:
            raise FileNotFoundError(f"No such file: {path}")
        return self.files[path]

    def write_file(self, path: Union[str, Path], content: str):
        """Write file content."""
        self.add_file(path, content)

    def list_dir(self, path: Union[str, Path]) -> list[str]:
        """List directory contents."""
        path = str(path).rstrip("/")
        if path not in self.directories:
            raise FileNotFoundError(f"No such directory: {path}")

        contents = []
        # Add files in directory
        for file_path in self.files:
            dir_name = os.path.dirname(file_path)
            if dir_name == path:
                contents.append(os.path.basename(file_path))

        # Add subdirectories
        for dir_path in self.directories:
            parent = os.path.dirname(dir_path.rstrip("/"))
            if parent == path and dir_path != path:
                contents.append(os.path.basename(dir_path))

        return sorted(set(contents))


def create_mock_filesystem_patches(filesystem: MockFilesystem):
    """
    Create patches for common filesystem operations.

    Returns a dictionary of patches that can be used with patch.multiple()
    """
    patches = {}

    # Path.exists
    def mock_exists(self):
        return filesystem.exists(str(self))

    patches["pathlib.Path.exists"] = Mock(side_effect=mock_exists)

    # Path.is_file
    def mock_is_file(self):
        return filesystem.is_file(str(self))

    patches["pathlib.Path.is_file"] = Mock(side_effect=mock_is_file)

    # Path.is_dir
    def mock_is_dir(self):
        return filesystem.is_dir(str(self))

    patches["pathlib.Path.is_dir"] = Mock(side_effect=mock_is_dir)

    # os.path.exists
    patches["os.path.exists"] = Mock(side_effect=filesystem.exists)

    # os.path.isfile
    patches["os.path.isfile"] = Mock(side_effect=filesystem.is_file)

    # os.path.isdir
    patches["os.path.isdir"] = Mock(side_effect=filesystem.is_dir)

    # os.listdir
    def mock_listdir(path):
        return filesystem.list_dir(path)

    patches["os.listdir"] = Mock(side_effect=mock_listdir)

    # open()
    def mock_file_open(path, mode="r", *args, **kwargs):
        path = str(path)
        if "r" in mode and path not in filesystem.files:
            raise FileNotFoundError(f"No such file: {path}")

        content = filesystem.files.get(path, "")
        mock_file = MockFile(content, mode)

        # If writing, update filesystem on close
        original_close = mock_file.close

        def close_with_save():
            if "w" in mode or "a" in mode:
                filesystem.files[path] = mock_file._buffer.getvalue()
            original_close()

        mock_file.close = close_with_save
        return mock_file

    patches["builtins.open"] = Mock(side_effect=mock_file_open)

    return patches


class MockPath:
    """Mock pathlib.Path for testing."""

    def __init__(self, path: Union[str, MockPath], filesystem: Union[MockFilesystem, None] = None):
        self.path = str(path)
        self.filesystem = filesystem or MockFilesystem()

    def __str__(self):
        return self.path

    def __truediv__(self, other):
        return MockPath(os.path.join(self.path, str(other)), self.filesystem)

    def exists(self) -> bool:
        return self.filesystem.exists(self.path)

    def is_file(self) -> bool:
        return self.filesystem.is_file(self.path)

    def is_dir(self) -> bool:
        return self.filesystem.is_dir(self.path)

    def read_text(self, encoding: str = "utf-8") -> str:
        return self.filesystem.read_file(self.path)

    def write_text(self, content: str, encoding: str = "utf-8"):
        self.filesystem.write_file(self.path, content)

    def iterdir(self):
        contents = self.filesystem.list_dir(self.path)
        for item in contents:
            yield MockPath(os.path.join(self.path, item), self.filesystem)

    @property
    def parent(self):
        return MockPath(os.path.dirname(self.path), self.filesystem)

    @property
    def name(self):
        return os.path.basename(self.path)

    @property
    def stem(self):
        return os.path.splitext(self.name)[0]

    @property
    def suffix(self):
        return os.path.splitext(self.name)[1]


# Utility functions for common testing scenarios
def mock_file_content(content: str, path: Union[str, None] = None):
    """Create a mock for reading file content."""
    return mock_open(read_data=content)


def create_temp_filesystem():
    """Create a temporary filesystem for testing."""

    class TempFilesystem:
        def __init__(self):
            self.temp_dir = tempfile.mkdtemp()
            self.created_files = []

        def add_file(self, relative_path: str, content: str) -> Path:
            """Add a file to the temporary filesystem."""
            full_path = Path(self.temp_dir) / relative_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
            self.created_files.append(full_path)
            return full_path

        def cleanup(self):
            """Clean up the temporary filesystem."""
            import shutil

            shutil.rmtree(self.temp_dir)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.cleanup()

    return TempFilesystem()


def patch_filesystem(files: dict[str, str]):
    """
    Decorator to patch filesystem with given files.

    Usage:
        @patch_filesystem({
            'test.sol': 'contract Test {}',
            'dir/other.sol': 'contract Other {}'
        })
        def test_something(mock_fs):
            # Test code here
            pass
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            fs = MockFilesystem()
            for path, content in files.items():
                fs.add_file(path, content)

            patches = create_mock_filesystem_patches(fs)
            with (
                patch.multiple("builtins", **{"open": patches["builtins.open"]}),
                patch.multiple("os.path", **{k: v for k, v in patches.items() if k.startswith("os.path.")}),
                patch.multiple("pathlib.Path", **{k: v for k, v in patches.items() if k.startswith("pathlib.Path.")}),
            ):
                return func(fs, *args, **kwargs)

        return wrapper

    return decorator
