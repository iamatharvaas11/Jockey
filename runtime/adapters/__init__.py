"""
JOCKY Runtime Adapters Package
Provides platform detection and adapter factories for Windows and Linux.
"""
import sys
from typing import Optional

from .base_adapter import ForensicAdapter
from .windows_adapter import WindowsAdapter
from .linux_adapter import LinuxAdapter


def get_platform_adapter(force_os: Optional[str] = None) -> ForensicAdapter:
    """
    Select and instantiate the appropriate ForensicAdapter for the host platform.

    Args:
        force_os: Optional override ('windows', 'linux') for testing.
    """
    target_os = force_os.lower() if force_os else sys.platform.lower()

    if target_os.startswith("win"):
        return WindowsAdapter()
    elif target_os.startswith("linux"):
        return LinuxAdapter()
    else:
        # Default fallback for Darwin/BSD: use LinuxAdapter (Unix/POSIX collectors)
        return LinuxAdapter()


__all__ = [
    "ForensicAdapter",
    "WindowsAdapter",
    "LinuxAdapter",
    "get_platform_adapter",
]
