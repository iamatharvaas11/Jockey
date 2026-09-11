"""
JOCKY Registry Collector
Collects Windows Registry persistence mechanisms (Run/RunOnce keys, Services, etc.).
Strictly declares unsupported status on Linux and other non-Windows platforms.
"""
import sys
from typing import Dict, List, Optional, Tuple

from .base import BaseCollector, CollectorResult, CollectorStatus


class RegistryCollector(BaseCollector):
    """Forensic registry collector for Windows autoruns and system services."""

    def __init__(self):
        super().__init__(name="registry_collector")
        self.is_windows = sys.platform == "win32"
        self.winreg = None
        if self.is_windows:
            try:
                import winreg
                self.winreg = winreg
            except ImportError:
                pass

    def collect(self, **kwargs) -> CollectorResult:
        """
        Collect standard persistence registry keys (Run keys).
        Returns a normalized CollectorResult envelope.
        """
        return self.collect_run_keys()

    def collect_run_keys(self) -> CollectorResult:
        """Query standard Run and RunOnce autorun registry locations."""
        if not self.is_windows:
            return CollectorResult(
                type="registry",
                source=sys.platform,
                status=CollectorStatus.UNSUPPORTED,
                data=[],
                limitations=["Windows Registry is only supported on Windows platforms."],
            )

        if not self.winreg:
            return CollectorResult(
                type="registry",
                source="win32",
                status=CollectorStatus.FAILED,
                data=[],
                errors=["winreg module not available."],
            )

        keys_to_check: List[Tuple[Any, str]] = [
            (self.winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (self.winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (self.winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (self.winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        results = []
        errors = []
        limitations = []

        for hive, subkey in keys_to_check:
            hive_name = "HKLM" if hive == self.winreg.HKEY_LOCAL_MACHINE else "HKCU"
            try:
                with self.winreg.OpenKey(hive, subkey) as key:
                    i = 0
                    while True:
                        try:
                            name, value, type_ = self.winreg.EnumValue(key, i)
                            results.append({
                                "hive": hive_name,
                                "key": subkey,
                                "value_name": name,
                                "value_data": str(value),
                                "type": type_,
                            })
                            i += 1
                        except OSError:
                            break
            except PermissionError:
                limitations.append(f"Access denied opening {hive_name}\\{subkey}")
            except FileNotFoundError:
                # Normal: subkey may not exist
                pass
            except Exception as e:
                errors.append(f"Error querying {hive_name}\\{subkey}: {str(e)}")

        status = CollectorStatus.SUCCESS
        if errors and not results:
            status = CollectorStatus.FAILED
        elif errors or limitations:
            status = CollectorStatus.PARTIAL

        return CollectorResult(
            type="registry",
            source="win32",
            status=status,
            data=results,
            errors=errors,
            limitations=limitations,
        )

    def collect_services(self) -> CollectorResult:
        """Query installed Windows Services registered in HKLM\\SYSTEM\\CurrentControlSet\\Services."""
        if not self.is_windows:
            return CollectorResult(
                type="registry_services",
                source=sys.platform,
                status=CollectorStatus.UNSUPPORTED,
                data=[],
                limitations=["Windows Services registry is only supported on Windows."],
            )

        results = []
        errors = []
        limitations = []

        try:
            services_key_path = r"SYSTEM\CurrentControlSet\Services"
            with self.winreg.OpenKey(self.winreg.HKEY_LOCAL_MACHINE, services_key_path) as key:
                i = 0
                while True:
                    try:
                        svc_name = self.winreg.EnumKey(key, i)
                        try:
                            with self.winreg.OpenKey(key, svc_name) as svc_key:
                                image_path = ""
                                try:
                                    image_path, _ = self.winreg.QueryValueEx(svc_key, "ImagePath")
                                except FileNotFoundError:
                                    pass
                                results.append({
                                    "service_name": svc_name,
                                    "image_path": str(image_path),
                                    "key": f"{services_key_path}\\{svc_name}",
                                })
                        except (PermissionError, FileNotFoundError):
                            pass
                        i += 1
                    except OSError:
                        break
        except PermissionError:
            limitations.append("Administrator privileges required to enumerate HKLM\\SYSTEM\\Services.")
        except Exception as e:
            errors.append(f"Error enumerating services: {str(e)}")

        status = CollectorStatus.SUCCESS
        if errors and not results:
            status = CollectorStatus.FAILED
        elif errors or limitations:
            status = CollectorStatus.PARTIAL

        return CollectorResult(
            type="registry_services",
            source="win32",
            status=status,
            data=results,
            errors=errors,
            limitations=limitations,
        )
