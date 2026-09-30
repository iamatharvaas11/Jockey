"""
JOCKY File Collector
Collects filesystem metadata, timestamps, permissions, and cryptographic hashes
with resilient error handling for unreadable, locked, or missing files.
"""
import datetime
from datetime import timezone
import hashlib
import os
import sys
from typing import Any, Dict, List, Optional

from .base import BaseCollector, CollectorResult, CollectorStatus


class FileCollector(BaseCollector):
    """Forensic filesystem collector extracting file metadata and cryptographic hashes."""

    def __init__(self, max_hash_size_bytes: int = 100 * 1024 * 1024):  # 100 MB max for full hashing
        super().__init__(name="file_collector")
        self.max_hash_size = max_hash_size_bytes

    def hash_file(self, filepath: str) -> Dict[str, Optional[str]]:
        """
        Compute MD5 and SHA-256 for a given file.
        Returns None for hashes if file cannot be read, rather than fabricating hashes.
        """
        hashes: Dict[str, Optional[str]] = {"md5": None, "sha256": None}
        try:
            size = os.path.getsize(filepath)
            if size > self.max_hash_size:
                # Fast header fingerprint for very large files (>100MB)
                md5 = hashlib.md5()
                sha256 = hashlib.sha256()
                with open(filepath, "rb") as f:
                    chunk = f.read(1024 * 1024)
                    if chunk:
                        md5.update(chunk)
                        sha256.update(chunk)
                hashes["md5"] = md5.hexdigest()
                hashes["sha256"] = sha256.hexdigest()
                return hashes

            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    md5.update(chunk)
                    sha256.update(chunk)
            hashes["md5"] = md5.hexdigest()
            hashes["sha256"] = sha256.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            hashes["md5"] = None
            hashes["sha256"] = None
        return hashes

    def get_metadata(self, filepath: str) -> Dict[str, Any]:
        """Extract filesystem metadata and timestamps safely."""
        meta: Dict[str, Any] = {
            "path": filepath,
            "size": 0,
            "created_time": "",
            "modified_time": "",
            "accessed_time": "",
            "permissions": "",
            "type": "unknown",
            "error": None,
        }
        try:
            stat = os.stat(filepath)
            meta["size"] = stat.st_size
            meta["created_time"] = datetime.datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat()
            meta["modified_time"] = datetime.datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
            meta["accessed_time"] = datetime.datetime.fromtimestamp(stat.st_atime, timezone.utc).isoformat()
            meta["permissions"] = oct(stat.st_mode)[-3:]
            meta["type"] = "directory" if os.path.isdir(filepath) else "file"
        except PermissionError:
            meta["error"] = "PermissionDenied"
        except FileNotFoundError:
            meta["error"] = "FileNotFound"
        except OSError as e:
            meta["error"] = f"OSError: {e.strerror}"
        return meta

    def scan_directory(self, path: str, extensions: Optional[List[str]] = None, recursive: bool = True, max_files: int = 500) -> CollectorResult:
        """Scan a directory and collect file items."""
        return self.collect(paths=[path], extensions=extensions, recursive=recursive, max_files=max_files)

    def find_recent_files(self, directory: str, hours: int = 24, max_files: int = 100) -> CollectorResult:
        """Collect files modified within the last N hours."""
        cutoff = datetime.datetime.now(timezone.utc) - datetime.timedelta(hours=hours)
        cutoff_epoch = cutoff.timestamp()
        return self.collect(paths=[directory], min_mtime=cutoff_epoch, max_files=max_files)

    def collect(
        self,
        paths: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
        recursive: bool = True,
        max_files: int = 200,
        min_mtime: Optional[float] = None,
        **kwargs,
    ) -> CollectorResult:
        """
        Collect filesystem evidence across given paths.
        Returns a normalized CollectorResult envelope.
        """
        files_data = []
        errors = []
        limitations = []

        if not paths:
            # Default triage locations
            if sys.platform == "win32":
                paths = [
                    os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Default"), "AppData", "Local", "Temp"),
                    "C:\\Windows\\Temp",
                ]
            else:
                paths = ["/tmp", "/var/tmp"]

        for base_path in paths:
            if not os.path.exists(base_path):
                limitations.append(f"Target path does not exist: {base_path}")
                continue

            try:
                if os.path.isfile(base_path):
                    meta = self.get_metadata(base_path)
                    meta.update(self.hash_file(base_path))
                    files_data.append(meta)
                    continue

                def _on_walk_error(err: OSError):
                    errors.append(f"Access denied accessing directory: {err.filename}")
                    limitations.append(f"Directory unreadable (access denied): {err.filename}")

                for root, dirs, files in os.walk(base_path, onerror=_on_walk_error):
                    for file in files:
                        if len(files_data) >= max_files:
                            limitations.append(f"File count reached collection cap ({max_files} files).")
                            break

                        if extensions and not any(file.lower().endswith(ext.lower()) for ext in extensions):
                            continue

                        filepath = os.path.join(root, file)
                        try:
                            if min_mtime:
                                stat = os.stat(filepath)
                                if stat.st_mtime < min_mtime:
                                    continue

                            meta = self.get_metadata(filepath)
                            hashes = self.hash_file(filepath)
                            if hashes.get("sha256") is None and meta.get("size", 0) > 0:
                                meta["hash_error"] = "Hash calculation failed (locked or unreadable file)"
                                limitations.append(f"Hash calculation failed for {filepath}: file locked or unreadable")
                            meta.update(hashes)
                            files_data.append(meta)

                        except PermissionError:
                            errors.append(f"Permission denied: {filepath}")
                        except FileNotFoundError:
                            errors.append(f"File disappeared during collection: {filepath}")
                        except OSError as e:
                            errors.append(f"Cannot read {filepath}: {e.strerror}")

                    if len(files_data) >= max_files or not recursive:
                        break

            except PermissionError:
                errors.append(f"Access denied accessing directory: {base_path}")
            except Exception as e:
                errors.append(f"Error reading {base_path}: {str(e)}")

        status = CollectorStatus.SUCCESS
        if errors and not files_data:
            status = CollectorStatus.FAILED
        elif errors or limitations:
            status = CollectorStatus.PARTIAL

        return CollectorResult(
            type="file",
            source=sys.platform,
            status=status,
            data=files_data,
            errors=errors,
            limitations=limitations,
        )
