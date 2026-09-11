"""
JOCKY Evidence Normalizer
Transforms raw records from Windows, Linux, and custom collectors into
canonical, schema-compliant CanonicalEvidenceItem instances.
"""
from typing import Any, Dict, List, Optional
import uuid

from collectors.base import CollectorResult, CollectorStatus
from evidence.schema import (
    CanonicalEvidenceItem,
    EvidenceStatus,
    EvidenceType,
    EventEvidence,
    FileEvidence,
    NetworkEvidence,
    ProcessEvidence,
    RegistryEvidence,
)


class EvidenceNormalizer:
    """Normalizes heterogeneous collector outputs across operating systems into canonical schema."""

    @staticmethod
    def normalize_collector_result(result: CollectorResult) -> List[CanonicalEvidenceItem]:
        """Convert an entire CollectorResult into a list of CanonicalEvidenceItems."""
        items = []
        c_type = result.type.lower()

        for raw_entry in result.data:
            if c_type == "process":
                item = EvidenceNormalizer.normalize_process(raw_entry, host=result.host, source=result.source)
            elif c_type in ("file", "files"):
                item = EvidenceNormalizer.normalize_file(raw_entry, host=result.host, source=result.source)
            elif c_type in ("network", "network_interfaces"):
                item = EvidenceNormalizer.normalize_network(raw_entry, host=result.host, source=result.source)
            elif c_type in ("eventlog", "eventlogs"):
                item = EvidenceNormalizer.normalize_event(raw_entry, host=result.host, source=result.source)
            elif c_type in ("registry", "registry_services"):
                item = EvidenceNormalizer.normalize_registry(raw_entry, host=result.host, source=result.source)
            else:
                item = CanonicalEvidenceItem(
                    host=result.host,
                    type=EvidenceType.GENERIC.value,
                    source=result.source,
                    collector=f"{c_type}_collector",
                    status=result.status.value if isinstance(result.status, CollectorStatus) else str(result.status),
                    data=raw_entry,
                    limitations=list(result.limitations),
                    errors=list(result.errors),
                )
            items.append(item)

        return items

    @staticmethod
    def normalize_process(data: Dict[str, Any], host: str = "", source: str = "unknown") -> CanonicalEvidenceItem:
        """
        Normalize process records from Windows (psutil/win32) or Linux (/proc or psutil).
        """
        # Common fields
        pid = int(data.get("pid", 0))
        ppid = int(data.get("ppid", 0)) if data.get("ppid") is not None else 0
        name = str(data.get("name") or "unknown")
        exe_path = data.get("exe_path") or data.get("exe") or None
        exe_hash = data.get("exe_hash") or None
        cmdline = data.get("cmdline") or None
        username = data.get("username") or None
        created_time = data.get("created_time") or data.get("create_time") or None
        status = str(data.get("status") or "unknown")
        memory_bytes = data.get("memory_bytes") or data.get("memory_rss") or None
        threads = data.get("threads") or None

        # Isolate platform-specific raw fields
        known_keys = {"pid", "ppid", "name", "exe_path", "exe", "exe_hash", "cmdline", "username", "status", "created_time", "create_time", "memory_bytes", "memory_rss", "threads"}
        platform_data = {k: v for k, v in data.items() if k not in known_keys}

        proc_evidence = ProcessEvidence(
            pid=pid,
            ppid=ppid,
            name=name,
            exe_path=exe_path,
            exe_hash=exe_hash,
            cmdline=cmdline,
            username=username,
            created_time=created_time,
            status=status,
            memory_bytes=memory_bytes,
            threads=threads,
            platform_data=platform_data,
        )

        return CanonicalEvidenceItem(
            host=host,
            type=EvidenceType.PROCESS.value,
            source=source,
            collector="ProcessCollector",
            status=EvidenceStatus.SUCCESS.value,
            data=proc_evidence.to_dict(),
        )

    @staticmethod
    def normalize_file(data: Dict[str, Any], host: str = "", source: str = "unknown") -> CanonicalEvidenceItem:
        """Normalize filesystem records across Windows and POSIX."""
        path = str(data.get("path") or "unknown")
        size = int(data.get("size", 0)) if data.get("size") is not None else 0
        created_time = data.get("created_time") or None
        modified_time = data.get("modified_time") or None
        accessed_time = data.get("accessed_time") or None
        permissions = data.get("permissions") or None
        f_type = data.get("type") or "file"
        sha256 = data.get("sha256") or None
        md5 = data.get("md5") or None

        known_keys = {"path", "size", "created_time", "modified_time", "accessed_time", "permissions", "type", "sha256", "md5"}
        platform_data = {k: v for k, v in data.items() if k not in known_keys}

        file_evidence = FileEvidence(
            path=path,
            size=size,
            created_time=created_time,
            modified_time=modified_time,
            accessed_time=accessed_time,
            permissions=permissions,
            type=f_type,
            sha256=sha256,
            md5=md5,
            platform_data=platform_data,
        )

        return CanonicalEvidenceItem(
            host=host,
            type=EvidenceType.FILE.value,
            source=source,
            collector="FileCollector",
            status=EvidenceStatus.SUCCESS.value,
            data=file_evidence.to_dict(),
        )

    @staticmethod
    def normalize_network(data: Dict[str, Any], host: str = "", source: str = "unknown") -> CanonicalEvidenceItem:
        """Normalize network connections across Windows (psutil) and Linux (/proc/net)."""
        protocol = str(data.get("protocol") or "UNKNOWN").upper()
        local_ip = str(data.get("local_ip") or data.get("local_address") or "0.0.0.0")
        local_port = int(data.get("local_port", 0)) if data.get("local_port") is not None else 0
        remote_ip = str(data.get("remote_ip") or data.get("remote_address") or "0.0.0.0")
        remote_port = int(data.get("remote_port", 0)) if data.get("remote_port") is not None else 0
        status = str(data.get("status") or "UNKNOWN")
        pid = int(data.get("pid", 0)) if data.get("pid") else None
        process_name = data.get("process_name") or None

        known_keys = {"protocol", "local_ip", "local_address", "local_port", "remote_ip", "remote_address", "remote_port", "status", "pid", "process_name"}
        platform_data = {k: v for k, v in data.items() if k not in known_keys}

        net_evidence = NetworkEvidence(
            protocol=protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            status=status,
            pid=pid,
            process_name=process_name,
            platform_data=platform_data,
        )

        return CanonicalEvidenceItem(
            host=host,
            type=EvidenceType.NETWORK.value,
            source=source,
            collector="NetworkCollector",
            status=EvidenceStatus.SUCCESS.value,
            data=net_evidence.to_dict(),
        )

    @staticmethod
    def normalize_event(data: Dict[str, Any], host: str = "", source: str = "unknown") -> CanonicalEvidenceItem:
        """Normalize Windows EventLog or Linux syslog/authlog."""
        log_name = str(data.get("log_name") or "system")
        event_id = int(data.get("event_id", 0)) if data.get("event_id") is not None else 0
        src = str(data.get("source") or log_name)
        time_created = str(data.get("time_created") or data.get("timestamp") or "")
        event_data = data.get("event_data") or {}
        message = data.get("message") or data.get("log") or None

        known_keys = {"log_name", "event_id", "source", "time_created", "timestamp", "event_data", "message", "log"}
        platform_data = {k: v for k, v in data.items() if k not in known_keys}

        event_evidence = EventEvidence(
            log_name=log_name,
            event_id=event_id,
            source=src,
            time_created=time_created,
            event_data=event_data,
            message=message,
            platform_data=platform_data,
        )

        return CanonicalEvidenceItem(
            host=host,
            type=EvidenceType.EVENT.value,
            source=source,
            collector="EventLogCollector",
            status=EvidenceStatus.SUCCESS.value,
            data=event_evidence.to_dict(),
        )

    @staticmethod
    def normalize_registry(data: Dict[str, Any], host: str = "", source: str = "win32") -> CanonicalEvidenceItem:
        """Normalize Windows Registry autorun and service entries."""
        hive = str(data.get("hive") or "HKLM")
        key = str(data.get("key") or data.get("path") or "")
        value_name = str(data.get("value_name") or data.get("name") or data.get("service_name") or "")
        value_data = str(data.get("value_data") or data.get("value") or data.get("image_path") or "")
        value_type = data.get("type")

        known_keys = {"hive", "key", "path", "value_name", "name", "service_name", "value_data", "value", "image_path", "type"}
        platform_data = {k: v for k, v in data.items() if k not in known_keys}

        reg_evidence = RegistryEvidence(
            hive=hive,
            key=key,
            value_name=value_name,
            value_data=value_data,
            value_type=value_type if isinstance(value_type, int) else None,
            platform_data=platform_data,
        )

        return CanonicalEvidenceItem(
            host=host,
            type=EvidenceType.REGISTRY.value,
            source=source,
            collector="RegistryCollector",
            status=EvidenceStatus.SUCCESS.value,
            data=reg_evidence.to_dict(),
        )

