"""
JOCKY Evidence Schema Validator
Enforces required provenance fields, timestamp formatting, hash integrity syntax,
and type-specific structural rules on CanonicalEvidenceItem instances.
"""
from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Any, Dict, List, Optional, Tuple

from evidence.schema import CanonicalEvidenceItem, EvidenceStatus, EvidenceType

_HEX_64_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
_ISO_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$"
)


@dataclass
class ValidationResult:
    """Result of validating an evidence item."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class EvidenceValidator:
    """Validates CanonicalEvidenceItem instances against schema constraints."""

    ALLOWED_TYPES = {t.value for t in EvidenceType}
    ALLOWED_STATUSES = {s.value for s in EvidenceStatus}

    @classmethod
    def validate(cls, item: CanonicalEvidenceItem) -> ValidationResult:
        """Validate an evidence item and return ValidationResult."""
        errors: List[str] = []
        warnings: List[str] = []

        # 1. Required Top-Level Provenance Fields
        if not item.id or not isinstance(item.id, str):
            errors.append("Evidence item 'id' must be a non-empty string.")

        if not item.host or not isinstance(item.host, str) or not item.host.strip():
            errors.append("Evidence item 'host' must be a non-empty string.")

        if not item.source or not isinstance(item.source, str):
            errors.append("Evidence item 'source' must be specified.")

        # 2. Timestamp Format
        if not item.timestamp or not isinstance(item.timestamp, str):
            errors.append("Evidence item 'timestamp' must be a non-empty string.")
        elif not _ISO_TIMESTAMP_PATTERN.match(item.timestamp):
            errors.append(f"Invalid timestamp format: '{item.timestamp}'. Expected ISO-8601 UTC.")

        # 3. Evidence Type
        if item.type not in cls.ALLOWED_TYPES:
            errors.append(f"Invalid evidence type: '{item.type}'. Allowed types: {cls.ALLOWED_TYPES}")

        # 4. Status
        if item.status not in cls.ALLOWED_STATUSES:
            errors.append(f"Invalid status: '{item.status}'. Allowed statuses: {cls.ALLOWED_STATUSES}")

        # 5. Hash Format (if present)
        if item.hash is not None:
            if not isinstance(item.hash, str) or not _HEX_64_PATTERN.match(item.hash):
                errors.append(f"Invalid SHA-256 hash format: '{item.hash}'. Must be 64 hex characters.")

        # 6. Type-Specific Entity Data Constraints
        data = item.data if isinstance(item.data, dict) else {}
        if not isinstance(item.data, dict):
            errors.append("Evidence 'data' must be a dictionary.")
        else:
            cls._validate_entity_data(item.type, data, errors, warnings)

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)

    @classmethod
    def _validate_entity_data(cls, e_type: str, data: Dict[str, Any], errors: List[str], warnings: List[str]):
        if e_type == EvidenceType.PROCESS.value:
            if "pid" not in data or not isinstance(data["pid"], int):
                errors.append("Process evidence requires an integer 'pid'.")
            if "name" not in data or not str(data["name"]).strip():
                errors.append("Process evidence requires a non-empty 'name'.")

        elif e_type == EvidenceType.FILE.value:
            if "path" not in data or not str(data["path"]).strip():
                errors.append("File evidence requires a non-empty 'path'.")
            if "size" not in data or not isinstance(data["size"], int) or data["size"] < 0:
                errors.append("File evidence requires a non-negative integer 'size'.")
            if data.get("sha256") and not _HEX_64_PATTERN.match(str(data["sha256"])):
                errors.append(f"Invalid file sha256 format: '{data['sha256']}'.")

        elif e_type == EvidenceType.NETWORK.value:
            if "protocol" not in data:
                errors.append("Network evidence requires 'protocol'.")
            if "local_ip" not in data:
                errors.append("Network evidence requires 'local_ip'.")
            if "local_port" not in data or not isinstance(data["local_port"], int):
                errors.append("Network evidence requires integer 'local_port'.")

        elif e_type == EvidenceType.EVENT.value:
            if "log_name" not in data:
                errors.append("Event evidence requires 'log_name'.")
            if "event_id" not in data or not isinstance(data["event_id"], int):
                errors.append("Event evidence requires integer 'event_id'.")

        elif e_type == EvidenceType.REGISTRY.value:
            if "hive" not in data:
                errors.append("Registry evidence requires 'hive'.")
            if "key" not in data:
                errors.append("Registry evidence requires 'key'.")
            if "value_name" not in data:
                errors.append("Registry evidence requires 'value_name'.")

