"""
JOCKY Evidence Integrity & Cryptographic Hashing
Computes deterministic SHA-256 hashes over canonical evidence representations,
constructs integrity manifests, and performs strict tamper detection and verification.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
import platform
import socket
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from evidence.schema import CanonicalEvidenceItem


class IntegrityError(Exception):
    """Raised when cryptographic hashing or verification fails unexpectedly."""
    pass


class VerificationStatus(str, Enum):
    VALID = "VALID"
    MODIFIED = "MODIFIED"
    CORRUPTED = "CORRUPTED"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"


@dataclass
class ManifestEntry:
    """A cryptographic entry linking an evidence item to its verified SHA-256 digest."""
    evidence_id: str
    type: str
    hash_sha256: str
    timestamp: str
    source: str
    host: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "type": self.type,
            "hash_sha256": self.hash_sha256,
            "timestamp": self.timestamp,
            "source": self.source,
            "host": self.host,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ManifestEntry":
        return cls(
            evidence_id=data["evidence_id"],
            type=data.get("type", "generic"),
            hash_sha256=data["hash_sha256"],
            timestamp=data.get("timestamp", ""),
            source=data.get("source", "unknown"),
            host=data.get("host", "unknown"),
        )


@dataclass
class IntegrityManifest:
    """Cryptographic manifest encapsulating evidence digests and an overall root hash."""
    manifest_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = "DEFAULT-CASE"
    examiner: str = "JOCKY Automated Evidence Engine"
    host: str = field(default_factory=socket.gethostname)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    algorithm: str = "SHA-256"
    root_hash: str = ""
    entries: List[ManifestEntry] = field(default_factory=list)
    status: str = "unverified"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "case_id": self.case_id,
            "examiner": self.examiner,
            "host": self.host,
            "timestamp": self.timestamp,
            "algorithm": self.algorithm,
            "root_hash": self.root_hash,
            "total_items": len(self.entries),
            "status": self.status,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IntegrityManifest":
        entries = [ManifestEntry.from_dict(e) for e in data.get("entries", [])]
        return cls(
            manifest_id=data.get("manifest_id", str(uuid.uuid4())),
            case_id=data.get("case_id", "DEFAULT-CASE"),
            examiner=data.get("examiner", "JOCKY"),
            host=data.get("host", socket.gethostname()),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            algorithm=data.get("algorithm", "SHA-256"),
            root_hash=data.get("root_hash", ""),
            entries=entries,
            status=data.get("status", "unverified"),
        )


@dataclass
class VerificationReport:
    """Report detailing the outcome of an evidence or manifest verification pass."""
    status: VerificationStatus
    total_checked: int
    valid_count: int
    modified_count: int
    missing_count: int
    corrupted_count: int
    details: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return self.status == VerificationStatus.VALID


class EvidenceIntegrityManager:
    """
    Cryptographic manager computing deterministic SHA-256 digests
    and generating/verifying tamper-evident manifests.
    """

    @staticmethod
    def compute_evidence_hash(item: CanonicalEvidenceItem) -> str:
        """
        Compute deterministic SHA-256 hash of a CanonicalEvidenceItem.
        Omits the 'hash' attribute itself to ensure reproducibility.
        Raises IntegrityError if serialization fails (no silent placeholders).
        """
        try:
            # Deterministic representation: sort keys, strict separators, UTF-8
            raw_dict = item.to_dict(include_hash=False)
            canonical_bytes = json.dumps(
                raw_dict,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            digest = hashlib.sha256(canonical_bytes).hexdigest()
            return digest
        except Exception as e:
            raise IntegrityError(f"Failed to compute deterministic SHA-256 hash for evidence {item.id}: {e}") from e

    @staticmethod
    def attach_hash(item: CanonicalEvidenceItem) -> CanonicalEvidenceItem:
        """Compute and set the hash attribute on an evidence item."""
        item.hash = EvidenceIntegrityManager.compute_evidence_hash(item)
        return item

    @staticmethod
    def compute_root_hash(entry_hashes: List[str]) -> str:
        """Compute deterministic root hash across all item digests."""
        if not entry_hashes:
            return hashlib.sha256(b"").hexdigest()
        sorted_hashes = sorted(entry_hashes)
        combined = "".join(sorted_hashes).encode("utf-8")
        return hashlib.sha256(combined).hexdigest()

    @staticmethod
    def create_manifest(
        items: List[CanonicalEvidenceItem],
        case_id: str = "DEFAULT-CASE",
        examiner: str = "JOCKY Automated Evidence Engine",
    ) -> IntegrityManifest:
        """Construct an IntegrityManifest for a collection of evidence items."""
        manifest = IntegrityManifest(case_id=case_id, examiner=examiner)
        entry_hashes = []

        for item in items:
            if not item.hash:
                EvidenceIntegrityManager.attach_hash(item)

            entry = ManifestEntry(
                evidence_id=item.id,
                type=item.type,
                hash_sha256=item.hash,
                timestamp=item.timestamp,
                source=item.source,
                host=item.host,
            )
            manifest.entries.append(entry)
            entry_hashes.append(item.hash)

        manifest.root_hash = EvidenceIntegrityManager.compute_root_hash(entry_hashes)
        manifest.status = "verified"
        return manifest

    @staticmethod
    def verify_item(item: CanonicalEvidenceItem, recorded_hash: Optional[str] = None) -> VerificationStatus:
        """
        Verify an individual evidence item against a recorded hash or its own attached hash.
        Returns VerificationStatus.VALID if intact, or VerificationStatus.MODIFIED if tampered.
        """
        expected = recorded_hash or item.hash
        if not expected:
            return VerificationStatus.CORRUPTED

        try:
            computed = EvidenceIntegrityManager.compute_evidence_hash(item)
            if computed.lower() == expected.lower():
                return VerificationStatus.VALID
            return VerificationStatus.MODIFIED
        except IntegrityError:
            return VerificationStatus.CORRUPTED

    @staticmethod
    def verify_manifest(
        manifest: IntegrityManifest,
        items: Union[List[CanonicalEvidenceItem], Dict[str, CanonicalEvidenceItem]],
    ) -> VerificationReport:
        """
        Verify all entries in an IntegrityManifest against stored evidence items.
        Detects tampering, modifications, missing records, and root hash discrepancies.
        """
        if isinstance(items, list):
            item_map = {it.id: it for it in items}
        else:
            item_map = items

        details = []
        valid_cnt = 0
        mod_cnt = 0
        missing_cnt = 0
        corrupted_cnt = 0
        computed_entry_hashes = []

        for entry in manifest.entries:
            eid = entry.evidence_id
            if eid not in item_map:
                missing_cnt += 1
                details.append({
                    "evidence_id": eid,
                    "status": VerificationStatus.MISSING_EVIDENCE.value,
                    "reason": "Evidence item not found in store",
                })
                continue

            item = item_map[eid]
            status = EvidenceIntegrityManager.verify_item(item, entry.hash_sha256)
            if status == VerificationStatus.VALID:
                valid_cnt += 1
                computed_entry_hashes.append(entry.hash_sha256)
                details.append({"evidence_id": eid, "status": VerificationStatus.VALID.value})
            elif status == VerificationStatus.MODIFIED:
                mod_cnt += 1
                details.append({
                    "evidence_id": eid,
                    "status": VerificationStatus.MODIFIED.value,
                    "expected_hash": entry.hash_sha256,
                    "computed_hash": EvidenceIntegrityManager.compute_evidence_hash(item),
                })
            else:
                corrupted_cnt += 1
                details.append({"evidence_id": eid, "status": VerificationStatus.CORRUPTED.value})

        # Check root hash integrity
        expected_root = EvidenceIntegrityManager.compute_root_hash(
            [e.hash_sha256 for e in manifest.entries]
        )
        root_matches = (expected_root.lower() == manifest.root_hash.lower())

        if not root_matches:
            corrupted_cnt += 1
            details.append({
                "evidence_id": "MANIFEST_ROOT",
                "status": VerificationStatus.CORRUPTED.value,
                "reason": "Root hash does not match computed entry digests",
            })

        overall_status = VerificationStatus.VALID
        if mod_cnt > 0:
            overall_status = VerificationStatus.MODIFIED
        elif corrupted_cnt > 0:
            overall_status = VerificationStatus.CORRUPTED
        elif missing_cnt > 0:
            overall_status = VerificationStatus.MISSING_EVIDENCE

        return VerificationReport(
            status=overall_status,
            total_checked=len(manifest.entries),
            valid_count=valid_cnt,
            modified_count=mod_cnt,
            missing_count=missing_cnt,
            corrupted_count=corrupted_cnt,
            details=details,
        )

