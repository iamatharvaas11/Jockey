"""
JOCKY Evidence Store Abstraction
Provides decoupled in-memory and persistent filesystem storage for canonical evidence,
with querying, filtering, export/import, and integrated integrity verification.
"""
from abc import ABC, abstractmethod
import json
import os
from typing import Any, Dict, List, Optional

from evidence.integrity import EvidenceIntegrityManager, IntegrityManifest, VerificationReport
from evidence.schema import CanonicalEvidenceItem
from evidence.validator import EvidenceValidator


class EvidenceStore(ABC):
    """Abstract evidence storage interface."""

    @abstractmethod
    def add(self, item: CanonicalEvidenceItem) -> str:
        """Store an evidence item and return its ID."""
        pass

    @abstractmethod
    def add_batch(self, items: List[CanonicalEvidenceItem]) -> List[str]:
        """Store multiple evidence items in a single batch."""
        pass

    @abstractmethod
    def get(self, evidence_id: str) -> Optional[CanonicalEvidenceItem]:
        """Retrieve a specific evidence item by ID."""
        pass

    @abstractmethod
    def list(
        self,
        evidence_type: Optional[str] = None,
        host: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[CanonicalEvidenceItem]:
        """Query evidence items with optional type, host, and time filters."""
        pass

    @abstractmethod
    def count(self) -> int:
        """Return total number of stored evidence items."""
        pass

    @abstractmethod
    def export_json(self, path: str) -> str:
        """Export all evidence and an integrity manifest to a JSON file."""
        pass

    @abstractmethod
    def import_json(self, path: str) -> int:
        """Import evidence items from a JSON file."""
        pass

    @abstractmethod
    def create_manifest(self, case_id: str = "DEFAULT-CASE", examiner: str = "JOCKY") -> IntegrityManifest:
        """Generate a cryptographic integrity manifest across all stored items."""
        pass

    @abstractmethod
    def verify_integrity(self, manifest: Optional[IntegrityManifest] = None) -> VerificationReport:
        """Verify the integrity of all stored evidence against a manifest."""
        pass


class InMemoryEvidenceStore(EvidenceStore):
    """Thread-safe, decoupled in-memory evidence store."""

    def __init__(self):
        self._items: Dict[str, CanonicalEvidenceItem] = {}

    def add(self, item: CanonicalEvidenceItem) -> str:
        # Validate item
        v_res = EvidenceValidator.validate(item)
        if not v_res.is_valid:
            item.errors.extend(v_res.errors)

        # Attach hash if missing
        if not item.hash:
            EvidenceIntegrityManager.attach_hash(item)

        self._items[item.id] = item
        return item.id

    def add_batch(self, items: List[CanonicalEvidenceItem]) -> List[str]:
        ids = []
        for it in items:
            ids.append(self.add(it))
        return ids

    def get(self, evidence_id: str) -> Optional[CanonicalEvidenceItem]:
        return self._items.get(evidence_id)

    def list(
        self,
        evidence_type: Optional[str] = None,
        host: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[CanonicalEvidenceItem]:
        results = []
        for it in self._items.values():
            if evidence_type and it.type.lower() != evidence_type.lower():
                continue
            if host and it.host.lower() != host.lower():
                continue
            if start_time and it.timestamp < start_time:
                continue
            if end_time and it.timestamp > end_time:
                continue
            results.append(it)
        return results

    list_items = list

    def count(self) -> int:
        return len(self._items)

    def export_json(self, path: str) -> str:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        manifest = self.create_manifest()
        export_payload = {
            "evidence_count": len(self._items),
            "manifest": manifest.to_dict(),
            "items": [it.to_dict() for it in self._items.values()],
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(export_payload, f, indent=2, ensure_ascii=False)

        return path

    def import_json(self, path: str) -> int:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        imported_count = 0
        raw_items = payload.get("items", [])
        for raw in raw_items:
            item = CanonicalEvidenceItem.from_dict(raw)
            self.add(item)
            imported_count += 1

        return imported_count

    def create_manifest(self, case_id: str = "DEFAULT-CASE", examiner: str = "JOCKY") -> IntegrityManifest:
        items_list = list(self._items.values())
        return EvidenceIntegrityManager.create_manifest(items_list, case_id=case_id, examiner=examiner)

    def verify_integrity(self, manifest: Optional[IntegrityManifest] = None) -> VerificationReport:
        if not manifest:
            manifest = self.create_manifest()
        return EvidenceIntegrityManager.verify_manifest(manifest, self._items)


class FileEvidenceStore(InMemoryEvidenceStore):
    """Persistent filesystem evidence store syncing state to a JSON file."""

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
        if os.path.exists(file_path):
            self.import_json(file_path)

    def add(self, item: CanonicalEvidenceItem) -> str:
        eid = super().add(item)
        self.export_json(self.file_path)
        return eid

    def add_batch(self, items: List[CanonicalEvidenceItem]) -> List[str]:
        ids = super().add_batch(items)
        self.export_json(self.file_path)
        return ids

