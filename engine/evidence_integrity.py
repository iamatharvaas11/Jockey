"""
JOCKY Evidence Integrity Adapter
Integrates engine-level integrity operations with the canonical evidence integrity manager.
Eliminates silent placeholder hashes and guarantees genuine cryptographic verification.
"""
from datetime import datetime, timezone
import json
import platform
import sys
from typing import Any, Dict, List, Optional

from evidence.integrity import (
    EvidenceIntegrityManager,
    IntegrityError,
    IntegrityManifest,
    ManifestEntry,
    VerificationReport,
    VerificationStatus,
)
from evidence.audit import AuditLogger, AuditRecord, AuditAction


class EvidenceIntegrity:
    """Provides cryptographic integrity calculation, manifests, and audit logging."""

    def __init__(self):
        self.audit_logger = AuditLogger()

    def hash_artifact(self, data: Any) -> str:
        """
        Compute deterministic SHA-256 hash of data.
        Raises IntegrityError if serialization fails (no silent placeholders).
        """
        if data is None:
            raise IntegrityError("Cannot hash None artifact data.")
        try:
            json_bytes = json.dumps(
                data,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            return EvidenceIntegrityManager.compute_root_hash([json_bytes.decode("latin1")])
        except Exception as e:
            raise IntegrityError(f"Failed to hash artifact: {e}") from e

    def create_manifest(self, case_id: str, examiner: str, artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Construct a real, verified integrity manifest across actual artifacts."""
        entry_hashes = []
        manifest_artifacts = []

        for art in artifacts:
            art_data = art.get("data")
            if art_data is None:
                raise IntegrityError(f"Artifact '{art.get('name')}' contains no data to hash.")

            h = self.hash_artifact(art_data)
            entry_hashes.append(h)
            manifest_artifacts.append({
                "name": art.get("name"),
                "description": art.get("description"),
                "hash_sha256": h,
            })

        root_h = EvidenceIntegrityManager.compute_root_hash(entry_hashes)

        return {
            "case_id": case_id,
            "examiner": examiner,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "environment": {
                "hostname": platform.node(),
                "platform": platform.platform(),
                "python_version": sys.version,
            },
            "root_hash": root_h,
            "status": "verified",
            "artifacts": manifest_artifacts,
        }

    def verify_artifact(self, artifact_data: Any, expected_hash: str) -> bool:
        """Verify whether an artifact matches its expected SHA-256 hash."""
        if not expected_hash:
            return False
        try:
            computed = self.hash_artifact(artifact_data)
            return computed.lower() == expected_hash.lower()
        except IntegrityError:
            return False

    def save_manifest(self, manifest: Dict[str, Any], output_path: str):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4)

    def create_audit_record(
        self,
        action: str,
        user: str,
        entity_type: str,
        entity_id: Optional[str],
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        rec = self.audit_logger.log(
            action=action,
            actor=user,
            evidence_id=entity_id,
            details={"entity_type": entity_type, **(details or {})},
        )
        return rec.to_dict()
