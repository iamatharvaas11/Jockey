"""
JOCKY Canonical Evidence Framework
Provides standardized evidence schemas, cross-platform normalizers, schema validation,
cryptographic SHA-256 integrity manifests, decoupled storage, and chain-of-custody audit logging.
"""
from .schema import (
    CanonicalEvidenceItem,
    EvidenceType,
    EvidenceStatus,
    ProcessEvidence,
    FileEvidence,
    NetworkEvidence,
    EventEvidence,
    RegistryEvidence,
)
from .normalizer import EvidenceNormalizer
from .validator import EvidenceValidator, ValidationResult
from .integrity import (
    EvidenceIntegrityManager,
    IntegrityManifest,
    ManifestEntry,
    VerificationReport,
    VerificationStatus,
    IntegrityError,
)
from .store import (
    EvidenceStore,
    InMemoryEvidenceStore,
    FileEvidenceStore,
)
from .audit import (
    AuditRecord,
    AuditAction,
    AuditLogger,
)

__all__ = [
    "CanonicalEvidenceItem",
    "EvidenceType",
    "EvidenceStatus",
    "ProcessEvidence",
    "FileEvidence",
    "NetworkEvidence",
    "EventEvidence",
    "RegistryEvidence",
    "EvidenceNormalizer",
    "EvidenceValidator",
    "ValidationResult",
    "EvidenceIntegrityManager",
    "IntegrityManifest",
    "ManifestEntry",
    "VerificationReport",
    "VerificationStatus",
    "IntegrityError",
    "EvidenceStore",
    "InMemoryEvidenceStore",
    "FileEvidenceStore",
    "AuditRecord",
    "AuditAction",
    "AuditLogger",
]

