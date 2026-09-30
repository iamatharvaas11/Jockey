"""
JOCKY Endpoint Agent Models
Defines endpoint identities, configuration, task contracts, and lifecycle statuses.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import os
import socket
from typing import Any, Dict, List, Optional
import uuid


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    ASSIGNED = "ASSIGNED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"


@dataclass
class AgentConfig:
    """Agent runtime configuration and server connection details."""
    server_url: str = field(default_factory=lambda: os.environ.get("BACKEND_URL", os.environ.get("SERVER_URL", "http://localhost:8000")))
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    api_token: str = field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = field(default_factory=socket.gethostname)
    ip_address: str = "127.0.0.1"
    os_type: str = "Windows"
    poll_interval_seconds: int = 5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_url": self.server_url,
            "agent_id": self.agent_id,
            "api_token": self.api_token,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type,
            "poll_interval_seconds": self.poll_interval_seconds,
        }


@dataclass
class AgentTask:
    """An authorized investigation task assigned to an endpoint agent."""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = "CASE-DEFAULT"
    commands: List[str] = field(default_factory=lambda: ["SCAN PROCESSES;"])
    assigned_to: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    assigned_at: Optional[str] = None
    completed_at: Optional[str] = None
    timeout_seconds: int = 60
    retry_count: int = 0
    max_retries: int = 3
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "investigation_id": self.investigation_id,
            "commands": self.commands,
            "assigned_to": self.assigned_to,
            "status": self.status.value,
            "created_at": self.created_at,
            "assigned_at": self.assigned_at,
            "completed_at": self.completed_at,
            "timeout_seconds": self.timeout_seconds,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "error_message": self.error_message,
        }


@dataclass
class TaskResult:
    """Forensic result payload submitted by an endpoint agent upon task execution."""
    task_id: str
    status: TaskStatus
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    integrity_manifest: Optional[Dict[str, Any]] = None
    limitations: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    execution_time_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "evidence_items": self.evidence_items,
            "integrity_manifest": self.integrity_manifest,
            "limitations": self.limitations,
            "errors": self.errors,
            "execution_time_seconds": self.execution_time_seconds,
        }

