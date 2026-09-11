"""
JOCKY Central Agent Server Hub
Coordinates multi-endpoint agents: handles registration, authentication, heartbeats,
task queue dispatching, timeout/retry mechanics, cryptographic result verification,
and automatic downstream analysis processing.
"""
from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, List, Optional
import uuid

from agent.models import AgentConfig, AgentTask, TaskResult, TaskStatus
from agent.policy import validate_task_commands
from analysis import run_investigation_analysis
from evidence.audit import AuditAction, AuditLogger
from evidence.integrity import EvidenceIntegrityManager, IntegrityManifest, VerificationStatus
from evidence.schema import CanonicalEvidenceItem

logger = logging.getLogger("jocky.agent.hub")


class AgentAuthenticationError(Exception):
    """Raised when an agent request cannot be verified or authenticated."""
    pass


class AgentServerHub:
    """Central orchestration hub managing remote or local authorized JOCKY endpoint agents."""

    def __init__(self, heartbeat_timeout_seconds: int = 30):
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._agents: Dict[str, Dict[str, Any]] = {}
        self._tasks: Dict[str, AgentTask] = {}
        self._results: Dict[str, TaskResult] = {}
        self._audit_logger = AuditLogger()

    # ========================================================================
    # 1. Endpoint Registration & Authentication
    # ========================================================================

    def register_endpoint(
        self,
        hostname: str,
        ip_address: str = "127.0.0.1",
        os_type: str = "Windows",
        system_info: Optional[Dict[str, Any]] = None,
    ) -> AgentConfig:
        """Register a new endpoint agent and provision an authentication token."""
        agent_id = str(uuid.uuid4())
        api_token = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        config = AgentConfig(
            agent_id=agent_id,
            api_token=api_token,
            hostname=hostname,
            ip_address=ip_address,
            os_type=os_type,
        )

        self._agents[agent_id] = {
            "config": config,
            "status": "ONLINE",
            "registered_at": now,
            "last_heartbeat": now,
            "system_info": system_info or {},
        }

        self._audit_logger.log(
            action=AuditAction.COLLECT,
            actor="SERVER_HUB",
            evidence_id=agent_id,
            result="SUCCESS",
            details={"action": "ENDPOINT_REGISTERED", "hostname": hostname},
        )
        logger.info(f"Registered endpoint agent {hostname} (ID: {agent_id})")
        return config

    def authenticate_agent(self, agent_id: str, api_token: str):
        """Verify endpoint agent identity and authorization."""
        if agent_id not in self._agents:
            raise AgentAuthenticationError(f"Unknown agent identifier: '{agent_id}'")
        if self._agents[agent_id]["config"].api_token != api_token:
            raise AgentAuthenticationError("Invalid agent authentication credentials.")

    # ========================================================================
    # 2. Heartbeat & Online/Offline Status Tracking
    # ========================================================================

    def record_heartbeat(self, agent_id: str, api_token: str, telemetry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Record agent heartbeat, updating status to ONLINE and refreshing timestamp."""
        self.authenticate_agent(agent_id, api_token)
        now_dt = datetime.now(timezone.utc)
        self._agents[agent_id]["last_heartbeat"] = now_dt.isoformat()
        self._agents[agent_id]["status"] = "ONLINE"
        if telemetry:
            self._agents[agent_id]["system_info"].update(telemetry)

        # Count pending tasks for this agent
        pending_count = sum(
            1 for t in self._tasks.values()
            if t.assigned_to == agent_id and t.status in (TaskStatus.PENDING, TaskStatus.ASSIGNED)
        )
        return {"status": "ACK", "agent_status": "ONLINE", "pending_tasks": pending_count}

    def check_agent_statuses(self) -> Dict[str, str]:
        """Identify stale heartbeats and transition inactive agents to OFFLINE."""
        now_dt = datetime.now(timezone.utc)
        statuses = {}
        for agent_id, data in self._agents.items():
            last_hb_str = data["last_heartbeat"]
            last_hb_dt = datetime.fromisoformat(last_hb_str)
            if now_dt - last_hb_dt > timedelta(seconds=self.heartbeat_timeout_seconds):
                data["status"] = "OFFLINE"
            statuses[agent_id] = data["status"]
        return statuses

    # ========================================================================
    # 3. Task Management & Dispatch
    # ========================================================================

    def create_task(
        self,
        investigation_id: str,
        commands: List[str],
        assigned_to: Optional[str] = None,
        timeout_seconds: int = 60,
    ) -> AgentTask:
        """Create a new, allow-listed read-only investigation task for an endpoint."""
        safe_commands = validate_task_commands(commands)
        task = AgentTask(
            investigation_id=investigation_id,
            commands=list(safe_commands),
            assigned_to=assigned_to,
            status=TaskStatus.ASSIGNED if assigned_to else TaskStatus.PENDING,
            timeout_seconds=timeout_seconds,
        )
        self._tasks[task.task_id] = task
        logger.info(f"Created task {task.task_id} for investigation {investigation_id}")
        return task

    def get_next_task(self, agent_id: str, api_token: str) -> Optional[AgentTask]:
        """Fetch the next available task for the requesting agent."""
        self.authenticate_agent(agent_id, api_token)
        for task in self._tasks.values():
            if task.assigned_to == agent_id and task.status in (TaskStatus.PENDING, TaskStatus.ASSIGNED):
                task.status = TaskStatus.RUNNING
                task.assigned_at = datetime.now(timezone.utc).isoformat()
                return task
        return None

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending or running task."""
        if task_id in self._tasks:
            t = self._tasks[task_id]
            if t.status in (TaskStatus.PENDING, TaskStatus.ASSIGNED, TaskStatus.RUNNING):
                t.status = TaskStatus.CANCELLED
                return True
        return False

    # ========================================================================
    # 4. Result Submission, Integrity Verification & Analysis Pipeline
    # ========================================================================

    def submit_task_result(
        self,
        agent_id: str,
        api_token: str,
        task_result: TaskResult,
    ) -> Dict[str, Any]:
        """
        Accept, verify, and process evidence submitted by an endpoint agent.
        Validates cryptographic integrity manifest before triggering downstream analysis.
        """
        self.authenticate_agent(agent_id, api_token)
        task_id = task_result.task_id
        if task_id not in self._tasks:
            raise ValueError(f"Task ID {task_id} does not exist in central hub.")

        task = self._tasks[task_id]

        # Verify cryptographic integrity if manifest is present
        integrity_valid = True
        verification_status = "UNVERIFIED"

        if task_result.integrity_manifest and task_result.evidence_items:
            m_dict = task_result.integrity_manifest
            manifest = IntegrityManifest.from_dict(m_dict)
            canonical_items = [
                CanonicalEvidenceItem.from_dict(it) if isinstance(it, dict) else it
                for it in task_result.evidence_items
            ]
            v_report = EvidenceIntegrityManager.verify_manifest(manifest, canonical_items)
            verification_status = v_report.status.value
            if v_report.status != VerificationStatus.VALID:
                integrity_valid = False
                task.status = TaskStatus.FAILED
                task.error_message = f"Integrity verification failed: {verification_status}"
                return {
                    "task_id": task_id,
                    "status": "REJECTED",
                    "verification_status": verification_status,
                    "reason": "Tampered or corrupted evidence submitted by agent.",
                }

        # Process analysis pipeline
        canonical_items = [
            CanonicalEvidenceItem.from_dict(it) if isinstance(it, dict) else it
            for it in task_result.evidence_items
        ]
        analysis = run_investigation_analysis(canonical_items, case_id=task.investigation_id)

        task.status = TaskStatus.COMPLETED
        task.completed_at = datetime.now(timezone.utc).isoformat()
        self._results[task_id] = task_result

        return {
            "task_id": task_id,
            "status": "ACCEPTED",
            "verification_status": verification_status,
            "evidence_count": len(task_result.evidence_items),
            "ioc_findings": len(analysis.findings),
            "relationships": len(analysis.relationships),
            "timeline_events": len(analysis.timeline),
        }

    def retry_task_if_eligible(self, task_id: str) -> bool:
        """Retry a failed or timed out task if it has not exceeded max retries."""
        if task_id in self._tasks:
            task = self._tasks[task_id]
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.ASSIGNED
                task.error_message = None
                return True
            task.status = TaskStatus.FAILED
        return False
