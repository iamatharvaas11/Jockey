"""
JOCKY Endpoint Agent Client Core
Executes authorized forensic tasks, collects local evidence, generates cryptographic
integrity manifests, and securely submits results back to the central server hub.
"""
import logging
import time
from typing import Any, Dict, List, Optional

from agent.models import AgentConfig, AgentTask, TaskResult, TaskStatus
from agent.policy import SAFE_SCAN_COMMANDS, validate_task_commands
from evidence.integrity import EvidenceIntegrityManager
from evidence.schema import CanonicalEvidenceItem
from runtime import ForensicRuntime

logger = logging.getLogger("jocky.agent.core")


class EndpointAgent:
    """Autonomous, authorized forensic endpoint agent."""

    def __init__(self, config: AgentConfig, runtime: Optional[ForensicRuntime] = None):
        self.config = config
        self.runtime = runtime or ForensicRuntime()
        self.is_registered = False

    def register(self, hub) -> bool:
        """Register with central hub or backend server."""
        try:
            cfg = hub.register_endpoint(
                hostname=self.config.hostname,
                ip_address=self.config.ip_address,
                os_type=self.config.os_type,
            )
            self.config.agent_id = cfg.agent_id
            self.config.api_token = cfg.api_token
            self.is_registered = True
            logger.info(f"Agent successfully registered as {self.config.agent_id}")
            return True
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return False

    def send_heartbeat(self, hub, telemetry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send heartbeat telemetry to central hub."""
        return hub.record_heartbeat(
            agent_id=self.config.agent_id,
            api_token=self.config.api_token,
            telemetry=telemetry or {"hostname": self.config.hostname},
        )

    def execute_task(self, task: AgentTask) -> TaskResult:
        """
        Execute an authorized investigation task.
        Runs runtime collectors, computes deterministic SHA-256 digests,
        and generates an IntegrityManifest.
        """
        start_time = time.time()
        canonical_items: List[CanonicalEvidenceItem] = []
        limitations: List[str] = []
        errors: List[str] = []

        try:
            # Re-validate at the endpoint: a compromised or outdated hub must
            # never turn an evidence collector into a general execution agent.
            safe_commands = validate_task_commands(task.commands)
            requested_scans = []
            for command in safe_commands:
                for scan_name in SAFE_SCAN_COMMANDS[command]:
                    if scan_name not in requested_scans:
                        requested_scans.append(scan_name)

            for scan_name in requested_scans:
                result = self.runtime.execute_scan(scan_name)
                if result.limitations:
                    limitations.extend(result.limitations)
                if result.errors:
                    errors.extend(result.errors)

            # Retrieve normalized items from runtime evidence store
            stored_items = self.runtime.evidence_store.list_items()
            canonical_items.extend(stored_items)

            # Generate Cryptographic Integrity Manifest
            manifest = EvidenceIntegrityManager.create_manifest(
                items=canonical_items,
                case_id=task.investigation_id,
                examiner=f"EndpointAgent-{self.config.hostname}",
            )

            execution_duration = time.time() - start_time
            return TaskResult(
                task_id=task.task_id,
                status=TaskStatus.COMPLETED,
                evidence_items=[it.to_dict() for it in canonical_items],
                integrity_manifest=manifest.to_dict(),
                limitations=list(set(limitations)),
                errors=list(set(errors)),
                execution_time_seconds=execution_duration,
            )
        except Exception as e:
            execution_duration = time.time() - start_time
            logger.error(f"Task execution error: {e}")
            return TaskResult(
                task_id=task.task_id,
                status=TaskStatus.FAILED,
                evidence_items=[],
                integrity_manifest=None,
                limitations=[],
                errors=[str(e)],
                execution_time_seconds=execution_duration,
            )

    def run_cycle(self, hub) -> Optional[Dict[str, Any]]:
        """Run one complete agent lifecycle step: heartbeat -> poll -> execute -> submit."""
        if not self.is_registered:
            if not self.register(hub):
                return None

        # 1. Send Heartbeat
        self.send_heartbeat(hub)

        # 2. Poll for Next Task
        task = hub.get_next_task(self.config.agent_id, self.config.api_token)
        if not task:
            return None

        # 3. Execute Task
        result = self.execute_task(task)

        # 4. Submit Results back to Hub
        submission_resp = hub.submit_task_result(
            agent_id=self.config.agent_id,
            api_token=self.config.api_token,
            task_result=result,
        )
        return submission_resp
