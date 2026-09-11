"""
Tests for JOCKY Stage 9 Multi-Endpoint Agent Subsystem
Covers registration, authentication, heartbeats, online/offline detection,
task dispatch, completion, retries, timeouts, cancellation, unauthorized rejection,
cryptographic result integrity verification, and multi-agent coordination.
"""
import time
import pytest

from agent.models import AgentConfig, AgentTask, TaskResult, TaskStatus
from agent.server_hub import AgentServerHub, AgentAuthenticationError
from agent.core import EndpointAgent
from evidence.integrity import EvidenceIntegrityManager, IntegrityManifest
from evidence.schema import CanonicalEvidenceItem, EvidenceType
from runtime import ForensicRuntime


class TestAgentLifecycleAndAuth:
    @pytest.fixture
    def hub(self):
        return AgentServerHub(heartbeat_timeout_seconds=2)

    def test_endpoint_registration_and_identity(self, hub):
        cfg = hub.register_endpoint(hostname="SRV-WIN-01", ip_address="10.0.0.15", os_type="Windows")
        assert cfg.agent_id is not None
        assert cfg.api_token is not None
        assert cfg.hostname == "SRV-WIN-01"

    def test_heartbeat_updates_online_status(self, hub):
        cfg = hub.register_endpoint(hostname="SRV-WIN-02")
        hb_resp = hub.record_heartbeat(cfg.agent_id, cfg.api_token, {"cpu_percent": 12.5})
        assert hb_resp["status"] == "ACK"
        assert hb_resp["agent_status"] == "ONLINE"

    def test_unauthorized_heartbeat_rejected(self, hub):
        cfg = hub.register_endpoint(hostname="SRV-WIN-03")
        with pytest.raises(AgentAuthenticationError):
            hub.record_heartbeat(cfg.agent_id, "invalid-token-12345")

    def test_agent_offline_detection(self, hub):
        # hub heartbeat timeout is 2 seconds
        cfg = hub.register_endpoint(hostname="SRV-STALE-01")
        statuses = hub.check_agent_statuses()
        assert statuses[cfg.agent_id] == "ONLINE"

        # Advance artificial time or wait
        time.sleep(2.1)
        statuses = hub.check_agent_statuses()
        assert statuses[cfg.agent_id] == "OFFLINE"


class TestAgentTaskOrchestration:
    @pytest.fixture
    def hub(self):
        return AgentServerHub()

    def test_task_creation_and_dispatch(self, hub):
        cfg = hub.register_endpoint(hostname="WORKSTATION-01")
        task = hub.create_task(
            investigation_id="CAS-001",
            commands=["SCAN PROCESSES;"],
            assigned_to=cfg.agent_id,
        )
        assert task.status == TaskStatus.ASSIGNED

        dispatched = hub.get_next_task(cfg.agent_id, cfg.api_token)
        assert dispatched is not None
        assert dispatched.task_id == task.task_id
        assert dispatched.status == TaskStatus.RUNNING

    def test_unauthorized_task_fetch_rejected(self, hub):
        cfg = hub.register_endpoint(hostname="WORKSTATION-02")
        with pytest.raises(AgentAuthenticationError):
            hub.get_next_task(cfg.agent_id, "bad-token")

    def test_task_cancellation(self, hub):
        cfg = hub.register_endpoint(hostname="WORKSTATION-03")
        task = hub.create_task(investigation_id="CAS-002", commands=["SCAN NETWORK;"], assigned_to=cfg.agent_id)
        assert hub.cancel_task(task.task_id) is True
        assert task.status == TaskStatus.CANCELLED

    def test_task_retry_mechanism(self, hub):
        cfg = hub.register_endpoint(hostname="WORKSTATION-04")
        task = hub.create_task(investigation_id="CAS-003", commands=["SCAN PROCESSES;"], assigned_to=cfg.agent_id)
        task.max_retries = 2

        assert hub.retry_task_if_eligible(task.task_id) is True
        assert task.retry_count == 1
        assert task.status == TaskStatus.ASSIGNED

        assert hub.retry_task_if_eligible(task.task_id) is True
        assert task.retry_count == 2

        # 3rd retry exceeds max_retries
        assert hub.retry_task_if_eligible(task.task_id) is False
        assert task.status == TaskStatus.FAILED


class TestResultSubmissionAndIntegrity:
    @pytest.fixture
    def hub(self):
        return AgentServerHub()

    def test_valid_result_submission_accepted(self, hub):
        cfg = hub.register_endpoint(hostname="WORKSTATION-05")
        task = hub.create_task(investigation_id="CAS-004", commands=["SCAN PROCESSES;"], assigned_to=cfg.agent_id)

        # Build genuine evidence and manifest
        items = [
            CanonicalEvidenceItem(id="EV-1", host="WORKSTATION-05", type=EvidenceType.PROCESS.value, data={"pid": 4}),
            CanonicalEvidenceItem(id="EV-2", host="WORKSTATION-05", type=EvidenceType.NETWORK.value, data={"pid": 4}),
        ]
        manifest = EvidenceIntegrityManager.create_manifest(items=items, case_id="CAS-004")

        result = TaskResult(
            task_id=task.task_id,
            status=TaskStatus.COMPLETED,
            evidence_items=[it.to_dict() for it in items],
            integrity_manifest=manifest.to_dict(),
        )

        resp = hub.submit_task_result(cfg.agent_id, cfg.api_token, result)
        assert resp["status"] == "ACCEPTED"
        assert resp["verification_status"] == "VALID"
        assert resp["evidence_count"] == 2
        assert task.status == TaskStatus.COMPLETED

    def test_tampered_result_submission_rejected(self, hub):
        cfg = hub.register_endpoint(hostname="WORKSTATION-06")
        task = hub.create_task(investigation_id="CAS-005", commands=["SCAN PROCESSES;"], assigned_to=cfg.agent_id)

        items = [
            CanonicalEvidenceItem(id="EV-1", host="WORKSTATION-06", type=EvidenceType.PROCESS.value, data={"pid": 4}),
        ]
        manifest = EvidenceIntegrityManager.create_manifest(items=items, case_id="CAS-005")

        # Adversary tampers with evidence data after manifest generation
        tampered_items = [it.to_dict() for it in items]
        tampered_items[0]["data"]["pid"] = 999999

        result = TaskResult(
            task_id=task.task_id,
            status=TaskStatus.COMPLETED,
            evidence_items=tampered_items,
            integrity_manifest=manifest.to_dict(),
        )

        resp = hub.submit_task_result(cfg.agent_id, cfg.api_token, result)
        assert resp["status"] == "REJECTED"
        assert resp["verification_status"] == "MODIFIED"
        assert task.status == TaskStatus.FAILED


class TestMultiAgentIntegration:
    def test_one_server_two_agents_coordination(self):
        """Simulate 1 Central Hub + 2 concurrent endpoint agents collecting evidence."""
        hub = AgentServerHub()

        # Agent 1 (Windows Host)
        agent1_cfg = AgentConfig(hostname="HOST-ALPHA", os_type="Windows")
        agent1 = EndpointAgent(config=agent1_cfg)
        assert agent1.register(hub) is True

        # Agent 2 (Linux Host)
        agent2_cfg = AgentConfig(hostname="HOST-BRAVO", os_type="Linux")
        agent2 = EndpointAgent(config=agent2_cfg)
        assert agent2.register(hub) is True

        # Central server dispatches task to Agent 1
        t1 = hub.create_task(investigation_id="CAS-ALPHA", commands=["SCAN PROCESSES;"], assigned_to=agent1.config.agent_id)

        # Central server dispatches task to Agent 2
        t2 = hub.create_task(investigation_id="CAS-BRAVO", commands=["SCAN NETWORK;"], assigned_to=agent2.config.agent_id)

        # Agent 1 executes lifecycle cycle
        res1 = agent1.run_cycle(hub)
        assert res1 is not None
        assert res1["status"] == "ACCEPTED"
        assert t1.status == TaskStatus.COMPLETED

        # Agent 2 executes lifecycle cycle
        res2 = agent2.run_cycle(hub)
        assert res2 is not None
        assert res2["status"] == "ACCEPTED"
        assert t2.status == TaskStatus.COMPLETED

