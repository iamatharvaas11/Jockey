"""Tests for the defensive allow-list on centrally dispatched endpoint tasks."""
import pytest

from agent.policy import TaskCommandRejected, validate_task_command, validate_task_commands
from agent.server_hub import AgentServerHub


def test_safe_scan_command_is_normalised_and_accepted():
    assert validate_task_command("  scan   processes;  ") == "SCAN PROCESSES"


@pytest.mark.parametrize(
    "command",
    [
        "RUN diagnostics;",
        "SCAN PROCESSES; DISABLE EDR;",
        "PROCESS HOLLOWING;",
        "SCAN NETWORK; DOMAIN FRONTING;",
    ],
)
def test_unsafe_or_unsupported_endpoint_commands_are_rejected(command):
    with pytest.raises(TaskCommandRejected):
        validate_task_command(command)


def test_empty_endpoint_task_is_rejected():
    with pytest.raises(TaskCommandRejected):
        validate_task_commands([])


def test_hub_rejects_unsafe_task_before_dispatch():
    hub = AgentServerHub()
    with pytest.raises(TaskCommandRejected):
        hub.create_task("CASE-001", ["DLL INJECTION;"])
