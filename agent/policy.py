"""Safety policy for centrally dispatched JOCKY endpoint tasks.

Endpoint agents are evidence collectors, not remote administration or execution
agents. This module therefore accepts only explicitly enumerated, read-only
collection requests and rejects unsupported requests and unsafe task text.
"""
from __future__ import annotations

from typing import Iterable, Tuple


class TaskCommandRejected(ValueError):
    """Raised when a central task falls outside JOCKY's DFIR-only scope."""


# This defence-in-depth list keeps future command-parser changes from widening
# JOCKY's scope. The allow-list below remains the actual authority.
PROHIBITED_TECHNIQUE_TERMS = frozenset(
    {
        "API UNHOOK",
        "BYPASS AV",
        "BYPASS EDR",
        "DIRECT SYSCALL",
        "DISABLE ANTIVIRUS",
        "DISABLE EDR",
        "DLL INJECTION",
        "DOMAIN FRONTING",
        "EDR BYPASS",
        "KERNEL TAMPERING",
        "PERSISTENCE",
        "PRIVILEGE ESCALATION",
        "PROCESS HOLLOWING",
        "REFLECTIVE DLL",
        "SOCKS5",
        "THREAD HIJACKING",
        "VULNERABLE DRIVER",
    }
)

# Each accepted operation maps only to a local, read-only forensic collector.
SAFE_SCAN_COMMANDS = {
    "SCAN PROCESSES": ("process",),
    "SCAN FILES": ("files",),
    "SCAN NETWORK": ("network",),
    "SCAN EVENTLOGS": ("eventlogs",),
    "SCAN REGISTRY": ("registry",),
    "SCAN ALL": ("process", "files", "network", "eventlogs", "registry"),
}


def _normalise(command: str) -> str:
    if not isinstance(command, str) or not command.strip():
        raise TaskCommandRejected("Endpoint task commands must be non-empty strings.")
    return " ".join(command.strip().rstrip(";").upper().split())


def validate_task_command(command: str) -> str:
    """Return a canonical safe command or raise a scope-specific exception."""
    normalised = _normalise(command)
    if any(term in normalised for term in PROHIBITED_TECHNIQUE_TERMS):
        raise TaskCommandRejected(
            "Rejected endpoint task: JOCKY agents collect forensic evidence and "
            "do not support security-control evasion, tampering, persistence, or escalation."
        )
    if normalised not in SAFE_SCAN_COMMANDS:
        allowed = ", ".join(SAFE_SCAN_COMMANDS)
        raise TaskCommandRejected(
            f"Unsupported endpoint task '{normalised}'. Allowed read-only tasks: {allowed}."
        )
    return normalised


def validate_task_commands(commands: Iterable[str]) -> Tuple[str, ...]:
    """Validate a non-empty sequence of endpoint collection commands."""
    try:
        validated = tuple(validate_task_command(command) for command in commands)
    except TypeError as exc:
        raise TaskCommandRejected("Endpoint task commands must be an iterable of strings.") from exc
    if not validated:
        raise TaskCommandRejected("An endpoint task must contain at least one read-only collection command.")
    return validated
