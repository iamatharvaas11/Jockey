"""
JOCKY Network Collector
Collects active network sockets, listening ports, and remote connections,
with process association and honest platform capability handling.
"""
import socket
import sys
from typing import Dict, List, Optional

import psutil

from .base import BaseCollector, CollectorResult, CollectorStatus


class NetworkCollector(BaseCollector):
    """Forensic network collector for TCP/UDP connections and interfaces."""

    def __init__(self):
        super().__init__(name="network_collector")

    def collect(self, **kwargs) -> CollectorResult:
        """
        Collect active network connections.
        Returns a normalized CollectorResult envelope.
        """
        return self.collect_connections(**kwargs)

    def collect_connections(self, kind: str = "inet") -> CollectorResult:
        """Collect established, listening, and active network connections."""
        connections = []
        errors = []
        limitations = []
        unassociated_pids = 0

        try:
            conns = psutil.net_connections(kind=kind)
        except (psutil.AccessDenied, PermissionError):
            limitations.append(
                "Elevated/root privileges required: Access was denied inspecting network sockets."
            )
            return CollectorResult(
                type="network",
                source=sys.platform,
                status=CollectorStatus.FAILED,
                data=[],
                errors=["PermissionDenied: Root/Administrator privileges required to query system connections."],
                limitations=limitations,
            )
        except Exception as e:
            return CollectorResult(
                type="network",
                source=sys.platform,
                status=CollectorStatus.FAILED,
                data=[],
                errors=[f"Network socket query failed: {str(e)}"],
                limitations=limitations,
            )

        for conn in conns:
            try:
                laddr = conn.laddr
                raddr = conn.raddr
                local_ip = laddr.ip if laddr else ""
                local_port = laddr.port if laddr else 0
                remote_ip = raddr.ip if raddr else ""
                remote_port = raddr.port if raddr else 0

                # Resolve process association if PID is provided
                pid = conn.pid
                proc_name = ""
                if pid:
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = ""
                else:
                    unassociated_pids += 1

                connections.append({
                    "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": conn.status if conn.status else "UNKNOWN",
                    "pid": pid or 0,
                    "process_name": proc_name,
                })

            except Exception as e:
                errors.append(f"Error parsing socket record: {str(e)}")

        if unassociated_pids > 0:
            limitations.append(
                f"{unassociated_pids} connections have no process PID associated (insufficient privileges or kernel sockets)."
            )

        status = CollectorStatus.SUCCESS
        if errors and not connections:
            status = CollectorStatus.FAILED
        elif errors or limitations:
            status = CollectorStatus.PARTIAL

        return CollectorResult(
            type="network",
            source=sys.platform,
            status=status,
            data=connections,
            errors=errors,
            limitations=limitations,
        )

    def collect_interfaces(self) -> CollectorResult:
        """Collect network interface configuration and link status."""
        interfaces = []
        errors = []

        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for name, addresses in addrs.items():
                if_stats = stats.get(name)
                ips = [addr.address for addr in addresses if addr.family == socket.AF_INET]
                macs = [addr.address for addr in addresses if addr.family == psutil.AF_LINK]
                interfaces.append({
                    "name": name,
                    "ips": ips,
                    "macs": macs,
                    "is_up": if_stats.isup if if_stats else False,
                    "speed_mbps": if_stats.speed if if_stats else 0,
                })
        except Exception as e:
            errors.append(f"Failed to query network interfaces: {str(e)}")

        return CollectorResult(
            type="network_interfaces",
            source=sys.platform,
            status=CollectorStatus.SUCCESS if not errors else CollectorStatus.FAILED,
            data=interfaces,
            errors=errors,
        )
