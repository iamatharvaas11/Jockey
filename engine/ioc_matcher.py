import re
from typing import Any, Dict, List, Optional
from analysis.ioc import IOCEngine, IOCRule


class IOCMatcher:
    """
    IOC Matcher bridge component.
    Maintains compatibility with legacy caller interfaces while delegating
    to the configurable analysis.ioc.IOCEngine.
    """
    def __init__(self, hash_iocs=None, ip_iocs=None, domain_iocs=None, pattern_iocs=None):
        self.engine = IOCEngine()
        self.hash_iocs = set(hash_iocs or ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"])
        self.ip_iocs = set(ip_iocs or ["10.0.0.99", "192.168.1.100"])
        self.domain_iocs = set(domain_iocs or ["evil.com", "malicious.net"])
        
        # Regex patterns for LOLBins and suspicious command lines
        self.pattern_iocs = pattern_iocs or [
            r"(?i)powershell.*-enc",
            r"(?i)certutil.*-urlcache",
            r"(?i)bitsadmin.*/transfer",
            r"(?i)regsvr32.*/i:",
            r"(?i)mshta.*http",
            r"(?i)wmic.*process call create"
        ]
        self.compiled_patterns = []
        for p in self.pattern_iocs:
            try:
                self.compiled_patterns.append(re.compile(p))
            except re.error:
                pass

    def match_hash(self, file_hash: str) -> dict | None:
        if file_hash and file_hash in self.hash_iocs:
            return {"type": "hash_match", "value": file_hash, "severity": "high"}
        return None

    def match_ip(self, ip: str) -> dict | None:
        if ip and ip in self.ip_iocs:
            return {"type": "ip_match", "value": ip, "severity": "high"}
        return None

    def match_domain(self, domain: str) -> dict | None:
        if domain and domain in self.domain_iocs:
            return {"type": "domain_match", "value": domain, "severity": "medium"}
        return None

    def match_command_line(self, cmdline: str) -> list[dict]:
        matches = []
        if cmdline:
            for i, p in enumerate(self.compiled_patterns):
                if p.search(cmdline):
                    matches.append({"type": "cmdline_pattern_match", "value": cmdline, "pattern": self.pattern_iocs[i], "severity": "high"})
        return matches

    def scan_processes(self, processes: list) -> list[dict]:
        results = []
        for p in processes:
            h_match = self.match_hash(p.get('exe_hash'))
            if h_match:
                results.append({"process": p, "match": h_match})
                
            cmd_matches = self.match_command_line(p.get('cmdline'))
            for m in cmd_matches:
                results.append({"process": p, "match": m})
        return results

    def scan_connections(self, connections: list) -> list[dict]:
        results = []
        for c in connections:
            rem_ip = c.get('remote_ip')
            loc_ip = c.get('local_ip')
            
            ip_match = self.match_ip(rem_ip) or self.match_ip(loc_ip)
            if ip_match:
                results.append({"connection": c, "match": ip_match})
        return results

    def scan_all(self, processes, connections, files=None) -> dict:
        results = {
            "process_matches": self.scan_processes(processes or []),
            "connection_matches": self.scan_connections(connections or []),
            "file_matches": []
        }
        
        if files:
            for f in files:
                h_match_sha = self.match_hash(f.get('sha256'))
                h_match_md5 = self.match_hash(f.get('md5'))
                if h_match_sha:
                    results["file_matches"].append({"file": f, "match": h_match_sha})
                elif h_match_md5:
                    results["file_matches"].append({"file": f, "match": h_match_md5})
                    
        return results
