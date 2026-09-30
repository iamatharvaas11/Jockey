"""
JOCKY IOC Rule Engine
Evaluates CanonicalEvidenceItem records against externalized, explainable detection rules.
Produces structured IOCFinding instances without claiming certainty.
"""
import json
import os
import re
from typing import Any, Dict, List, Optional

from analysis.ioc.rule import IOCRule, RuleValidator
from analysis.models import IOCFinding
from evidence.schema import CanonicalEvidenceItem, EvidenceType


class IOCEngine:
    """Configurable IOC and behavioral rule engine evaluating canonical evidence."""

    def __init__(self, rules_path: Optional[str] = None, rules: Optional[List[IOCRule]] = None):
        self._rules: List[IOCRule] = []
        self._compiled_regexes: Dict[str, List[re.Pattern]] = {}

        if rules is not None:
            for r in rules:
                self.add_rule(r)
        elif rules_path and os.path.exists(rules_path):
            self.load_rules_from_file(rules_path)
        else:
            default_path = os.path.join(os.path.dirname(__file__), "default_rules.json")
            if os.path.exists(default_path):
                self.load_rules_from_file(default_path)

    @property
    def rules(self) -> List[IOCRule]:
        return list(self._rules)

    def add_rule(self, rule: IOCRule):
        """Add an IOCRule to the engine."""
        self._rules.append(rule)
        # Precompile regexes safely if present
        patterns = rule.conditions.get("regex_patterns", []) if isinstance(rule.conditions, dict) else []
        if patterns and isinstance(patterns, list):
            compiled = []
            for p in patterns:
                try:
                    compiled.append(re.compile(p))
                except (re.error, TypeError):
                    pass
            if compiled:
                self._compiled_regexes[rule.rule_id] = compiled

    def load_rules_from_file(self, file_path: str):
        """Load and validate rules from a JSON configuration file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, ValueError):
            return

        raw_rules = data.get("rules", []) if isinstance(data, dict) else []
        if isinstance(raw_rules, list):
            for r_dict in raw_rules:
                if isinstance(r_dict, dict):
                    try:
                        rule = IOCRule.from_dict(r_dict)
                        self.add_rule(rule)
                    except Exception:
                        continue

    def evaluate_item(
        self,
        item: CanonicalEvidenceItem,
        process_map: Optional[Dict[int, CanonicalEvidenceItem]] = None,
    ) -> List[IOCFinding]:
        """Evaluate an individual evidence item against all matching enabled rules."""
        findings = []
        item_type = item.type.lower()
        data = item.data or {}

        for rule in self._rules:
            if not rule.enabled:
                continue

            if item_type not in rule.evidence_types:
                continue

            matched, reason, matched_snippet = self._check_rule_match(rule, item, data, process_map)
            if matched:
                findings.append(IOCFinding(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    reason=reason,
                    host=item.host,
                    timestamp=item.timestamp,
                    evidence_ids=[item.id],
                    matched_data=matched_snippet,
                    explanation=rule.explanation,
                ))

        return findings

    def evaluate_all(self, items: List[CanonicalEvidenceItem]) -> List[IOCFinding]:
        """Evaluate a collection of evidence items, constructing context for parent-child inspection."""
        # Build process map for parent-child evaluations
        process_map: Dict[int, CanonicalEvidenceItem] = {}
        for it in items:
            if it.type == EvidenceType.PROCESS.value and isinstance(it.data, dict):
                pid = it.data.get("pid")
                if isinstance(pid, int):
                    process_map[pid] = it

        findings = []
        for it in items:
            findings.extend(self.evaluate_item(it, process_map=process_map))
        return findings

    def _check_rule_match(
        self,
        rule: IOCRule,
        item: CanonicalEvidenceItem,
        data: Dict[str, Any],
        process_map: Optional[Dict[int, CanonicalEvidenceItem]],
    ) -> tuple[bool, str, Dict[str, Any]]:
        conds = rule.conditions

        # 1. Hash match condition
        if conds.get("target_hashes"):
            target_hashes = {str(h).lower() for h in conds["target_hashes"] if h is not None}
            fields_to_check = conds.get("hash_match_fields") or ["sha256", "md5", "exe_hash"]
            for f in fields_to_check:
                val = str(data.get(f) or "").lower()
                if val and val in target_hashes:
                    return True, f"Matched known threat hash ({val}) in field '{f}'", {f: val}

        # 2. Commandline or path regex match
        if rule.rule_id in self._compiled_regexes:
            target_field = conds.get("field", "cmdline")
            text_to_test = str(data.get(target_field) or "")
            if text_to_test:
                for pat in self._compiled_regexes[rule.rule_id]:
                    m = pat.search(text_to_test)
                    if m:
                        return True, f"Pattern match '{pat.pattern}' in '{target_field}'", {
                            "field": target_field,
                            "match": m.group(0),
                            "full_text": text_to_test,
                        }

        # 3. Parent-Child process relationship match
        if conds.get("parent_child_pairs") and process_map:
            ppid = data.get("ppid")
            c_name = str(data.get("name") or "").lower()
            if ppid in process_map:
                parent_proc = process_map[ppid]
                p_name = str(parent_proc.data.get("name") or "").lower()
                for pair in conds["parent_child_pairs"]:
                    if pair.get("parent", "").lower() == p_name and pair.get("child", "").lower() == c_name:
                        return True, f"Suspicious parent '{p_name}' (PID {ppid}) spawned child '{c_name}' (PID {data.get('pid')})", {
                            "parent": parent_proc.data,
                            "child": data,
                        }

        # 4. Remote IP connection match
        if conds.get("target_ips"):
            target_ips = {str(ip) for ip in conds["target_ips"] if ip is not None}
            f_name = conds.get("field", "remote_ip")
            ip_val = str(data.get(f_name) or "")
            if ip_val and ip_val in target_ips:
                return True, f"Connection to known suspicious IP '{ip_val}'", {f_name: ip_val}

        # 5. Event ID and message match
        if conds.get("event_ids"):
            e_id = data.get("event_id")
            if e_id in conds["event_ids"]:
                return True, f"Matched event ID {e_id}", {"event_id": e_id}

        if conds.get("message_regex"):
            msg = str(data.get("message") or "")
            try:
                if msg and re.search(conds["message_regex"], msg):
                    return True, f"Event message matched pattern '{conds['message_regex']}'", {"message": msg[:150]}
            except re.error:
                pass

        return False, "", {}

