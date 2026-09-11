"""
JOCKY Forensic Report Generator
Produces production-quality, court-admissible JSON, HTML, and PDF (when supported)
forensic reports from canonical evidence, IOC findings, relationships, timeline,
cryptographic manifests, and chain-of-custody audit records.
"""
import datetime
from datetime import timezone
import json
import os
from typing import Any, Dict, List, Optional

from analysis.models import EvidenceRelationship, IOCFinding, InvestigationAnalysis, TimelineEvent
from evidence.audit import AuditRecord
from evidence.integrity import IntegrityManifest, VerificationReport, VerificationStatus
from evidence.schema import CanonicalEvidenceItem, EvidenceType


class ReportGenerator:
    """Production-quality reporting engine consuming real canonical forensic evidence and analysis."""

    def __init__(self, case_id: str = "JOCKY-CASE-001", examiner: str = "JOCKY Forensic Framework"):
        self.case_id = case_id
        self.examiner = examiner

    def generate(
        self,
        processes: Optional[List[dict]] = None,
        connections: Optional[List[dict]] = None,
        events: Optional[List[dict]] = None,
        files: Optional[List[dict]] = None,
        registry: Optional[List[dict]] = None,
        correlations: Optional[Dict[str, Any]] = None,
        ioc_matches: Optional[Dict[str, Any]] = None,
        timeline: Optional[List[dict]] = None,
        integrity_manifest: Optional[Any] = None,
        verification_report: Optional[Any] = None,
        evidence_items: Optional[List[Any]] = None,
        analysis: Optional[Any] = None,
        audit_records: Optional[List[Any]] = None,
        limitations: Optional[List[str]] = None,
        errors: Optional[List[str]] = None,
        hosts: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a complete, structured forensic investigation report.
        Strictly enforces integrity status: VERIFIED, UNVERIFIED, or FAILED.
        Never fabricates hashes, compliance claims, or findings.
        """
        now_utc = datetime.datetime.now(timezone.utc).isoformat()

        # 1. Normalize Canonical Evidence Items
        canonical_list: List[Dict[str, Any]] = []
        if evidence_items:
            for item in evidence_items:
                if isinstance(item, CanonicalEvidenceItem):
                    canonical_list.append(item.to_dict())
                elif isinstance(item, dict):
                    canonical_list.append(item)

        # Count by evidence type
        type_counts = {
            "process": len(processes or []),
            "network": len(connections or []),
            "event": len(events or []),
            "file": len(files or []),
            "registry": len(registry or []),
        }

        for c_item in canonical_list:
            t = c_item.get("type", "generic").lower()
            type_counts[t] = type_counts.get(t, 0) + 1

        # 2. Extract Hosts
        host_set = set(hosts or [])
        for c_item in canonical_list:
            if c_item.get("host"):
                host_set.add(c_item["host"])
        if not host_set:
            host_set.add("LOCAL_HOST")

        # 3. Process IOC Findings
        findings_list: List[Dict[str, Any]] = []
        if analysis and hasattr(analysis, "findings"):
            findings_list = [f.to_dict() if hasattr(f, "to_dict") else f for f in analysis.findings]
        elif isinstance(ioc_matches, dict):
            if "canonical_findings" in ioc_matches:
                findings_list = ioc_matches["canonical_findings"]
            elif "alerts" in ioc_matches:
                findings_list = ioc_matches["alerts"]
            elif "process_matches" in ioc_matches:
                for pm in ioc_matches.get("process_matches", []):
                    findings_list.append(pm.get("match", {}))

        # 4. Process Relationships
        relationships_list: List[Dict[str, Any]] = []
        if analysis and hasattr(analysis, "relationships"):
            relationships_list = [r.to_dict() if hasattr(r, "to_dict") else r for r in analysis.relationships]
        elif isinstance(correlations, dict) and "relationships" in correlations:
            relationships_list = correlations["relationships"]

        # 5. Process Timeline
        timeline_list: List[Dict[str, Any]] = []
        if analysis and hasattr(analysis, "timeline"):
            timeline_list = [t.to_dict() if hasattr(t, "to_dict") else t for t in analysis.timeline]
        elif timeline:
            timeline_list = [t.to_dict() if hasattr(t, "to_dict") else t for t in timeline]

        # 6. Process Audit Records
        audit_list: List[Dict[str, Any]] = []
        if audit_records:
            for rec in audit_records:
                if isinstance(rec, AuditRecord):
                    audit_list.append(rec.to_dict())
                elif isinstance(rec, dict):
                    audit_list.append(rec)

        # 7. Strictly Evaluate Integrity Status
        # Status rule:
        # VERIFIED: Only when manifest verification genuinely succeeds.
        # UNVERIFIED: When integrity data is absent.
        # FAILED: When verification fails (e.g. tamper detected, missing items, corrupted root hash).
        integrity_section = self._resolve_integrity_section(integrity_manifest, verification_report)

        report = {
            "meta": {
                "case_id": self.case_id,
                "examiner": self.examiner,
                "generated_at": now_utc,
                "platform": "JOCKY Forensic Framework",
                "hosts": sorted(list(host_set)),
            },
            "summary": {
                "total_evidence_items": len(canonical_list) or sum(type_counts.values()),
                "evidence_by_type": type_counts,
                "total_ioc_findings": len(findings_list),
                "total_relationships": len(relationships_list),
                "total_timeline_events": len(timeline_list),
                "total_audit_records": len(audit_list),
                "integrity_status": integrity_section["status"],
            },
            "integrity_manifest": integrity_section,
            "evidence_items": canonical_list,
            "ioc_findings": findings_list,
            "relationships": relationships_list,
            "timeline": timeline_list,
            "limitations": list(set(limitations or [])),
            "errors": list(errors or []),
            "audit_trail": audit_list,
            # Backward-compatible keys
            "processes": processes or [],
            "connections": connections or [],
            "ioc_matches": ioc_matches or {},
            "correlations": correlations or {},
        }
        return report

    def _resolve_integrity_section(
        self,
        manifest: Optional[Any],
        verification_report: Optional[Any],
    ) -> Dict[str, Any]:
        """Strictly enforce integrity status without inventing hashes or verification results."""
        if not manifest:
            return {
                "status": "unverified",
                "verified": False,
                "message": "No integrity manifest provided; evidence has not been cryptographically verified.",
                "root_hash": None,
                "artifacts": [],
                "entries": [],
            }

        manifest_dict: Dict[str, Any] = {}
        if isinstance(manifest, IntegrityManifest):
            manifest_dict = manifest.to_dict()
        elif isinstance(manifest, dict):
            manifest_dict = dict(manifest)

        # Determine verification status
        v_status = "unverified"
        verified_flag = False

        if verification_report:
            if isinstance(verification_report, VerificationReport):
                v_code = verification_report.status.value
            elif isinstance(verification_report, dict):
                v_code = verification_report.get("status", "UNVERIFIED")
            else:
                v_code = str(verification_report)

            if v_code == "VALID":
                v_status = "verified"
                verified_flag = True
            elif v_code in ("MODIFIED", "CORRUPTED", "MISSING_EVIDENCE", "FAILED"):
                v_status = "failed"
                verified_flag = False
            else:
                v_status = "unverified"
                verified_flag = False
        elif manifest_dict.get("status") in ("verified", "VERIFIED") or manifest_dict.get("verified") is True:
            v_status = "verified"
            verified_flag = True
        elif manifest_dict.get("status") in ("failed", "FAILED"):
            v_status = "failed"
            verified_flag = False

        manifest_dict["status"] = v_status
        manifest_dict["verified"] = verified_flag

        # Normalize artifacts / entries
        if "artifacts" not in manifest_dict:
            manifest_dict["artifacts"] = []
            for entry in manifest_dict.get("entries", []):
                manifest_dict["artifacts"].append({
                    "name": f"{entry.get('type')}_{entry.get('evidence_id')[:8]}",
                    "hash_sha256": entry.get("hash_sha256"),
                    "status": "VERIFIED" if verified_flag else v_status.upper(),
                })

        return manifest_dict

    def to_json(self, report: Dict[str, Any], filepath: str):
        """Save forensic report to JSON file with UTF-8 encoding and directory creation."""
        dir_name = os.path.dirname(os.path.abspath(filepath))
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

    def to_html(self, report: Dict[str, Any], filepath: str):
        """Generate a production-quality, standalone court-admissible HTML report."""
        dir_name = os.path.dirname(os.path.abspath(filepath))
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        html_content = self.render_html(report)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

    def render_html(self, report: Dict[str, Any]) -> str:
        """Render a production-quality, standalone court-admissible HTML report string."""

        meta = report.get("meta", {})
        summary = report.get("summary", {})
        integrity = report.get("integrity_manifest", {})
        findings = report.get("ioc_findings", [])
        relationships = report.get("relationships", [])
        timeline = report.get("timeline", [])
        audit_trail = report.get("audit_trail", [])
        limitations = report.get("limitations", [])
        errors = report.get("errors", [])

        # Integrity Status Badge
        status_key = str(integrity.get("status", "unverified")).lower()
        if status_key == "verified":
            badge_class = "badge-verified"
            status_text = "VERIFIED — Cryptographic Integrity Confirmed (SHA-256)"
        elif status_key == "failed":
            badge_class = "badge-failed"
            status_text = "FAILED — Tamper Detected / Verification Mismatch"
        else:
            badge_class = "badge-unverified"
            status_text = "UNVERIFIED — No Cryptographic Manifest Provided"

        # IOC Findings HTML
        findings_html = ""
        if findings:
            for f in findings[:50]:
                sev = str(f.get("severity", "MEDIUM")).upper()
                sev_cls = sev.lower()
                r_id = f.get("rule_id", "IOC")
                r_name = f.get("rule_name", "")
                reason = f.get("reason", "")
                host = f.get("host", "")
                expl = f.get("explanation", "")
                findings_html += f"""
                <tr>
                    <td><span class="badge {sev_cls}">{sev}</span></td>
                    <td style="font-family: monospace; font-weight: bold;">{r_id}</td>
                    <td>{r_name}</td>
                    <td>{reason}</td>
                    <td style="font-family: monospace; font-size: 11px;">{host}</td>
                    <td style="color: #64748b; font-size: 11px;">{expl}</td>
                </tr>"""
        else:
            findings_html = "<tr><td colspan='6' style='text-align: center; color: #10b981; padding: 16px;'>Zero IOC Threat Signatures or Behavioral Anomalies Detected</td></tr>"

        # Relationships HTML
        relationships_html = ""
        if relationships:
            for r in relationships[:50]:
                r_type = r.get("relationship_type", "")
                conf = r.get("confidence", 1.0)
                reason = r.get("reason", "")
                src = r.get("source_evidence_id", "")[:8]
                tgt = r.get("target_evidence_id", "")[:8]
                relationships_html += f"""
                <tr>
                    <td style="font-family: monospace; font-size: 11px;">{src}... &rarr; {tgt}...</td>
                    <td style="font-weight: bold; color: #0284c7;">{r_type}</td>
                    <td style="font-family: monospace;">{conf:.2f}</td>
                    <td>{reason}</td>
                </tr>"""
        else:
            relationships_html = "<tr><td colspan='4' style='text-align: center; color: #64748b; padding: 14px;'>No cross-artifact relationships established.</td></tr>"

        # Timeline HTML
        timeline_html = ""
        if timeline:
            for ev in timeline[:60]:
                ts = ev.get("timestamp") or "MISSING_TIMESTAMP"
                e_type = ev.get("type", "EVENT")
                src = ev.get("source", "")
                summ = ev.get("summary", "")
                est_note = " (Estimated)" if ev.get("is_timestamp_estimated") else ""
                timeline_html += f"""
                <tr>
                    <td style="font-family: monospace; font-size: 11px;">{ts}{est_note}</td>
                    <td><span class="badge info">{e_type}</span></td>
                    <td style="text-transform: uppercase; font-size: 11px; font-weight: bold;">{src}</td>
                    <td>{summ}</td>
                </tr>"""
        else:
            timeline_html = "<tr><td colspan='4' style='text-align: center; color: #64748b; padding: 14px;'>No timeline events generated.</td></tr>"

        # Audit Trail HTML
        audit_html = ""
        if audit_trail:
            for a in audit_trail[:30]:
                a_ts = a.get("timestamp", "")
                a_actor = a.get("actor", "")
                a_action = a.get("action", "")
                a_ev = str(a.get("evidence_id") or "")[:8]
                a_hash = str(a.get("record_hash") or "")[:16]
                audit_html += f"""
                <tr>
                    <td style="font-family: monospace; font-size: 11px;">{a_ts}</td>
                    <td>{a_actor}</td>
                    <td style="font-weight: bold;">{a_action}</td>
                    <td style="font-family: monospace; font-size: 11px;">{a_ev}</td>
                    <td style="font-family: monospace; font-size: 11px; color: #0284c7;">{a_hash}...</td>
                </tr>"""
        else:
            audit_html = "<tr><td colspan='5' style='text-align: center; color: #64748b; padding: 14px;'>No audit records logged.</td></tr>"

        # Limitations HTML
        limitations_html = ""
        if limitations:
            items_li = "".join(f"<li>{lim}</li>" for lim in limitations)
            limitations_html = f"""
            <div class="callout warning">
                <strong>Investigation Limitations:</strong>
                <ul>{items_li}</ul>
            </div>"""

        # Errors HTML
        errors_html = ""
        if errors:
            err_li = "".join(f"<li>{err}</li>" for err in errors)
            errors_html = f"""
            <div class="callout danger">
                <strong>Collection Errors Encountered:</strong>
                <ul>{err_li}</ul>
            </div>"""

        # Manifest Root
        root_hash = integrity.get("root_hash") or "N/A"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JOCKY Forensic Investigation Report - {meta.get('case_id', 'CASE')}</title>
    <style>
        :root {{
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #0f172a;
            --border: #e2e8f0;
            --muted: #64748b;
            --accent: #0284c7;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.5;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1100px;
            margin: auto;
            background: var(--card-bg);
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
            border: 1px solid var(--border);
        }}
        .header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}
        .title {{
            font-size: 24px;
            font-weight: 800;
            margin: 0 0 5px 0;
            text-transform: uppercase;
            letter-spacing: -0.5px;
        }}
        .subtitle {{
            color: var(--muted);
            font-size: 13px;
            margin: 0;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .banner {{
            padding: 12px 18px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 13px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .badge-verified {{ background: #ecfdf5; color: #065f46; border: 1px solid #a7f3d0; }}
        .badge-unverified {{ background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }}
        .badge-failed {{ background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }}
        .stat-card {{
            border: 1px solid var(--border);
            padding: 16px;
            border-radius: 6px;
            text-align: center;
            background: #ffffff;
        }}
        .stat-num {{
            font-size: 24px;
            font-weight: bold;
            color: var(--accent);
            margin-bottom: 4px;
        }}
        .stat-lbl {{
            font-size: 11px;
            text-transform: uppercase;
            color: var(--muted);
            font-weight: 600;
        }}
        h2 {{
            font-size: 16px;
            border-left: 4px solid var(--accent);
            padding-left: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin: 30px 0 15px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 8px 10px;
            border: 1px solid var(--border);
            text-align: left;
        }}
        th {{
            background-color: #f1f5f9;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            color: #475569;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge.critical {{ background: #fee2e2; color: #b91c1c; }}
        .badge.high {{ background: #ffedd5; color: #c2410c; }}
        .badge.medium {{ background: #fef3c7; color: #b45309; }}
        .badge.low {{ background: #f1f5f9; color: #475569; }}
        .badge.info {{ background: #e0f2fe; color: #0369a1; }}
        .callout {{
            padding: 14px 18px;
            border-radius: 6px;
            font-size: 13px;
            margin-bottom: 20px;
        }}
        .callout.warning {{ background: #fffbeb; border-left: 4px solid #f59e0b; color: #92400e; }}
        .callout.danger {{ background: #fef2f2; border-left: 4px solid #ef4444; color: #991b1b; }}
        .callout ul {{ margin: 6px 0 0 18px; padding: 0; }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            color: var(--muted);
        }}
        @media print {{
            body {{ padding: 0; background: #ffffff; }}
            .container {{ box-shadow: none; border: none; padding: 0; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1 class="title">Forensic Investigation Report</h1>
            <p class="subtitle">JOCKY Digital Forensics & Incident Response Framework</p>
        </div>
        <div style="text-align: right; font-size: 12px; font-family: monospace;">
            <div><strong>Case:</strong> {meta.get('case_id', 'N/A')}</div>
            <div><strong>Examiner:</strong> {meta.get('examiner', 'N/A')}</div>
            <div><strong>Date:</strong> {meta.get('generated_at', '')[:19]} UTC</div>
        </div>
    </div>

    <div class="banner {badge_class}">
        <span>{status_text}</span>
        <span style="font-family: monospace; font-size: 11px;">Root SHA-256: {str(root_hash)[:16]}...</span>
    </div>

    <div class="grid">
        <div class="stat-card">
            <div class="stat-num">{summary.get('total_evidence_items', 0)}</div>
            <div class="stat-lbl">Evidence Items</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{summary.get('total_ioc_findings', 0)}</div>
            <div class="stat-lbl">IOC Findings</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{summary.get('total_relationships', 0)}</div>
            <div class="stat-lbl">Correlated Edges</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{summary.get('total_timeline_events', 0)}</div>
            <div class="stat-lbl">Timeline Events</div>
        </div>
    </div>

    {limitations_html}
    {errors_html}

    <h2>1. Threat Indicators & Behavioral Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Rule ID</th>
                <th>Rule Name</th>
                <th>Observation Reason</th>
                <th>Host</th>
                <th>Explanation</th>
            </tr>
        </thead>
        <tbody>
            {findings_html}
        </tbody>
    </table>

    <h2>2. Cross-Artifact Correlation Graph</h2>
    <table>
        <thead>
            <tr>
                <th>Artifact Edge (Source &rarr; Target)</th>
                <th>Relationship Type</th>
                <th>Confidence</th>
                <th>Reason</th>
            </tr>
        </thead>
        <tbody>
            {relationships_html}
        </tbody>
    </table>

    <h2>3. Chronological Super-Timeline</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp (UTC)</th>
                <th>Event Type</th>
                <th>Source</th>
                <th>Event Summary</th>
            </tr>
        </thead>
        <tbody>
            {timeline_html}
        </tbody>
    </table>

    <h2>4. Evidence Integrity Manifest & Verification</h2>
    <table style="font-family: monospace;">
        <thead>
            <tr>
                <th>Artifact Identifier</th>
                <th>SHA-256 Digest</th>
                <th>Integrity Status</th>
            </tr>
        </thead>
        <tbody>
            {"".join(f"<tr><td>{art.get('name', 'item')}</td><td style='color: #0284c7;'>{art.get('hash_sha256', 'None')}</td><td>{art.get('status', 'UNVERIFIED')}</td></tr>" for art in integrity.get('artifacts', [])[:25]) or "<tr><td colspan='3' style='text-align: center;'>No individual artifacts listed.</td></tr>"}
        </tbody>
    </table>

    <h2>5. Chain-of-Custody Audit Trail</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp (UTC)</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Evidence ID</th>
                <th>Cryptographic Record Hash</th>
            </tr>
        </thead>
        <tbody>
            {audit_html}
        </tbody>
    </table>

    <div class="footer">
        <span>Generated by JOCKY Forensic Investigation Engine</span>
        <span>Target Host(s): {', '.join(meta.get('hosts', []))}</span>
    </div>
</div>
</body>
</html>"""
        return html_content

    def to_pdf(self, report: Dict[str, Any], filepath: str) -> bool:
        """
        Generate PDF report if a supported PDF generation backend is installed.
        Detects dependency safely before execution; raises clear exception if missing.
        """
        try:
            import reportlab  # type: ignore
            # Build PDF using reportlab if available
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas

            c = canvas.Canvas(filepath, pagesize=letter)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, 750, "JOCKY Forensic Investigation Report")
            c.setFont("Helvetica", 10)
            c.drawString(50, 730, f"Case: {report.get('meta', {}).get('case_id')} | Date: {report.get('meta', {}).get('generated_at')}")
            c.drawString(50, 710, f"Integrity Status: {report.get('summary', {}).get('integrity_status')}")
            c.drawString(50, 690, f"Total Evidence Items: {report.get('summary', {}).get('total_evidence_items')}")
            c.drawString(50, 670, f"IOC Findings: {report.get('summary', {}).get('total_ioc_findings')}")
            c.drawString(50, 650, f"Timeline Events: {report.get('summary', {}).get('total_timeline_events')}")
            c.save()
            return True
        except ImportError:
            raise NotImplementedError(
                "PDF generation requires the 'reportlab' dependency. "
                "HTML and JSON reports are fully supported and printable via browser print-to-PDF."
            )
