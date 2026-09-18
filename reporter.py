import json
from typing import List, Dict, Any
from models import PersistentFinding, AnomalyType

def _finding_to_dict(finding: PersistentFinding) -> Dict[str, Any]:
    return {
        "pid": finding.pid,
        "anomaly_type": finding.anomaly_type.value,
        "persistence_status": finding.persistence_status.value,
        "severity": finding.severity,
        "rounds_detected": finding.rounds_detected,
        "total_rounds": finding.total_rounds,
        "evidence": finding.evidence
    }

def generate_json_report(
    summary_meta: Dict[str, Any],
    findings: List[PersistentFinding]
) -> str:
    report_dict = {
        "metadata": summary_meta,
        "total_anomalies": len(findings),
        "findings": [_finding_to_dict(f) for f in findings]
    }
    return json.dumps(report_dict, indent=2)

def generate_text_report(
    summary_meta: Dict[str, Any],
    findings: List[PersistentFinding]
) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("       PROCESS VISIBILITY ANOMALY DETECTION REPORT")
    lines.append("=" * 70)
    lines.append(f" Start Time: {summary_meta.get('start_time')}")
    lines.append(f" Rounds:     {summary_meta.get('rounds')} (Interval: {summary_meta.get('interval')}s)")
    lines.append(f" Network:    {'ENABLED' if summary_meta.get('network_correlation') else 'DISABLED'}")
    lines.append(f" Total Anomalies Found: {len(findings)}")
    lines.append("-" * 70)

    if not findings:
        lines.append(" [✓] System Status: CLEAN")
        lines.append("     No anomalies detected.")
    else:
        lines.append(" [!] ANOMALIES DETECTED:")
        for idx, f in enumerate(findings, start=1):
            pid_display = f"PID: {f.pid}" if f.pid is not None else "PID: [N/A - Socket]"
            lines.append(f"\n  #{idx} {pid_display} | Severity: [{f.severity}] | Status: [{f.persistence_status.value}]")
            lines.append(f"     Type:        {f.anomaly_type.value}")
            
            if f.anomaly_type == AnomalyType.UNOWNED_ACTIVE_SOCKET:
                lines.append("     Evidence (Socket Info):")
                lines.append(f"       - Inode:          {f.evidence.get('inode')}")
                lines.append(f"       - State:          {f.evidence.get('state')}")
                lines.append(f"       - Local Endpoint: {f.evidence.get('local_address')}")
                lines.append(f"       - Peer Endpoint:  {f.evidence.get('remote_address')}")
                if "permission_warning" in f.evidence:
                    lines.append(f"       - Notice:         {f.evidence.get('permission_warning')}")
            else:
                lines.append(f"     Persistence: Detected in {f.rounds_detected}/{f.total_rounds} rounds")
                lines.append("     Evidence (Process):")
                lines.append(f"       - Detection Ratio: {f.evidence.get('detection_ratio')}")
                lines.append(f"       - Missing Source:   {f.evidence.get('first_round_evidence', {}).get('missing_from')}")
                lines.append(f"       - Detected Source:  {f.evidence.get('first_round_evidence', {}).get('detected_in')}")
                if "process_name" in f.evidence.get('first_round_evidence', {}):
                    lines.append(f"       - Process Name:    {f.evidence.get('first_round_evidence', {}).get('process_name')}")

    lines.append("=" * 70)
    return "\n".join(lines)
