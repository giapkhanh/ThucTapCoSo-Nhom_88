from typing import List, Dict, Tuple
from models import DetectionFinding, PersistentFinding, PersistenceStatus, AnomalyType

def analyze_persistence(
    findings_per_round: List[List[DetectionFinding]],
    min_rounds_for_persistent: int = 2
) -> List[PersistentFinding]:
    """
    Evaluates temporal persistence across multiple scan rounds to differentiate
    persistent concealment anomalies from transient race conditions.
    """
    total_rounds = len(findings_per_round)
    if total_rounds == 0:
        return []

    aggregated: Dict[Tuple[Optional[int], AnomalyType], List[Tuple[int, DetectionFinding]]] = {}

    for round_idx, round_findings in enumerate(findings_per_round, start=1):
        for finding in round_findings:
            key = (finding.pid, finding.anomaly_type)
            if key not in aggregated:
                aggregated[key] = []
            aggregated[key].append((round_idx, finding))

    persistent_findings: List[PersistentFinding] = []

    for (pid, anomaly_type), records in aggregated.items():
        rounds_detected = len(records)
        is_persistent = rounds_detected >= min_rounds_for_persistent

        status = PersistenceStatus.PERSISTENT if is_persistent else PersistenceStatus.TRANSIENT
        
        if is_persistent and anomaly_type == AnomalyType.HIDDEN_FROM_PROCFS:
            severity = "CRITICAL"
        elif is_persistent:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        timeline = [
            {"round": r, "snapshot_time": f.evidence.get("snapshot_time")}
            for r, f in records
        ]

        persistent_findings.append(
            PersistentFinding(
                pid=pid,
                anomaly_type=anomaly_type,
                persistence_status=status,
                severity=severity,
                rounds_detected=rounds_detected,
                total_rounds=total_rounds,
                evidence={
                    "detection_ratio": f"{rounds_detected}/{total_rounds}",
                    "timeline": timeline,
                    "first_round_evidence": records[0][1].evidence
                }
            )
        )

    return persistent_findings
