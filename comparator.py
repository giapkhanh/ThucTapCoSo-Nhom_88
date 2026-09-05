from typing import List
from models import SystemSnapshot, ObservationSource, AnomalyType, DetectionFinding

def compare_snapshot_views(snapshot: SystemSnapshot) -> List[DetectionFinding]:
    """
    Compares observations between Procfs enumeration and Process Existence Probing.
    Note: Both views are non-atomic and captured at slightly different timestamps.
    """
    findings: List[DetectionFinding] = []
    
    proc_pids = snapshot.get_pids_for_source(ObservationSource.PROCFS)
    probe_pids = snapshot.get_pids_for_source(ObservationSource.PROCESS_PROBE)

    # 1. PID responds to kill(0) probe but is missing from /proc enumeration
    hidden_in_proc = probe_pids - proc_pids
    for pid in sorted(hidden_in_proc):
        probe_obs = snapshot.get_observation(ObservationSource.PROCESS_PROBE, pid)
        findings.append(
            DetectionFinding(
                pid=pid,
                anomaly_type=AnomalyType.HIDDEN_FROM_PROCFS,
                severity="HIGH",
                description=f"PID {pid} responded to process existence probe (kill 0) but was absent from /proc directory enumeration.",
                evidence={
                    "detected_in": ObservationSource.PROCESS_PROBE.value,
                    "missing_from": ObservationSource.PROCFS.value,
                    "probe_observation_time": probe_obs.timestamp if probe_obs else None,
                    "snapshot_time": snapshot.timestamp
                }
            )
        )

    # 2. PID listed in /proc but kill(0) returns ESRCH (typically process terminated during scan window)
    absent_in_probe = proc_pids - probe_pids
    for pid in sorted(absent_in_probe):
        proc_obs = snapshot.get_observation(ObservationSource.PROCFS, pid)
        findings.append(
            DetectionFinding(
                pid=pid,
                anomaly_type=AnomalyType.ABSENT_IN_PROBE,
                severity="LOW",
                description=f"PID {pid} was enumerated from /proc but failed existence probe (likely terminated during the scan window).",
                evidence={
                    "detected_in": ObservationSource.PROCFS.value,
                    "missing_from": ObservationSource.PROCESS_PROBE.value,
                    "process_name": proc_obs.name if proc_obs else "unknown",
                    "procfs_observation_time": proc_obs.timestamp if proc_obs else None,
                    "snapshot_time": snapshot.timestamp
                }
            )
        )

    return findings
