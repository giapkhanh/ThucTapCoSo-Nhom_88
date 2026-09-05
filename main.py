import argparse
import sys
import time
from datetime import datetime
from typing import List, Tuple
from models import SystemSnapshot, PersistentFinding, PersistenceStatus
from collectors import collect_from_proc, collect_from_process_probe
from comparator import compare_snapshot_views
from analyzer import analyze_persistence
from network import collect_network_sockets, analyze_network_anomalies
from reporter import generate_text_report, generate_json_report

def create_system_snapshot(include_network: bool = False) -> Tuple[SystemSnapshot, int]:
    snapshot = SystemSnapshot()
    for obs in collect_from_proc():
        snapshot.add_observation(obs)
    for obs in collect_from_process_probe():
        snapshot.add_observation(obs)
    
    perm_denied_count = 0
    if include_network:
        snapshot.sockets, perm_denied_count = collect_network_sockets()
        
    return snapshot, perm_denied_count

def run_scan(rounds: int, interval: float, include_network: bool = False, verbose: bool = False) -> tuple[dict, List[PersistentFinding]]:
    start_time_iso = datetime.now().isoformat()
    findings_per_round = []
    perm_denied = 0

    for r in range(1, rounds + 1):
        if verbose:
            print(f"[*] Round {r}/{rounds}: Scanning snapshot...", file=sys.stderr)
        
        scan_net = include_network and (r == rounds)
        snapshot, perm_denied = create_system_snapshot(include_network=scan_net)
        
        round_findings = compare_snapshot_views(snapshot)
        findings_per_round.append(round_findings)
        
        if r < rounds:
            time.sleep(interval)

    persistent_findings = analyze_persistence(findings_per_round, min_rounds_for_persistent=2)

    if include_network and snapshot.sockets:
        if verbose:
            print("[*] Analyzing Network & Socket correlations...", file=sys.stderr)
        net_findings = analyze_network_anomalies(snapshot.sockets, perm_denied_count=perm_denied)
        for nf in net_findings:
            persistent_findings.append(
                PersistentFinding(
                    pid=None,
                    anomaly_type=nf.anomaly_type,
                    persistence_status=PersistenceStatus.PERSISTENT,
                    severity=nf.severity,
                    rounds_detected=1,
                    total_rounds=rounds,
                    evidence=nf.evidence
                )
            )

    summary_meta = {
        "start_time": start_time_iso,
        "rounds": rounds,
        "interval": interval,
        "network_correlation": include_network
    }

    return summary_meta, persistent_findings

def main():
    parser = argparse.ArgumentParser(
        description="Process Visibility Anomaly Detection Prototype (Cross-View Research Tool)"
    )
    parser.add_argument("-r", "--rounds", type=int, default=3, help="Number of observation rounds (default: 3)")
    parser.add_argument("-i", "--interval", type=float, default=0.5, help="Interval between rounds in seconds (default: 0.5)")
    parser.add_argument("--net", action="store_true", help="Enable Network Socket to Process correlation")
    parser.add_argument("--json", action="store_true", help="Output results in machine-readable JSON format")
    parser.add_argument("-o", "--output", type=str, help="Save report to specified output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show progress during collection")

    args = parser.parse_args()

    meta, findings = run_scan(
        rounds=args.rounds,
        interval=args.interval,
        include_network=args.net,
        verbose=args.verbose
    )

    if args.json:
        report = generate_json_report(meta, findings)
    else:
        report = generate_text_report(meta, findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        if args.verbose:
            print(f"[+] Report saved to {args.output}", file=sys.stderr)
    else:
        print(report)

if __name__ == "__main__":
    main()
