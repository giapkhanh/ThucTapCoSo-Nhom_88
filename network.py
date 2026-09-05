import os
import socket
import struct
from typing import List, Dict, Tuple
from models import SocketInfo, DetectionFinding, AnomalyType

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

def decode_hex_endpoint(hex_endpoint: str) -> str:
    try:
        hex_ip, hex_port = hex_endpoint.split(":")
        ip_bytes = struct.pack("<L", int(hex_ip, 16))
        ip_str = socket.inet_ntoa(ip_bytes)
        port_num = int(hex_port, 16)
        return f"{ip_str}:{port_num}"
    except Exception:
        return hex_endpoint

def parse_proc_net_tcp() -> List[Tuple[int, str, str, str]]:
    records = []
    try:
        with open("/proc/net/tcp", "r") as f:
            lines = f.readlines()[1:]
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 10:
                    local_addr = decode_hex_endpoint(parts[1])
                    rem_addr = decode_hex_endpoint(parts[2])
                    state_code = parts[3]
                    state = TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
                    inode = int(parts[9])
                    records.append((inode, local_addr, rem_addr, state))
    except FileNotFoundError:
        pass
    return records

def map_socket_inodes_to_pids() -> Tuple[Dict[int, int], int]:
    """
    Map socket inode -> PID, đồng thời đếm số lượng tiến trình bị từ chối quyền truy cập (PermissionError).
    """
    inode_to_pid: Dict[int, int] = {}
    permission_denied_count = 0

    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pid = int(entry)
                fd_dir = f"/proc/{entry}/fd"
                try:
                    for fd in os.listdir(fd_dir):
                        try:
                            target = os.readlink(f"{fd_dir}/{fd}")
                            if target.startswith("socket:[") and target.endswith("]"):
                                inode = int(target[8:-1])
                                inode_to_pid[inode] = pid
                        except (FileNotFoundError, ProcessLookupError, PermissionError):
                            pass
                except PermissionError:
                    permission_denied_count += 1
                except (FileNotFoundError, ProcessLookupError):
                    pass
    except FileNotFoundError:
        pass

    return inode_to_pid, permission_denied_count

def collect_network_sockets() -> Tuple[List[SocketInfo], int]:
    raw_sockets = parse_proc_net_tcp()
    inode_map, perm_denied_count = map_socket_inodes_to_pids()

    socket_infos = []
    for inode, local_addr, rem_addr, state in raw_sockets:
        owner_pid = inode_map.get(inode)
        socket_infos.append(
            SocketInfo(
                inode=inode,
                local_address=local_addr,
                remote_address=rem_addr,
                state=state,
                owner_pid=owner_pid
            )
        )
    return socket_infos, perm_denied_count

def analyze_network_anomalies(sockets: List[SocketInfo], perm_denied_count: int = 0) -> List[DetectionFinding]:
    findings = []
    for s in sockets:
        if s.state in ("LISTEN", "ESTABLISHED") and s.owner_pid is None:
            evidence = {
                "inode": s.inode,
                "state": s.state,
                "local_address": s.local_address,
                "remote_address": s.remote_address,
            }
            if perm_denied_count > 0:
                evidence["permission_warning"] = (
                    f"Scan ran as non-root ({perm_denied_count} processes inaccessible). "
                    f"Socket may belong to a privileged daemon."
                )

            findings.append(
                DetectionFinding(
                    pid=None,
                    anomaly_type=AnomalyType.UNOWNED_ACTIVE_SOCKET,
                    severity="HIGH" if perm_denied_count == 0 else "LOW",
                    description=f"Active TCP Socket ({s.local_address}) in {s.state} state has no visible owner process in /proc.",
                    evidence=evidence
                )
            )
    return findings
