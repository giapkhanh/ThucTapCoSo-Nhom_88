import os
import ctypes
import errno
import time
from typing import List, Optional
from models import TaskObservation, ObservationSource

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.kill.argtypes = [ctypes.c_int, ctypes.c_int]
libc.kill.restype = ctypes.c_int

def _read_comm(path: str) -> Optional[str]:
    try:
        with open(path, 'r', errors='ignore') as f:
            return f.read().strip()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None

def _get_pid_max() -> int:
    fallback = 32768
    try:
        with open('/proc/sys/kernel/pid_max', 'r') as f:
            val = int(f.read().strip())
            return val if val > 0 else fallback
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, OSError):
        return fallback

def collect_from_proc() -> List[TaskObservation]:
    """
    Collector 1 (Procfs View):
    Traverses /proc and /proc/<PID>/task/ to collect visible TGIDs and TIDs.
    """
    observations = []
    scan_time = time.time()
    
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pid = int(entry)
                main_comm = _read_comm(f'/proc/{entry}/comm')
                
                observations.append(
                    TaskObservation(
                        pid=pid,
                        source=ObservationSource.PROCFS,
                        timestamp=scan_time,
                        name=main_comm
                    )
                )
                
                task_dir = f'/proc/{entry}/task'
                try:
                    for tid_entry in os.listdir(task_dir):
                        if tid_entry.isdigit():
                            tid = int(tid_entry)
                            if tid != pid:
                                thread_comm = _read_comm(f'{task_dir}/{tid_entry}/comm')
                                observations.append(
                                    TaskObservation(
                                        pid=tid,
                                        source=ObservationSource.PROCFS,
                                        timestamp=scan_time,
                                        name=thread_comm or main_comm
                                    )
                                )
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    pass
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
        
    return observations

def collect_from_process_probe() -> List[TaskObservation]:
    """
    Collector 2 (Process Existence Probe):
    Probes task existence across the PID namespace using kill(pid, 0).
    - Return 0: Task exists and caller has permission.
    - Return -1 (errno EPERM): Task exists but caller lacks permission.
    - Return -1 (errno ESRCH): Task does not exist.
    """
    observations = []
    scan_time = time.time()
    pid_max = _get_pid_max()
    kill_func = libc.kill

    for pid in range(1, pid_max + 1):
        res = kill_func(pid, 0)
        if res == 0:
            observations.append(
                TaskObservation(
                    pid=pid,
                    source=ObservationSource.PROCESS_PROBE,
                    timestamp=scan_time,
                    name=None
                )
            )
        else:
            err = ctypes.get_errno()
            if err == errno.EPERM:
                observations.append(
                    TaskObservation(
                        pid=pid,
                        source=ObservationSource.PROCESS_PROBE,
                        timestamp=scan_time,
                        name=None
                    )
                )
                
    return observations
