from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Optional, Dict, Set, Any, List

class ObservationSource(str, Enum):
    PROCFS = "procfs"
    PROCESS_PROBE = "process_probe"  # Existence probing via kill(pid, 0)
    NETWORK = "network"

class AnomalyType(str, Enum):
    HIDDEN_FROM_PROCFS = "HIDDEN_FROM_PROCFS"
    ABSENT_IN_PROBE = "ABSENT_IN_PROBE"  # Process exited between scan phases (race condition)
    UNOWNED_ACTIVE_SOCKET = "UNOWNED_ACTIVE_SOCKET"

class PersistenceStatus(str, Enum):
    PERSISTENT = "PERSISTENT"
    TRANSIENT = "TRANSIENT"

@dataclass(frozen=True)
class SocketInfo:
    inode: int
    local_address: str
    remote_address: str
    state: str
    owner_pid: Optional[int] = None

@dataclass(frozen=True)
class TaskObservation:
    pid: int
    source: ObservationSource
    timestamp: float
    name: Optional[str] = None

@dataclass(frozen=True)
class DetectionFinding:
    pid: Optional[int]
    anomaly_type: AnomalyType
    severity: str
    description: str
    evidence: Dict[str, Any]

@dataclass(frozen=True)
class PersistentFinding:
    pid: Optional[int]
    anomaly_type: AnomalyType
    persistence_status: PersistenceStatus
    severity: str
    rounds_detected: int
    total_rounds: int
    evidence: Dict[str, Any]

@dataclass
class SystemSnapshot:
    timestamp: float = field(default_factory=time.time)
    observations_by_source: Dict[ObservationSource, Dict[int, TaskObservation]] = field(
        default_factory=lambda: {
            ObservationSource.PROCFS: {},
            ObservationSource.PROCESS_PROBE: {},
        }
    )
    sockets: List[SocketInfo] = field(default_factory=list)

    def add_observation(self, obs: TaskObservation) -> None:
        self.observations_by_source[obs.source][obs.pid] = obs

    def get_pids_for_source(self, source: ObservationSource) -> Set[int]:
        return set(self.observations_by_source[source].keys())

    def get_observation(self, source: ObservationSource, pid: int) -> Optional[TaskObservation]:
        return self.observations_by_source[source].get(pid)
