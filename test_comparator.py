import unittest
from models import SystemSnapshot, TaskObservation, ObservationSource, AnomalyType
from comparator import compare_snapshot_views

class TestComparator(unittest.TestCase):

    def test_case_a_pid_in_both_views(self):
        snapshot = SystemSnapshot()
        snapshot.add_observation(TaskObservation(100, ObservationSource.PROCFS, 1.0, "init"))
        snapshot.add_observation(TaskObservation(100, ObservationSource.PROCESS_PROBE, 1.1))

        findings = compare_snapshot_views(snapshot)
        self.assertEqual(len(findings), 0)

    def test_case_b_pid_only_in_process_probe(self):
        snapshot = SystemSnapshot()
        snapshot.add_observation(TaskObservation(666, ObservationSource.PROCESS_PROBE, 1.1))

        findings = compare_snapshot_views(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].pid, 666)
        self.assertEqual(findings[0].anomaly_type, AnomalyType.HIDDEN_FROM_PROCFS)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].evidence["detected_in"], "process_probe")
        self.assertEqual(findings[0].evidence["missing_from"], "procfs")

    def test_case_c_pid_only_in_procfs(self):
        snapshot = SystemSnapshot()
        snapshot.add_observation(TaskObservation(300, ObservationSource.PROCFS, 1.0, "short_cmd"))

        findings = compare_snapshot_views(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].pid, 300)
        self.assertEqual(findings[0].anomaly_type, AnomalyType.ABSENT_IN_PROBE)
        self.assertEqual(findings[0].severity, "LOW")

    def test_case_d_empty_views(self):
        snapshot = SystemSnapshot()
        findings = compare_snapshot_views(snapshot)
        self.assertEqual(len(findings), 0)

if __name__ == '__main__':
    unittest.main()
