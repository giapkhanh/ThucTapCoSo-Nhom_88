import unittest
from models import DetectionFinding, AnomalyType, PersistenceStatus
from analyzer import analyze_persistence

class TestAnalyzer(unittest.TestCase):

    def setUp(self):
        self.finding_hidden = DetectionFinding(
            pid=666,
            anomaly_type=AnomalyType.HIDDEN_FROM_PROCFS,
            severity="HIGH",
            description="PID hidden",
            evidence={"snapshot_time": 1000.0}
        )
        self.finding_transient = DetectionFinding(
            pid=999,
            anomaly_type=AnomalyType.ABSENT_IN_PROBE,
            severity="LOW",
            description="Process died",
            evidence={"snapshot_time": 1000.0}
        )

    def test_clean_rounds(self):
        self.assertEqual(len(analyze_persistence([[], [], []])), 0)

    def test_transient_anomaly(self):
        findings_per_round = [[self.finding_transient], [], []]
        results = analyze_persistence(findings_per_round, min_rounds_for_persistent=2)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].persistence_status, PersistenceStatus.TRANSIENT)

    def test_persistent_anomaly(self):
        findings_per_round = [[self.finding_hidden], [self.finding_hidden], [self.finding_hidden]]
        results = analyze_persistence(findings_per_round, min_rounds_for_persistent=2)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].persistence_status, PersistenceStatus.PERSISTENT)
        self.assertEqual(results[0].severity, "CRITICAL")

if __name__ == '__main__':
    unittest.main()
