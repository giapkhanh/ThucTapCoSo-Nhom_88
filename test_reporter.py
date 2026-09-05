import unittest
import json
from models import PersistentFinding, AnomalyType, PersistenceStatus
from reporter import generate_text_report, generate_json_report

class TestReporter(unittest.TestCase):

    def setUp(self):
        self.mock_meta = {"start_time": "2026-08-15T09:00:00", "rounds": 3, "interval": 0.5}
        self.mock_finding = PersistentFinding(
            pid=7777,
            anomaly_type=AnomalyType.HIDDEN_FROM_PROCFS,
            persistence_status=PersistenceStatus.PERSISTENT,
            severity="CRITICAL",
            rounds_detected=3,
            total_rounds=3,
            evidence={
                "detection_ratio": "3/3",
                "first_round_evidence": {"detected_in": "process_probe", "missing_from": "procfs"}
            }
        )

    def test_text_report_clean(self):
        report = generate_text_report(self.mock_meta, [])
        self.assertIn("System Status: CLEAN", report)

    def test_text_report_finding(self):
        report = generate_text_report(self.mock_meta, [self.mock_finding])
        self.assertIn("PID: 7777", report)
        self.assertIn("HIDDEN_FROM_PROCFS", report)

    def test_json_report_structure(self):
        json_str = generate_json_report(self.mock_meta, [self.mock_finding])
        parsed = json.loads(json_str)
        self.assertEqual(parsed["total_anomalies"], 1)
        self.assertEqual(parsed["findings"][0]["pid"], 7777)

if __name__ == '__main__':
    unittest.main()
