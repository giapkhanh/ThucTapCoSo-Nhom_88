import unittest
from models import TaskObservation, ObservationSource, SystemSnapshot

class TestModels(unittest.TestCase):

    def test_task_observation_immutability(self):
        obs = TaskObservation(pid=1, source=ObservationSource.PROCFS, timestamp=100.0, name="systemd")
        with self.assertRaises(AttributeError):
            obs.name = "new_name"

    def test_system_snapshot_indexing(self):
        snapshot = SystemSnapshot()
        obs1 = TaskObservation(pid=100, source=ObservationSource.PROCFS, timestamp=100.0, name="bash")
        obs2 = TaskObservation(pid=100, source=ObservationSource.PROCESS_PROBE, timestamp=100.1, name=None)
        
        snapshot.add_observation(obs1)
        snapshot.add_observation(obs2)
        
        self.assertEqual(snapshot.get_pids_for_source(ObservationSource.PROCFS), {100})
        self.assertEqual(snapshot.get_pids_for_source(ObservationSource.PROCESS_PROBE), {100})
        self.assertEqual(snapshot.get_observation(ObservationSource.PROCFS, 100).name, "bash")
        self.assertIsNone(snapshot.get_observation(ObservationSource.PROCESS_PROBE, 100).name)

if __name__ == '__main__':
    unittest.main()
