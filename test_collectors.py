import unittest
from unittest.mock import patch
from collectors import collect_from_proc, collect_from_process_probe
from models import ObservationSource

class TestCollectors(unittest.TestCase):

    @patch('collectors._read_comm')
    @patch('os.listdir')
    def test_collect_from_proc(self, mock_listdir, mock_read_comm):
        def mock_listdir_call(path):
            if path == '/proc':
                return ['1', 'sys', '100']
            elif path == '/proc/1/task':
                return ['1']
            elif path == '/proc/100/task':
                return ['100', '101']
            return []
        
        mock_listdir.side_effect = mock_listdir_call
        mock_read_comm.return_value = "mock_proc"

        observations = collect_from_proc()
        pids = {obs.pid for obs in observations}
        
        self.assertEqual(pids, {1, 100, 101})
        self.assertTrue(all(obs.source == ObservationSource.PROCFS for obs in observations))
        self.assertTrue(all(obs.name == "mock_proc" for obs in observations))

    @patch('builtins.open')
    @patch('collectors.libc.kill')
    def test_collect_from_process_probe(self, mock_kill, mock_open):
        mock_open.return_value.__enter__.return_value.read.return_value = "3"
        
        def mock_kill_call(pid, sig):
            if pid in (1, 3):
                return 0
            return -1
            
        mock_kill.side_effect = mock_kill_call
        
        observations = collect_from_process_probe()
        pids = {obs.pid for obs in observations}
        
        self.assertEqual(pids, {1, 3})
        self.assertTrue(all(obs.source == ObservationSource.PROCESS_PROBE for obs in observations))
        self.assertTrue(all(obs.name is None for obs in observations))

if __name__ == '__main__':
    unittest.main()
