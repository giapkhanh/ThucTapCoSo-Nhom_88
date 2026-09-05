import unittest
from unittest.mock import patch, mock_open
from network import decode_hex_endpoint, parse_proc_net_tcp, analyze_network_anomalies
from models import SocketInfo, AnomalyType

class TestNetworkCorrelation(unittest.TestCase):

    def test_decode_hex_endpoint(self):
        # 0100007F -> 127.0.0.1, 0050 -> 80
        result = decode_hex_endpoint("0100007F:0050")
        self.assertEqual(result, "127.0.0.1:80")

        # 00000000:1F90 -> 0.0.0.0:8080
        result = decode_hex_endpoint("00000000:1F90")
        self.assertEqual(result, "0.0.0.0:8080")

    @patch("builtins.open", new_callable=mock_open, read_data="""  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 12345 1 0000000000000000 100 0 0 10 0
""")
    def test_parse_proc_net_tcp(self, mock_file):
        sockets = parse_proc_net_tcp()
        self.assertEqual(len(sockets), 1)
        inode, local_addr, rem_addr, state = sockets[0]
        self.assertEqual(inode, 12345)
        self.assertEqual(local_addr, "127.0.0.1:53")
        self.assertEqual(state, "LISTEN")

    def test_analyze_network_anomalies(self):
        sockets = [
            # Socket có owner hợp lệ -> Clean
            SocketInfo(inode=1001, local_address="127.0.0.1:80", remote_address="0.0.0.0:0", state="LISTEN", owner_pid=500),
            # Socket active nhưng không có owner -> Anomaly!
            SocketInfo(inode=1002, local_address="0.0.0.0:4444", remote_address="0.0.0.0:0", state="LISTEN", owner_pid=None),
            # Socket đã đóng (TIME_WAIT) không có owner -> Bỏ qua (không tạo cảnh báo thừa)
            SocketInfo(inode=1003, local_address="127.0.0.1:5000", remote_address="127.0.0.1:80", state="TIME_WAIT", owner_pid=None),
        ]

        findings = analyze_network_anomalies(sockets)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].anomaly_type, AnomalyType.UNOWNED_ACTIVE_SOCKET)
        self.assertEqual(findings[0].evidence["inode"], 1002)
        self.assertEqual(findings[0].evidence["local_address"], "0.0.0.0:4444")

if __name__ == "__main__":
    unittest.main()
