import http.server
from pathlib import Path
import runpy
import tempfile
import threading
import unittest
from unittest.mock import patch


Root = runpy.run_path(str(Path(__file__).with_name("root-stall-watch.py")))["Root"]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/debug/consensus/round":
            data = f"{self.server.round_number}\n".encode()
        elif self.path == "/debug/pprof/goroutine?debug=2":
            data = b"goroutine 1 [running]:\n"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("X-Root-Pid", str(self.server.root_pid))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class RootStallWatchTest(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.shutdown)
        self.server.round_number = 51
        self.server.root_pid = 123
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        home = Path(directory.name)
        (home / "pid").write_text("123\n")
        self.log = home / "debug.log"
        self.root = Root(home, 123, self.server.server_port, 0)

    def sample_at(self, now):
        with patch("time.monotonic", return_value=now):
            self.root.sample(5)

    def test_records_stall_despite_live_logs_and_rearms_after_progress(self):
        self.sample_at(1)
        self.server.round_number += 1
        self.sample_at(5)
        self.log.write_text("network still logging\n")
        self.sample_at(9)
        self.assertNotIn("stall dump", self.log.read_text())
        self.sample_at(10)
        self.sample_at(11)
        self.assertEqual(1, self.log.read_text().count("goroutine 1 [running]"))
        self.assertIn("round 52", self.log.read_text())
        self.server.round_number += 1
        self.sample_at(12)
        self.sample_at(17)
        self.assertEqual(2, self.log.read_text().count("goroutine 1 [running]"))
        self.assertIn("round 53", self.log.read_text())

    def test_replacement_cannot_write_another_roots_stacks(self):
        self.sample_at(1)
        self.server.root_pid = 124
        self.sample_at(7)
        self.assertFalse(self.log.exists())
        self.server.root_pid = 123
        (self.root.home / "pid").write_text("124\n")
        self.sample_at(8)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
