import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import lifecycle


class LifecycleTests(unittest.TestCase):
    def test_reject_callers_group(self):
        with self.assertRaises(RuntimeError):
            lifecycle.stop_access_groups([os.getpgrp()])

    def test_exited_parent_group_descendants_are_killed(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory)/'child'
            code = "import os,time,pathlib; child=os.fork(); pathlib.Path("+repr(str(ready))+").write_text(str(child)) if child else time.sleep(20)"
            parent = subprocess.Popen([sys.executable, '-c', code], start_new_session=True)
            try:
                parent.wait(timeout=2)
                deadline = time.monotonic()+2
                while not ready.exists() and time.monotonic()<deadline: time.sleep(.01)
                self.assertTrue(ready.exists())
                self.assertTrue(lifecycle.access_groups_alive({parent.pid}))
                with patch.object(lifecycle, 'PROCESSES', {'guacd': parent}), patch.object(lifecycle, 'ACCESS_GROUPS', {parent.pid}), patch.object(lifecycle, 'DIAGNOSTICS', []):
                    lifecycle.shutdown()
                self.assertFalse(lifecycle.access_groups_alive({parent.pid}))
            finally:
                try: os.killpg(parent.pid, signal.SIGKILL)
                except ProcessLookupError: pass

    def test_live_parent_group_killed(self):
        parent = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(20)'], start_new_session=True)
        try:
            lifecycle.stop_access_groups([parent.pid], timeout=2)
            parent.wait(timeout=2)
            self.assertFalse(lifecycle.access_groups_alive({parent.pid}))
        finally:
            try: os.killpg(parent.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            parent.wait(timeout=2)


if __name__ == '__main__': unittest.main()
