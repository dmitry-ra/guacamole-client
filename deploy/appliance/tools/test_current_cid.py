"""Actual CID file metadata boundaries; no engine or database operations."""
import os
from pathlib import Path
import tempfile
import unittest

import migrate_current as migration


@unittest.skipUnless(os.geteuid()==0,'Synthetic protected case requires root')
class CIDTests(unittest.TestCase):
    def test_root_private_case_accepts_native_public_cid_mode(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            case=Path(name);case.chmod(0o700)
            p=case/'cid';p.write_bytes(b'a'*64);p.chmod(0o644)
            self.assertEqual(migration.read_cid(case),'a'*64)
            p.chmod(0o600);p.write_bytes(b'a'*64+b'\n')
            self.assertEqual(migration.read_cid(case),'a'*64)
            for raw in (b'a'*63,b'g'*64,b'a'*64+b' ',b'a'*64+b'\n\n'):
                p.write_bytes(raw)
                with self.assertRaises(RuntimeError):migration.read_cid(case)

    def test_writable_foreign_linked_and_symlink_files_are_rejected(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            case=Path(name);case.chmod(0o700)
            p=case/'cid';p.write_bytes(b'a'*64)
            p.chmod(0o666)
            with self.assertRaises(RuntimeError):migration.read_cid(case)
            p.chmod(0o644);os.chown(p,12345,12345)
            with self.assertRaises(RuntimeError):migration.read_cid(case)
            os.chown(p,0,0);os.link(p,case/'link')
            with self.assertRaises(RuntimeError):migration.read_cid(case)
            p.unlink();p.symlink_to(case/'link')
            with self.assertRaises(OSError):migration.read_cid(case)


if __name__=='__main__':unittest.main()
