import importlib.util
import json
from pathlib import Path
import signal
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / "reliability-soak.py"
spec = importlib.util.spec_from_file_location("reliability_soak", PATH)
soak = importlib.util.module_from_spec(spec)
spec.loader.exec_module(soak)


class DatabaseBudget(unittest.TestCase):
    def test_whole_rocks_directory_includes_wal_sst_and_nested_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "wal").mkdir()
            for name, size in [("CURRENT", 8), ("000001.sst", 101), ("wal/000002.log", 37)]:
                (root / name).write_bytes(b"x" * size)
            self.assertEqual(soak.database_bytes(root), 146)

    def test_size_includes_metadata_and_lock_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "CURRENT").write_bytes(b"data")
            (root / "LOCK").write_bytes(b"lock")
            self.assertEqual(soak.database_bytes(root), 8)

    def test_compaction_can_remove_a_file_after_the_directory_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "CURRENT").write_bytes(b"live")
            # The walk already listed an SST that compaction has since unlinked.
            with patch.object(soak.os, "walk", return_value=[(str(root), [], ["CURRENT", "retired.sst"])]):
                self.assertEqual(soak.database_bytes(root), 4)

    def test_symlinks_do_not_escape_bounded_scratch_or_hide_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "db").mkdir(); (root / "outside").write_bytes(b"retained")
            (root / "db/link").symlink_to(root / "outside")
            with self.assertRaises(RuntimeError):
                soak.database_bytes(root / "db")
            self.assertEqual((root / "outside").read_bytes(), b"retained")
            (root / "db/link").unlink()
            (root / "db/link").symlink_to(root / "missing")
            with self.assertRaises(RuntimeError):
                soak.database_bytes(root / "db")


class IdentityAndResults(unittest.TestCase):
    def test_wrong_binary_or_old_rocks_layout_cannot_be_labelled_as_optimized_rocks(self):
        for actual in ["lmdb", "rocksdb-coverless-experimental", "rocksdb-optimized-experimental"]:
            with self.subTest(actual=actual), patch.object(soak.subprocess, "run", return_value=types.SimpleNamespace(stdout=actual)):
                with self.assertRaises(RuntimeError):
                    soak.verify_backend(Path("/unused/wok"))
        with patch.object(soak.subprocess, "run", return_value=types.SimpleNamespace(stdout="rocksdb-author-heads-experimental\n")) as run:
            self.assertEqual(soak.verify_backend(Path("/unused/wok")), "rocksdb-author-heads-experimental")
            self.assertEqual(run.call_args.args[0][-1], "storage-backend")

    def test_missing_crash_or_feed_verification_refuses_successful_driver_exit(self):
        good = dict(ok=True, restart_verified=True, crash_recovery_verified=True,
                    feed_author_count=500, author_feed_checks=6, author_live_deliveries=4)
        soak.validate_driver_result(good)
        for field, value in [("ok", False), ("restart_verified", False), ("crash_recovery_verified", False),
                             ("feed_author_count", 2), ("author_feed_checks", 0), ("author_live_deliveries", 0)]:
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                soak.validate_driver_result(dict(good, **{field: value}))


class ProcessOutcomes(unittest.TestCase):
    def test_already_exited_failure_is_not_a_graceful_shutdown(self):
        child = Mock(returncode=1); child.poll.return_value = 1
        with self.assertRaises(RuntimeError):
            soak.stop(child)
        child.send_signal.assert_not_called()

    def test_deliberate_sigkill_is_recorded_as_nonzero(self):
        child = Mock(returncode=None); child.poll.return_value = None; child.wait.return_value = -signal.SIGKILL
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "crash.json"
            soak.crash(child, path)
            self.assertEqual(json.loads(path.read_text())["actual_returncode"], -signal.SIGKILL)
            child.kill.assert_called_once_with()

    def test_unexpected_crash_exit_cannot_continue_recovery(self):
        child = Mock(returncode=None); child.poll.return_value = None; child.wait.return_value = 0
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "crash.json"
            with self.assertRaises(RuntimeError):
                soak.crash(child, path)
            self.assertEqual(json.loads(path.read_text())["actual_returncode"], 0)


if __name__ == "__main__":
    unittest.main()
