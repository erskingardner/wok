import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


load = module('lab_load', 'contrib/lab/load.py')
lab = module('lab_runner', 'scripts/lab.py')


class ResultGate(unittest.TestCase):
    def test_complete_correct_scenarios(self):
        self.check_rows(self.rows(), True)

    def test_successful_process_does_not_hide_failed_trials(self):
        for field, value in [('ok', False), ('errors', 1), ('mismatches', 1)]:
            with self.subTest(field=field):
                rows = self.rows()
                rows[1][field] = value
                self.check_rows(rows, False)

    def test_missing_duplicate_and_empty_scenarios(self):
        for rows in [[], self.rows()[:2], [self.rows()[0]] * 3]:
            self.check_rows(rows, False)

    @staticmethod
    def rows():
        return [dict(scenario=s, ok=True, errors=0, mismatches=0)
                for s in ['ws_publish_scaled', 'live_fanout', 'idle_connections']]

    def check_rows(self, rows, expected):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'results.jsonl'
            p.write_text('\n'.join(json.dumps(r) for r in rows))
            if expected:
                self.assertEqual(load.validate_results(p), rows)
            else:
                with self.assertRaises(RuntimeError):
                    load.validate_results(p)


class ArtifactArchive(unittest.TestCase):
    def archive(self, names):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as tar:
            for name, kind in names:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                if kind == tarfile.SYMTYPE:
                    entry.linkname = '/tmp'
                tar.addfile(entry)
        stream.seek(0)
        return stream

    def test_regular_results_extract(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab.extract_results(self.archive([('result.json', tarfile.REGTYPE)]), Path(tmp))
            self.assertTrue((Path(tmp)/'result.json').exists())

    def test_rejects_unsafe_members_before_extracting_anything(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                           ('symlink', tarfile.SYMTYPE), ('device', tarfile.CHRTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    lab.extract_results(self.archive([('first', tarfile.REGTYPE), (name, kind)]), Path(tmp))
                self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
