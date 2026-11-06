import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_version", SCRIPTS / "release-version.py")
version = importlib.util.module_from_spec(spec)
spec.loader.exec_module(version)


class SemVer(unittest.TestCase):
    def test_stable_rc_and_build_metadata_are_classified(self):
        for value in ["0.8.0", "1.2.3+build.01"]:
            self.assertFalse(version.is_prerelease(value))
        for value in ["0.8.0-rc.1", "1.2.3-alpha.0+build.01", "1.2.3-rc-2"]:
            self.assertTrue(version.is_prerelease(value))

    def test_invalid_or_ambiguous_versions_are_rejected(self):
        for value in ["", "v0.8.0", "00.8.0", "0.08.0", "0.8.00", "0.8", "0.8.0-",
                      "0.8.0-rc..1", "0.8.0-rc.01", "0.8.0+", "0.8.0+bad..id", "0.8.0\n"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                version.is_prerelease(value)


class ReleaseScripts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.output = self.root / "github-output"
        self.gh_args = self.root / "gh-args.json"
        self.env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                        GITHUB_OUTPUT=str(self.output), WOK_RELEASE_ALLOW_MISSING_TAG="1",
                        FIXTURE_PACKAGE_VERSION="0.8.0-rc.1", GH_ARGS=str(self.gh_args))
        self.executable("cargo", """import json, os, sys
assert sys.argv[1:] == ['metadata', '--locked', '--no-deps', '--format-version', '1']
print(json.dumps({'packages': [{'name': 'wok-cli', 'version': os.environ['FIXTURE_PACKAGE_VERSION']}]}))
""")
        self.executable("gh", """import json, os, sys
from pathlib import Path
Path(os.environ['GH_ARGS']).write_text(json.dumps(sys.argv[1:]))
""")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.fixture("0.8.0-rc.1")

    def executable(self, name, body):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o755)

    def fixture(self, value):
        (self.root / "Cargo.toml").write_text(f'[workspace.package]\nversion = "{value}"\n')
        (self.root / "CHANGELOG.md").write_text(
            f"# Changelog\n\n## [Unreleased]\n\nPending.\n\n## [{value}] - 2026-11-06\n\nRC notes.\n\n"
            "## [0.7.0] - 2026-10-01\n\nOld notes.\n")

    def run_script(self, name, *args):
        return subprocess.run(["bash", str(SCRIPTS / name), *args], cwd=self.root,
                              env=self.env, capture_output=True, text=True, timeout=15)

    def test_rc_contract_exports_exact_version_and_prerelease(self):
        result = self.run_script("check-release.sh", "v0.8.0-rc.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), "version=0.8.0-rc.1\nprerelease=true\n")

    def test_stable_contract_exports_false(self):
        self.fixture("0.8.0")
        self.env["FIXTURE_PACKAGE_VERSION"] = "0.8.0"
        result = self.run_script("check-release.sh", "v0.8.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("prerelease=false\n", self.output.read_text())

    def test_tag_workspace_and_package_versions_must_match(self):
        self.assertNotEqual(self.run_script("check-release.sh", "v0.8.0").returncode, 0)
        self.env["FIXTURE_PACKAGE_VERSION"] = "0.8.0-rc.2"
        self.assertNotEqual(self.run_script("check-release.sh", "v0.8.0-rc.1").returncode, 0)
        self.assertFalse(self.output.exists())

    def test_changelog_version_is_exact_not_a_regex(self):
        changelog = self.root / "CHANGELOG.md"
        changelog.write_text(changelog.read_text().replace("[0.8.0-rc.1]", "[0x8x0-rcx1]"))
        self.assertNotEqual(self.run_script("check-release.sh", "v0.8.0-rc.1").returncode, 0)
        self.assertNotEqual(self.run_script("release-notes.sh", "0.8.0-rc.1").returncode, 0)

    def test_existing_tag_must_point_at_this_commit(self):
        def git(*args):
            subprocess.run(["git", "-c", "user.name=Release Guard", "-c", "user.email=guard@example.invalid",
                            *args], cwd=self.root, check=True, capture_output=True)
        git("commit", "--allow-empty", "-qm", "tagged")
        git("tag", "v0.8.0-rc.1")
        git("commit", "--allow-empty", "-qm", "later")
        result = self.run_script("check-release.sh", "v0.8.0-rc.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("but checkout is", result.stderr)

    def test_missing_tag_requires_explicit_local_opt_in(self):
        self.env.pop("WOK_RELEASE_ALLOW_MISSING_TAG")
        self.assertNotEqual(self.run_script("check-release.sh", "v0.8.0-rc.1").returncode, 0)

    def test_rc_notes_exclude_other_sections(self):
        result = self.run_script("release-notes.sh", "0.8.0-rc.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "RC notes.")

    def test_empty_notes_cannot_publish(self):
        path = self.root / "CHANGELOG.md"
        path.write_text(path.read_text().replace("RC notes.", ""))
        self.assertNotEqual(self.run_script("release-notes.sh", "0.8.0-rc.1").returncode, 0)

    def test_publisher_marks_rc_prerelease_and_never_latest(self):
        result = self.run_script("publish-release.sh", "v0.8.0-rc.1", "dist", "notes.md")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads(self.gh_args.read_text())
        self.assertIn("--verify-tag", args)
        self.assertIn("--prerelease", args)
        self.assertIn("--latest=false", args)
        self.assertNotIn("--latest", args)
        self.assertEqual(args[:3], ["release", "create", "v0.8.0-rc.1"])

    def test_publisher_marks_stable_latest(self):
        self.assertEqual(self.run_script("publish-release.sh", "v0.8.0").returncode, 0)
        args = json.loads(self.gh_args.read_text())
        self.assertIn("--latest", args)
        self.assertNotIn("--prerelease", args)
        self.assertNotIn("--latest=false", args)

    def test_publisher_rejects_invalid_tag_before_gh(self):
        self.assertNotEqual(self.run_script("publish-release.sh", "v0.8.0-rc.01").returncode, 0)
        self.assertFalse(self.gh_args.exists())


if __name__ == "__main__":
    unittest.main()
