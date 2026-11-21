"""Verify single source of release version without requiring source installation."""
import contextlib
import io
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

from repo_sec_scan import cli
from repo_sec_scan._version import __version__

ROOT = Path(__file__).resolve().parents[1]


class Version025Tests(unittest.TestCase):
    def test_cli_version_from_source(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as finished:
                cli.main(['--version'])
        self.assertEqual(finished.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), f'secscan {__version__}')

    def test_module_version_from_source(self):
        completed = subprocess.run(
            [sys.executable, '-m', 'repo_sec_scan', '--version'],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), f'secscan {__version__}')

    def test_wheel_metadata_matches_authoritative_version(self):
        wheel = ROOT / 'dist' / f'repo_sec_scan-{__version__}-py3-none-any.whl'
        if not wheel.exists():
            self.skipTest('wheel not built')
        with zipfile.ZipFile(wheel) as archive:
            metadata_files = [p for p in archive.namelist() if p.endswith('.dist-info/METADATA')]
            self.assertEqual(len(metadata_files), 1)
            metadata = archive.read(metadata_files[0]).decode()
            self.assertIn(f'Version: {__version__}\n', metadata)
            self.assertIn('repo_sec_scan/_version.py', archive.namelist())


if __name__ == '__main__':
    unittest.main()
