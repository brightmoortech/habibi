"""Installer integration smoke tests; run only when a release wheel is bundled."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WHEEL = ROOT / 'dist' / 'repo_sec_scan-0.2.4-py3-none-any.whl'


@unittest.skipUnless(WHEEL.exists() and shutil.which('bash'), 'release wheel/bash unavailable')
class InstallerTests(unittest.TestCase):
    def test_install_repeat_and_failed_upgrade_preserves_installation(self):
        with tempfile.TemporaryDirectory(prefix='secscan-install-test-') as temp:
            prefix = Path(temp) / 'prefix'
            env = dict(os.environ, SECSCAN_PREFIX=str(prefix), PIP_NO_INDEX='1')
            installer = ROOT / 'install.sh'
            first = subprocess.run(['bash', str(installer)], env=env, text=True, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertTrue((prefix / 'bin' / 'secscan').exists())
            repeated = subprocess.run(['bash', str(installer)], env=env, text=True, capture_output=True)
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            self.assertIn('already installed', repeated.stdout)
            self.assertIn('usage: secscan', subprocess.check_output([str(prefix / 'bin' / 'secscan'), '--help'], text=True))
            # A later version whose package cannot be installed must not break the old command.
            mock_source = Path(temp) / 'broken'
            mock_source.mkdir()
            shutil.copy(installer, mock_source / 'install.sh')
            source = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
            (mock_source / 'pyproject.toml').write_text(source.replace('version = "0.2.4"', 'version = "0.2.5"'), encoding='utf-8')
            failure = subprocess.run(['bash', str(mock_source / 'install.sh')], env=env, text=True, capture_output=True)
            self.assertNotEqual(failure.returncode, 0)
            self.assertFalse((prefix / 'lib/repo-sec-scan/releases/0.2.5').exists())
            self.assertEqual((prefix / 'lib/repo-sec-scan/current').resolve().name, '0.2.4')
            self.assertEqual(subprocess.run([str(prefix / 'bin' / 'secscan'), 'plugins', 'list'], capture_output=True).returncode, 0)

    def test_help_does_not_install(self):
        result = subprocess.run(['bash', str(ROOT / 'install.sh'), '--help'], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('sudo ./install.sh', result.stdout)
