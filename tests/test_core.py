import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from habibi.core import audit, gitleaks_scan

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.invalid'], cwd=self.root, check=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=self.root, check=True)
        self.fake = Path(self.tmp.name) / 'bin'
        self.fake.mkdir()
        executable = self.fake / 'gitleaks'
        executable.write_text('''#!/usr/bin/env python3
import json,sys
from pathlib import Path
args=sys.argv
report=Path(args[args.index('--report-path')+1])
report.write_text('[]')
sys.exit(0)
''')
        executable.chmod(0o755)
        self.envpath = str(self.fake) + os.pathsep + os.environ['PATH']

    def test_all_scans_with_simulated_gitleaks(self):
        (self.root / 'README.md').write_text('generic content')
        subprocess.run(['git', 'add', 'README.md'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'initial'], cwd=self.root, check=True)
        (self.root / 'windmill').mkdir()
        (self.root / 'windmill' / 'one.flow.yaml').write_text('value: $var:foo')
        with patch.dict(os.environ, {'PATH': self.envpath}):
            result = audit(self.root)
        self.assertFalse(result['findings'])
        self.assertEqual(result['coverage']['gitleaks_git'], 'pass')
        self.assertEqual(result['coverage']['gitleaks_dir'], 'pass')
        self.assertEqual(result['coverage']['plugin:Windmill'], 'pass')

    def test_stop_on_first_literal(self):
        (self.root / 'keys.py').write_text('password = "test-secret-literal-value"')
        with patch.dict(os.environ, {'PATH': self.envpath}):
            result = audit(self.root, True)
        self.assertTrue(result['stopped_early'])
        self.assertTrue(result['findings'])
        self.assertNotIn('test-secret-literal-value', str(result))

if __name__ == '__main__':
    unittest.main()
