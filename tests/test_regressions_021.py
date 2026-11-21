import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from habibi.core import audit, generic_scan
from habibi.discovery import discover_packages
from habibi.models import Context


class Regression021Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        toolbin = Path(self.tmp.name) / 'bin'
        toolbin.mkdir()
        fake = toolbin / 'gitleaks'
        fake.write_text('''#!/usr/bin/env python3
import sys
from pathlib import Path
args=sys.argv
Path(args[args.index('--report-path')+1]).write_text('[]')
''')
        fake.chmod(0o755)
        self.scanpath = str(toolbin) + os.pathsep + os.environ['PATH']

    def scan(self, stop=False):
        with patch.dict(os.environ, {'PATH': self.scanpath}):
            return audit(self.root, stop)

    def test_unknown_dummy_package_is_reported_exactly_no_plugin(self):
        (self.root / 'pyproject.toml').write_text('''[project]
name = "sample-app"
dependencies = ["galactic-zebra-widget-123>=1.2"]
[project.optional-dependencies]
testing = ["unidentified-platypus-sdk~=2.0"]
[dependency-groups]
dev = ["mystery-muffin-package>=1"]
[tool.poetry.group.test.dependencies]
space-beaver = "^3"
''')
        result = self.scan()
        for pkg in ['galactic-zebra-widget-123', 'unidentified-platypus-sdk', 'mystery-muffin-package', 'space-beaver']:
            self.assertIn(pkg, result['packages'])
            self.assertEqual(result['coverage'][f'package:{pkg}'], 'generic-only (no specialized plugin available)')
        self.assertFalse(result['findings'])
        self.assertFalse(result['coverage_issues'])

    def test_warning_does_not_cause_early_stop(self):
        (self.root / 'secrets.txt').write_text('public dummy content')
        (self.root / 'zzz.py').write_text('password = "faux-credential-123456"')
        result = self.scan(True)
        self.assertTrue(result['stopped_early'])
        self.assertEqual(result['findings'][0]['severity'], 'warning')
        self.assertTrue(any(f['severity'] == 'high' for f in result['findings']))
        self.assertIn('generic', result['coverage'])

    def test_only_warning_completes_full_scan(self):
        (self.root / 'secrets.txt').write_text('dummy')
        result = self.scan(True)
        self.assertFalse(result['stopped_early'])
        self.assertEqual(result['coverage']['generic'], 'findings')

    def test_oversized_generic_file_incomplete(self):
        (self.root / 'large.txt').write_bytes(b'x' * 1_000_001)
        result = self.scan()
        self.assertEqual(result['coverage']['generic'], 'incomplete')
        self.assertTrue(any('large.txt' in x for x in result['coverage_issues']))

    def test_oversized_plugin_file_incomplete(self):
        path = self.root / 'windmill' / 'large.flow.yaml'
        path.parent.mkdir()
        path.write_bytes(b' ' * 1_000_001)
        result = self.scan()
        self.assertEqual(result['coverage']['plugin:Windmill'], 'incomplete')
        self.assertTrue(any('Windmill scan skipped' in x for x in result['coverage_issues']))

    def test_malformed_pyproject_reported_incomplete(self):
        (self.root / 'pyproject.toml').write_text('[project\nname = 123')
        result = self.scan()
        self.assertTrue(any('invalid TOML' in x for x in result['coverage_issues']))

    def test_staged_oversized_file_incomplete(self):
        (self.root / 'large.txt').write_bytes(b'k' * 1_000_001)
        subprocess.run(['git', 'add', 'large.txt'], cwd=self.root, check=True)
        result = self.scan()
        self.assertEqual(result['coverage']['gitleaks_staged_and_generic'], 'incomplete')

    def test_multiline_toml_and_not_project_name(self):
        path = self.root / 'pyproject.toml'
        path.write_text('''[project]
name = "some-project-name"
dependencies = [
 "requests>=2",
 "psycopg[binary]>=3; python_version > '3.9'",
]
[project.optional-dependencies]
all = [
 "dummy-does-not-exist>=1",
]
''')
        result = discover_packages(Context(self.root, [path]))
        self.assertIn('requests', result)
        self.assertIn('psycopg', result)
        self.assertIn('dummy-does-not-exist', result)
        self.assertNotIn('some-project-name', result)


if __name__ == '__main__':
    unittest.main()
