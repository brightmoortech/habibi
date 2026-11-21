import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from repo_sec_scan.discovery import discover_packages
from repo_sec_scan.models import Context, PluginResult
from repo_sec_scan.core import audit
from repo_sec_scan.plugins.registry import load_plugins
from repo_sec_scan.plugins.windmill import PLUGIN as WM
from repo_sec_scan.plugins.postgresql import PLUGIN as PG


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def context(self, contents):
        files = []
        for rel, content in contents.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            files.append(p)
        return Context(self.root, files)

    def test_declared_package_names_are_not_guessed(self):
        ctx = self.context({
            'package.json': json.dumps({'dependencies': {'@scope/unknown-sdk': '1.0', 'pg': '^8'}, 'devDependencies': {'vite': '1'}}),
            'requirements.txt': 'psycopg[binary]>=3\n# ignored\n-r extra.txt\ncustom-pkg==1.0\n',
            'compose.yaml': 'services:\n  dashboard:\n    image: metabase/metabase:v1\n  database:\n    image: postgres:18\n',
            'Dockerfile': 'FROM python:3.12-slim\n',
        })
        packages = discover_packages(ctx)
        for name in ('@scope/unknown-sdk', 'pg', 'vite', 'psycopg', 'custom-pkg',
                     'metabase/metabase:v1', 'postgres:18', 'python:3.12-slim'):
            self.assertIn(name, packages)
        self.assertFalse(WM.matches('metabase/metabase:v1'))
        self.assertFalse(PG.matches('metabase/metabase:v1'))
        self.assertTrue(PG.matches('postgres:18'))
        self.assertTrue(PG.matches('psycopg'))

    def test_pyproject_deps_and_poetry(self):
        ctx = self.context({'pyproject.toml': '''[project]
name = "demo"
dependencies = [
  "psycopg[binary]>=3.0",
  "unknown-project>=1",
]
[tool.poetry.dependencies]
python = "^3.12"
psycopg2 = "^2"
'''} )
        found = discover_packages(ctx)
        self.assertIn('psycopg', found)
        self.assertIn('psycopg2', found)
        self.assertIn('unknown-project', found)
        self.assertNotIn('python', found)
        self.assertNotIn('demo', found)

    def test_repository_e2e_unknown_package_fallback(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / 'compose.yaml').write_text('services:\n  metabase:\n    image: metabase/metabase:latest\n')
        (self.root / 'pg_hba.conf').write_text('host all all 127.0.0.1/32 trust\n')
        fake = self.root / 'gitleaks.fixture'
        fake.write_text('''#!/usr/bin/env python3
import sys
from pathlib import Path
args=sys.argv
Path(args[args.index('--report-path')+1]).write_text('[]')
''')
        fake.chmod(0o755)
        # Avoid placing the simulated tool inside the scanned repository.
        fakebin = self.root / 'fakebin'
        fakebin.mkdir()
        exe = fakebin / 'gitleaks'
        exe.write_bytes(fake.read_bytes()); exe.chmod(0o755)
        with patch.dict(os.environ, {'PATH': str(fakebin) + os.pathsep + os.environ['PATH']}):
            result = audit(self.root)
        self.assertIn('metabase/metabase:latest', result['packages'])
        self.assertEqual(result['coverage']['package:metabase/metabase:latest'],
                         'generic-only (no specialized plugin available)')
        self.assertEqual(result['coverage']['plugin:PostgreSQL'], 'findings')
        self.assertNotIn('plugin:Windmill', result['coverage'])

    def test_external_plugin_loading(self):
        class Extra:
            name = 'Extra'
            def matches(self, package): return package == 'extra'
            def detect(self, context): return False
            def scan(self, context, stop_on_finding=False): return PluginResult(self.name)

        class Entry:
            def load(self): return Extra

        class Entries:
            def select(self, group):
                self.group = group
                return [Entry()]
        with patch('repo_sec_scan.plugins.registry.metadata.entry_points', return_value=Entries()):
            names = [p.name for p in load_plugins()]
        self.assertIn('Extra', names)
        self.assertIn('PostgreSQL', names)
        self.assertIn('Windmill', names)

    def test_invalid_json_does_not_execute_repo_code(self):
        ctx = self.context({'package.json': '{ invalid json'})
        self.assertEqual(discover_packages(ctx), {})


if __name__ == '__main__':
    unittest.main()
