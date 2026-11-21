"""ISS-012 and ISS-013: technology inventory and live, grouped terminal output."""
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from repo_sec_scan import cli
from repo_sec_scan.core import audit
from repo_sec_scan.models import Finding
from repo_sec_scan.reporting import TerminalReport, _short_package


class Reporting027(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / 'repo'
        self.root.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        self.plugins = Path(tmp.name) / 'plugins'
        self.plugins.mkdir()
        env = patch.dict(os.environ, {'SECSCAN_PLUGIN_DIR': str(self.plugins)})
        env.start()
        self.addCleanup(env.stop)
        self.digest = 'ghcr.io/windmill-labs/windmill:1.848.3@sha256:' + 'a' * 64
        self.unknown = 'ghcr.io/windmill-labs/caddy-l4:2.11.4-1@sha256:' + 'b' * 64
        (self.root / 'compose.yaml').write_text(
            f'services:\n  a:\n    image: {self.digest}\n  b:\n    image: postgres:18.6\n  c:\n    image: {self.unknown}\n', encoding='utf-8')
        (self.root / 'pyproject.toml').write_text('[project]\nname="demo"\ndependencies=["pip"]\n')
        (self.root / '.env.example').write_text('sample placeholder')

    def scan(self, *, stop=False, callbacks=None, gitleaks=None):
        if gitleaks is None:
            gitleaks = ('pass', [])
        with patch('repo_sec_scan.core.gitleaks_scan', return_value=gitleaks), \
             patch('repo_sec_scan.core.staged_scan', return_value=('pass', [])):
            return audit(self.root, stop, callbacks)

    def test_discovered_technologies_merge_platform_and_specialized(self):
        output = self.scan()
        self.assertEqual(set(output['technologies']), {'Docker', 'Python', 'Windmill', 'PostgreSQL'})
        self.assertEqual(output['technologies']['Windmill'], ['compose.yaml'])
        self.assertIn(self.digest, output['packages'])
        self.assertEqual(output['coverage'][f'package:{self.digest}'], 'specialized: Windmill')
        self.assertEqual(output['coverage'][f'package:{self.unknown}'], 'generic-only (no specialized plugin available)')

    def test_live_events_discovery_first_with_per_check_findings_and_coverage(self):
        events = []
        result = self.scan(callbacks=events.append)
        kinds = [event['kind'] for event in events]
        self.assertEqual(kinds[0], 'discovery_start')
        self.assertLess(kinds.index('discovery_complete'), kinds.index('repository_start'))
        self.assertLess(kinds.index('repository_start'), kinds.index('technology_start'))
        self.assertLess(kinds.index('technology_start'), kinds.index('unsupported'))
        pairs = [(e['section'], e['label']) for e in events if e['kind'] == 'check_complete']
        self.assertEqual(pairs[:4], [('repository', 'Git history'), ('repository', 'Working files'),
                                     ('repository', 'Staged files'), ('repository', 'Generic checks')])
        self.assertIn(('technology', 'Windmill'), pairs)
        self.assertIn(('technology', 'PostgreSQL'), pairs)
        generic = next(e for e in events if e['kind'] == 'check_complete' and e['label'] == 'Generic checks')
        self.assertEqual(generic['findings'][0]['severity'], 'warning')
        self.assertEqual(generic['findings'][0]['path'], '.env.example')
        self.assertIn(self.unknown, next(e for e in events if e['kind'] == 'unsupported')['packages'])
        self.assertEqual(len(result['findings']), 1)

    def test_terminal_output_shows_problems_counts_and_short_digest(self):
        reporter = TerminalReport()
        with contextlib.redirect_stdout(io.StringIO()) as screen:
            result = self.scan(callbacks=reporter)
            reporter.finish(result)
        text = screen.getvalue()
        for section in ('[1] DISCOVERED TECHNOLOGIES', '[2] REPOSITORY SECURITY',
                        '[3] TECHNOLOGY SECURITY', '[4] UNSUPPORTED PACKAGES', 'SCAN SUMMARY'):
            self.assertIn(section, text)
        self.assertIn('Generic checks', text)
        self.assertIn('FINDINGS (1)', text)
        self.assertIn('sensitive filename', text)
        self.assertIn('.env.example', text)
        self.assertIn('Technologies detected:', text)
        self.assertIn('Coverage limitations:', text)
        self.assertIn('Checks: 4 | Findings: 1', text)
        self.assertIn('Generic checks only', text)
        self.assertNotIn('sha256:', text)
        self.assertIn('caddy-l4:2.11.4-1', text)

    def test_json_preserves_full_package_references(self):
        result = self.scan()
        text = json.dumps(result)
        self.assertIn(self.digest, text)
        self.assertIn(self.unknown, text)
        self.assertEqual(result['repository'], str(self.root))

    def test_stopped_early_does_not_claim_complete_or_run_remaining(self):
        reporter = TerminalReport()
        with contextlib.redirect_stdout(io.StringIO()) as screen:
            result = self.scan(stop=True, callbacks=reporter,
                               gitleaks=('findings', [Finding('Gitleaks-git', 'rule match', 'high', 'secret.txt', 2)]))
            reporter.finish(result)
        text = screen.getvalue()
        self.assertTrue(result['stopped_early'])
        self.assertIn('NOT RUN (scan stopped early)', text)
        self.assertIn('NOT EVALUATED (scan stopped early)', text)
        self.assertIn('INCOMPLETE', text)
        self.assertIn('secret.txt:2', text)
        self.assertNotIn('Working files', text)

    def test_discovery_issue_not_misreported_as_security_finding(self):
        (self.root / 'pyproject.toml').write_text('[project\nmissing')
        events = []
        result = self.scan(callbacks=events.append)
        self.assertTrue(result['coverage_issues'])
        self.assertEqual(len(result['findings']), 1)  # .env.example warning only
        reporter = TerminalReport()
        with contextlib.redirect_stdout(io.StringIO()) as screen:
            result = self.scan(callbacks=reporter)
            reporter.finish(result)
        self.assertIn('Discovery incomplete:', screen.getvalue())
        self.assertIn('INCOMPLETE', screen.getvalue())

    def test_cli_prints_live_sections_and_writes_original_json_shape(self):
        with tempfile.TemporaryDirectory() as temp:
            report_path = Path(temp) / 'audit.json'
            with patch('repo_sec_scan.cli.shutil.which', return_value='/usr/bin/tool'), \
                 patch('repo_sec_scan.core.gitleaks_scan', return_value=('pass', [])), \
                 patch('repo_sec_scan.core.staged_scan', return_value=('pass', [])), \
                 contextlib.redirect_stdout(io.StringIO()) as screen:
                exit_code = cli.main(['--report', str(report_path), str(self.root)])
            self.assertEqual(exit_code, 1)
            self.assertIn('[1] DISCOVERED TECHNOLOGIES', screen.getvalue())
            self.assertIn('Report saved:', screen.getvalue())
            stored = json.loads(report_path.read_text())
            self.assertIn(self.digest, stored['packages'])
            self.assertIn('coverage', stored)
            self.assertIn('findings', stored)

    def test_specialized_problem_displayed_under_technology(self):
        from repo_sec_scan.models import PluginResult

        class ExampleScanner:
            name = 'Example'

            def matches(self, package):
                return package == 'pip'

            def detect(self, ctx):
                return False

            def scan(self, ctx, stop_on_finding=False):
                return PluginResult('Example', ['Example'],
                                    [Finding('Example', 'unsafe setting', 'high', 'config.ini', 12)])

        fake_plugin = (self.root / 'example.py', ExampleScanner(), {'name': 'Example'}, None)
        reporter = TerminalReport()
        with patch('repo_sec_scan.core.inventory', return_value=[fake_plugin]), \
             contextlib.redirect_stdout(io.StringIO()) as screen:
            result = self.scan(callbacks=reporter)
            reporter.finish(result)
        text = screen.getvalue()
        technology_section = text.split('[3] TECHNOLOGY SECURITY')[1].split('[4] UNSUPPORTED PACKAGES')[0]
        self.assertIn('HIGH  unsafe setting | config.ini:12', technology_section)
        self.assertIn('Checks: 1 | Findings: 1', technology_section)
        self.assertEqual(len(result['findings']), 2)
        self.assertIn('Example', result['technologies'])

    def test_without_plugins_reports_no_specialized_scanner(self):
        reporter = TerminalReport()
        with patch('repo_sec_scan.core.inventory', return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()) as screen:
            result = self.scan(callbacks=reporter)
            reporter.finish(result)
        text = screen.getvalue()
        self.assertIn('No specialized scanner selected', text.split('[3] TECHNOLOGY SECURITY')[1].split('[4] UNSUPPORTED PACKAGES')[0])
        self.assertIn('Unsupported packages:        4', text)
        self.assertNotIn('specialized: ', json.dumps(result))

    def test_oversized_file_reports_coverage_problem_under_check(self):
        (self.root / 'large.txt').write_bytes(b'!' * 1_000_001)
        reporter = TerminalReport()
        with contextlib.redirect_stdout(io.StringIO()) as screen:
            result = self.scan(callbacks=reporter)
            reporter.finish(result)
        text = screen.getvalue()
        repository_section = text.split('[2] REPOSITORY SECURITY')[1].split('[3] TECHNOLOGY SECURITY')[0]
        self.assertIn('large.txt: generic scan skipped oversized file', repository_section)
        self.assertIn('INCOMPLETE', repository_section)
        self.assertIn('Scan coverage:               INCOMPLETE', text)
        self.assertTrue(result['coverage_issues'])

    def test_short_package_preserves_non_digest_names(self):
        self.assertEqual(_short_package('pip'), 'pip')
        self.assertEqual(_short_package(self.unknown), 'ghcr.io/windmill-labs/caddy-l4:2.11.4-1')


if __name__ == '__main__':
    unittest.main()
