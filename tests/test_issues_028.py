"""Traceability for ISS-014 through ISS-019."""
import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from habibi import cli
from habibi.core import _credential_assignment, audit, generic_scan
from habibi.models import Context
from habibi.plugins import manager
from habibi.reporting import TerminalReport


class Issues028(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        self.custom = self.root / 'plugins'
        self.custom.mkdir()
        env = patch.dict(os.environ, {'HABIBI_PLUGIN_DIR': str(self.custom)})
        env.start()
        self.addCleanup(env.stop)

    def test_014_no_started_output_and_final_status(self):
        report = TerminalReport()
        with contextlib.redirect_stdout(io.StringIO()) as screen:
            with patch('habibi.core.gitleaks_scan', return_value=('pass', [])), \
                 patch('habibi.core.staged_scan', return_value=('pass', [])):
                result = audit(self.repo, progress=report)
                report.finish(result)
        self.assertNotIn('STARTED', screen.getvalue())
        self.assertIn('Git history', screen.getvalue())
        self.assertIn('PASS', screen.getvalue())

    def test_015_all_user_examples_detected(self):
        cases = ['USER1_PWD=hello1234', 'USER1_PASSWORD=hello1234',
                 'password=hello1234', 'password="hello1234"',
                 'PWD="hello1234"', 'user_password="hello1234"']
        for case in cases:
            with self.subTest(case=case):
                self.assertTrue(_credential_assignment(case))

    def test_015_credential_variants_and_placeholders(self):
        for case in ['password = "short"', 'api_key: abcdef', 'access_token=abc123',
                     "CLIENT_SECRET='abc123'", 'db-passwd = password1']:
            with self.subTest(case=case):
                self.assertTrue(_credential_assignment(case))
        for case in ['api_key="${API_KEY}"', 'password="changeme"', 'password=""',
                     'password="placeholder"', 'password="$var:password"',
                     'password = os.getenv("PASSWORD")', '# password=not_a_secret',
                     'password="xxxxxxxx"', 'non_secret_name=hello1234',
                     'user=hello1234']:
            with self.subTest(case=case):
                self.assertFalse(_credential_assignment(case))

    def test_015_sensitive_values_never_in_findings(self):
        path = self.repo / 'example.conf'
        path.write_text('USER1_PWD=hello1234\nuser_password="VerySensitive123"\n')
        findings = generic_scan(Context(self.repo, [path]))
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.severity == 'high' for f in findings))
        self.assertNotIn('hello1234', str(findings))
        self.assertNotIn('VerySensitive123', str(findings))
        self.assertEqual([f.line for f in findings], [1, 2])

    def test_015_early_stop_and_untracked(self):
        (self.repo / 'untracked.conf').write_text('USER1_PASSWORD=hello1234')
        with patch('habibi.core.gitleaks_scan', return_value=('pass', [])), \
             patch('habibi.core.staged_scan', return_value=('pass', [])):
            result = audit(self.repo, stop_on_finding=True)
        self.assertTrue(result['stopped_early'])
        self.assertTrue(any(f['path'] == 'untracked.conf' for f in result['findings']))

    def test_016_missing_repo_path_explained_not_traceback(self):
        missing = self.root / 'does-not-exist'
        with contextlib.redirect_stderr(io.StringIO()) as error:
            code = cli.main([str(missing)])
        self.assertEqual(code, 2)
        self.assertIn('Repository path does not exist', error.getvalue())
        self.assertNotIn('Traceback', error.getvalue())

    def test_016_file_instead_of_directory(self):
        path = self.root / 'file'
        path.write_text('x')
        with contextlib.redirect_stderr(io.StringIO()) as error:
            code = cli.main([str(path)])
        self.assertEqual(code, 2)
        self.assertIn('not a directory', error.getvalue())

    def test_016_oserror_during_git_lookup(self):
        with patch('habibi.cli.shutil.which', return_value='/usr/bin/tool'), \
             patch('habibi.cli.subprocess.run', side_effect=PermissionError(13, 'Permission denied')):
            with contextlib.redirect_stderr(io.StringIO()) as error:
                code = cli.main([str(self.repo)])
        self.assertEqual(code, 2)
        self.assertIn('Cannot access repository path', error.getvalue())

    def test_017_description_heading(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as exit_: cli.main(['--help'])
        self.assertEqual(exit_.exception.code, 0)
        self.assertIn('Description:\n  Read-only Git repository security audit.', output.getvalue())

    def test_018_help_enumerates_five_commands(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit): cli.main(['--help'])
        text = output.getvalue().split('Commands:', 1)[1].split('positional arguments:', 1)[0]
        for command in ('list', 'info <name>', 'audit [name]', 'install <file>', 'remove <name>'):
            self.assertIn('habibi plugins ' + command, text)

    def test_019_info_dividers_built_in(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = manager.plugin_command(['info', 'windmill.py'])
        self.assertEqual(result, 0)
        self.assertIn('Windmill | Built-in | Active', output.getvalue())
        self.assertIn('-' * 50, output.getvalue())
        self.assertIn('Filename:      windmill.py', output.getvalue())

    def test_019_info_dividers_with_override(self):
        source = Path(__file__).parents[1] / 'habibi' / 'plugins' / 'windmill.py'
        custom = self.custom / 'windmill.py'
        custom.write_text(source.read_text().replace("'version': '1.0.0'", "'version': '2.0.1'"))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = manager.plugin_command(['info', 'windmill.py'])
        self.assertEqual(result, 0)
        text = output.getvalue()
        self.assertIn('Windmill | Built-in | Overridden', text)
        self.assertIn('Windmill | Custom | Active', text)
        self.assertEqual(text.count('Filename:      windmill.py'), 2)

if __name__ == '__main__': unittest.main()
