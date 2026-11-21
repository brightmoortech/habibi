"""v0.2.3 contract tests: plugin self-description, management and safety."""
import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from habibi.plugins import manager, registry, security
from habibi.core import audit

TEMPLATE = '''from habibi.models import PluginResult
class Scanner:
    name = "{name}"
    def matches(self, package): return package == "{match}"
    def detect(self, context): return False
    def scan(self, context, stop_on_finding=False): return PluginResult(self.name)
PLUGIN = Scanner()
def info():
    return {{"name": "{name}", "version": "{version}", "technologies": ["{name}"], "description": "test scanning"}}
'''


class PluginLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plugin_dir = self.root / 'installed'
        self.plugin_dir.mkdir()
        self.rules = self.root / 'rules.txt'
        self.rules.write_text('shutil.rmtree\nos.remove\nos.system\neval\nexec\n')
        env = patch.dict(os.environ, {'HABIBI_PLUGIN_DIR': str(self.plugin_dir), 'HABIBI_PLUGIN_RULES': str(self.rules)})
        env.start()
        self.addCleanup(env.stop)

    def source(self, version='1.0.0', name='Custom', filename='source.py', body=None):
        path = self.root / filename
        path.write_text(body if body is not None else TEMPLATE.format(name=name, version=version, match='custom-pkg'))
        return path

    def command(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            status = manager.plugin_command(list(args))
        return status, out.getvalue(), err.getvalue()

    def test_bundled_no_hardcoded_registry(self):
        names = {p.name for p in registry.load_plugins()}
        self.assertTrue({'PostgreSQL', 'Windmill'} <= names)
        code = Path(registry.__file__).read_text()
        self.assertNotIn('from .windmill import', code)
        self.assertNotIn('from .postgresql import', code)

    def test_builtin_metadata_and_interfaces(self):
        for name in ('windmill', 'postgresql'):
            path = registry.BUILTIN_DIRECTORY / (name + '.py')
            plugin, info = registry.load(path)
            self.assertEqual(plugin.name, info['name'])
            self.assertIn('version', info)
            self.assertGreater(len(info['technologies']), 0)
            self.assertIn('description', info)

    def test_automatic_directory_discovery(self):
        self.source().replace(self.plugin_dir / 'custom.py')
        self.assertIn('Custom', [p.name for p in registry.load_plugins()])

    def test_invalid_plugin_skipped_and_audited(self):
        (self.plugin_dir / 'bad.py').write_text('VALUE = 1\n')
        self.assertNotIn('bad', [p.name.casefold() for p in registry.load_plugins()])
        status, output, _ = self.command('audit')
        self.assertEqual(status, 1)
        self.assertIn('FAIL  bad.py', output)
        self.assertIn('missing info()', output)

    def test_audit_one_name_and_all(self):
        self.source().replace(self.plugin_dir / 'custom.py')
        status, output, _ = self.command('audit', 'custom')
        self.assertEqual(status, 0)
        self.assertIn('Custom', output)
        self.assertNotIn('PostgreSQL', output)
        self.assertEqual(self.command('audit')[0], 0)

    def test_plugin_list_columns_and_info(self):
        self.source().replace(self.plugin_dir / 'custom.py')
        status, output, _ = self.command('list')
        self.assertEqual(status, 0)
        for item in ('PLUGIN NAME', 'VERSION', 'FILENAME', 'Custom', '1.0.0', 'custom.py'):
            self.assertIn(item, output)
        status, output, _ = self.command('info', 'Custom')
        self.assertEqual(status, 0)
        self.assertIn('Technologies:  Custom', output)

    def test_install_reinstall_upgrade(self):
        self.assertEqual(self.command('install', str(self.source()))[0], 0)
        target = self.plugin_dir / 'custom.py'
        self.assertTrue(target.exists())
        self.assertEqual(self.command('install', str(self.source()))[0], 0)
        self.assertEqual(self.command('install', str(self.source('2.0.0')))[0], 0)
        self.assertIn('2.0.0', target.read_text())

    def test_reinstall_repairs_corrupt_existing_plugin(self):
        self.command('install', str(self.source()))
        destination = self.plugin_dir / 'custom.py'
        destination.write_text('not Python !!!\n')
        status, message, _ = self.command('install', str(self.source()))
        self.assertEqual(status, 0)
        self.assertIn('failed audit', message)
        self.assertIn('def info():', destination.read_text())

    def test_downgrade_declined_then_confirmed(self):
        self.command('install', str(self.source('2.0.0')))
        with patch('builtins.input', return_value='n'):
            self.assertEqual(self.command('install', str(self.source('1.0.0')))[0], 1)
        self.assertIn('2.0.0', (self.plugin_dir / 'custom.py').read_text())
        with patch('builtins.input', return_value='y'):
            self.assertEqual(self.command('install', str(self.source('1.0.0')))[0], 0)
        self.assertIn('1.0.0', (self.plugin_dir / 'custom.py').read_text())

    def test_install_blocked_preserves_existing(self):
        self.command('install', str(self.source()))
        original = (self.plugin_dir / 'custom.py').read_bytes()
        source = self.source('2.0.0', body=TEMPLATE.format(name='Custom', version='2.0.0', match='custom-pkg') + '\nimport shutil\nshutil.rmtree("/tmp")\n')
        self.assertEqual(self.command('install', str(source))[0], 2)
        self.assertEqual((self.plugin_dir / 'custom.py').read_bytes(), original)

    def test_failed_activation_restores_existing(self):
        self.command('install', str(self.source()))
        dest = self.plugin_dir / 'custom.py'
        original = dest.read_bytes()
        real_load = registry.load
        def fails_after_activation(path):
            if Path(path).resolve() == dest.resolve():
                raise ValueError('injected post-activation failure')
            return real_load(path)
        with patch.object(registry, 'load', side_effect=fails_after_activation):
            self.assertEqual(self.command('install', str(self.source('2.0.0')))[0], 2)
        self.assertEqual(dest.read_bytes(), original)
        restored, restored_info = registry.load(dest)
        self.assertEqual(restored.name, "Custom")
        self.assertEqual(restored_info["version"], "1.0.0")

    def test_remove_external_but_not_bundled(self):
        self.command('install', str(self.source()))
        self.assertEqual(self.command('remove', 'Custom')[0], 0)
        self.assertFalse((self.plugin_dir / 'custom.py').exists())
        self.assertEqual(self.command('remove', 'Windmill')[0], 2)

    def test_unknown_plugin_reported(self):
        self.assertEqual(self.command('audit', 'missing')[0], 2)
        self.assertEqual(self.command('info', 'missing')[0], 2)

    def test_static_scanner_ignores_comments_detects_calls(self):
        path = self.root / 'example.py'
        path.write_text('import shutil as s\n# shutil.rmtree("safe")\ns.rmtree("danger")\n')
        self.assertEqual(security.inspect(path), [(3, 'shutil.rmtree')])

    def test_custom_flat_rule(self):
        self.rules.write_text('os.chdir\n')
        path = self.root / 'example.py'
        path.write_text('import os\nos.chdir("/tmp")\n')
        self.assertEqual(security.inspect(path), [(2, 'os.chdir')])

    def test_invalid_rules_and_syntax_fail_closed(self):
        self.rules.write_text('not valid rule!!!\n')
        with self.assertRaises(ValueError):
            security.inspect(self.source())
        self.rules.write_text('os.remove\n')
        broken = self.source(body='def bad(: pass\n')
        with self.assertRaises(SyntaxError):
            security.inspect(broken)

    def test_static_scan_precedes_code_execution(self):
        marker = self.root / 'executed'
        source = self.source(body=f'import os\nos.remove("{marker}")\n')
        with patch('builtins.exec', side_effect=AssertionError('executed')):
            with self.assertRaises(ValueError):
                registry.load(source)

    def test_plugins_inside_scanned_repo_never_discovered(self):
        repository = self.root / 'repository'
        repository.mkdir()
        (repository / 'evil.py').write_text(TEMPLATE.format(name='Evil', version='1.0.0', match='evil'))
        self.assertNotIn(repository / 'evil.py', registry.candidates())

    def test_duplicate_name_reported(self):
        self.source().replace(self.plugin_dir / 'custom.py')
        (self.plugin_dir / 'copy.py').write_text(TEMPLATE.format(name='Custom', version='2.0.0', match='x'))
        rows = registry.inventory()
        self.assertTrue(any(error and 'duplicate' in error for _, _, _, error in rows))

    def test_no_root_execution(self):
        with patch('habibi.plugins.manager.os.geteuid', return_value=0):
            self.assertEqual(self.command('list')[0], 2)
            self.assertEqual(self.command('install', str(self.source()))[0], 2)

    def test_plugin_error_reduces_coverage(self):
        from unittest.mock import patch
        from habibi import core
        with patch.object(core, 'inventory', return_value=[(Path('bad.py'), None, None, 'invalid')]), \
             patch.object(core, 'enumerate_files', return_value=[]), \
             patch.object(core, 'gitleaks_scan', return_value=('pass', [])), \
             patch.object(core, 'staged_scan', return_value=('pass', [])):
            result = core.audit(self.root)
        self.assertIn('plugin-error (incomplete)', result['coverage']['plugin_load:bad.py'])

    def test_plugin_commands_do_not_offer_upgrade(self):
        with self.assertRaises(SystemExit) as exit_context:
            self.command('upgrade', str(self.source()))
        self.assertEqual(exit_context.exception.code, 2)

    def test_bundled_new_file_auto_discovered(self):
        # Fake package directory exercises the exact generic discovery path.
        with patch.object(registry, 'BUILTIN_DIRECTORY', self.plugin_dir):
            self.source(name='BrandNew').replace(self.plugin_dir / 'brandnew.py')
            self.assertIn('BrandNew', [plugin.name for plugin in registry.load_plugins()])

    def test_inspected_bytes_are_executed(self):
        source = self.source()
        with patch('habibi.plugins.registry.inspect', wraps=security.inspect) as inspected:
            plugin, info = registry.load(source)
        self.assertEqual(plugin.name, 'Custom')
        self.assertIsNotNone(inspected.call_args.kwargs.get('source'))

    def test_repo_plugin_dir_env_is_never_executed_during_audit(self):
        with patch.dict(os.environ, {'HABIBI_PLUGIN_DIR': str(self.root)}):
            self.source(name='RepoOnly')
            results = registry.inventory(exclude_root=self.root)
        self.assertTrue(any(error and 'inside repository' in error for _, _, _, error in results))

    def test_external_plugin_directory_not_tied_to_release(self):
        self.assertEqual(registry.external_directory().resolve(), self.plugin_dir.resolve())
        self.assertNotIn('releases', str(self.plugin_dir))

    def test_installer_static_only(self):
        status, output, _ = self.command('audit', '--static-only')
        self.assertEqual(status, 0)
        self.assertIn('static inspection', output)
        installer = Path(__file__).resolve().parents[1] / 'install.sh'
        self.assertIn('plugins audit --static-only', installer.read_text())

    def test_readme_contract(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / 'README.md').read_text()
        for expected in ('def info():', 'PLUGIN = ExamplePlugin()',
                         'habibi plugins audit Example', 'habibi plugins install ./example.py',
                         'plugin_security_rules.txt', 'does not prove a plugin is safe',
                         'Never run plugin commands with `sudo`'):
            self.assertIn(expected, readme)

    def test_legacy_cli_and_help(self):
        env = dict(os.environ)
        command = [os.sys.executable, '-m', 'habibi']
        test = subprocess.run(command + ['plugins', 'list'], capture_output=True, text=True, env=env)
        self.assertEqual(test.returncode, 0, test.stderr)
        self.assertIn('FILENAME', test.stdout)
        help_result = subprocess.run(command + ['--help'], capture_output=True, text=True, env=env)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn('habibi plugins audit', help_result.stdout)


if __name__ == '__main__':
    unittest.main()
