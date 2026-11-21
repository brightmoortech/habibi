"""Regression cases for 0.2.4 CLI and built-in/Custom override contract."""
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from repo_sec_scan import cli
from repo_sec_scan.plugins import manager, registry
from repo_sec_scan.core import audit
from test_plugin_lifecycle_023 import TEMPLATE


class Overrides024(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.directory = self.root / 'plugins'
        self.directory.mkdir()
        rules = self.root / 'rules.txt'
        rules.write_text('os.remove\nshutil.rmtree\nexec\neval\n')
        patcher = patch.dict(os.environ, {'SECSCAN_PLUGIN_DIR': str(self.directory), 'SECSCAN_PLUGIN_RULES': str(rules)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def command(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = manager.plugin_command(list(args))
        return code, out.getvalue(), err.getvalue()

    def overridden(self, filename='windmill.py', version='3.0.0'):
        path = self.root / ('source_' + filename)
        path.write_text(TEMPLATE.format(name='Windmill', version=version, match='windmill'))
        return path

    def test_version_and_help_show_commands(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as end:
                cli.main(['--version'])
        self.assertEqual(end.exception.code, 0)
        self.assertIn('secscan 0.2.4', out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit):
                cli.main(['--help'])
        self.assertIn('secscan plugins <command>', out.getvalue())
        self.assertIn('secscan plugins audit', out.getvalue())

    def test_redundant_option_removed(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as end:
                cli.main(['--list-plugins'])
        self.assertEqual(end.exception.code, 2)

    def test_built_in_list_has_type_and_status(self):
        code, text, _ = self.command('list')
        self.assertEqual(code, 0)
        for expected in ('TYPE', 'STATUS', 'Built-in', 'Active', 'windmill.py', 'postgresql.py'):
            self.assertIn(expected, text)

    def test_install_custom_same_filename_overrides_and_remove_restores(self):
        source = self.overridden()
        code, _, error = self.command('install', str(source))
        self.assertEqual(code, 0, error)
        target = self.directory / 'windmill.py'
        self.assertTrue(target.is_file())
        rows = registry.inventory()
        windmill = [r for r in rows if r[2] and r[2]['name'] == 'Windmill']
        self.assertEqual(len(windmill), 2)
        self.assertEqual(len([r for r in windmill if r[3] is None]), 1)
        self.assertEqual(next(r for r in windmill if r[3] is None)[0], target)
        self.assertEqual(next(r for r in windmill if r[0].parent == registry.BUILTIN_DIRECTORY)[3], 'overridden')
        self.assertEqual(len([p for p in registry.load_plugins() if p.name == 'Windmill']), 1)
        code, listing, _ = self.command('list')
        self.assertEqual(code, 0)
        self.assertIn('Custom', listing)
        self.assertIn('Overridden', listing)
        self.assertEqual(listing.count('windmill.py'), 2)
        code, _, _ = self.command('remove', 'Windmill')
        self.assertEqual(code, 0)
        self.assertFalse(target.exists())
        self.assertEqual(len([p for p in registry.load_plugins() if p.name == 'Windmill']), 1)
        code, listing, _ = self.command('list')
        self.assertEqual(code, 0)
        self.assertNotIn('Overridden', listing)

    def test_install_override_does_not_modify_builtin(self):
        builtin = registry.BUILTIN_DIRECTORY / 'windmill.py'
        before = builtin.read_bytes()
        self.assertEqual(self.command('install', str(self.overridden()))[0], 0)
        self.assertEqual(builtin.read_bytes(), before)

    def test_direct_filename_lookup_does_not_inventory_all(self):
        path = self.directory / 'windmill.py'
        path.write_text(TEMPLATE.format(name='Windmill', version='3.0.0', match='windmill'))
        with patch.object(registry, 'inventory', side_effect=AssertionError('unexpected full inventory')):
            matches = manager._matching('windmill.py')
        self.assertEqual({r[0].parent for r in matches}, {registry.BUILTIN_DIRECTORY, self.directory})

    def test_fallback_display_name(self):
        source = self.root / 'custom.py'
        source.write_text(TEMPLATE.format(name='MyPlugin', version='1.0.0', match='x'))
        # Noncanonical file must remain discoverable by declared display name.
        target = self.directory / 'different.py'
        target.write_bytes(source.read_bytes())
        matches = manager._matching('MyPlugin')
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], target)

    def test_override_security_failure_does_not_replace_builtin_or_load_custom(self):
        self.directory.joinpath('windmill.py').write_text('import os\nos.remove("/tmp/not-executed")\n')
        rows = registry.inventory()
        self.assertEqual(len([p for _, p, info, error in rows if p and info['name'] == 'Windmill']), 1)
        self.assertTrue(any(path.name == 'windmill.py' and err for path, _, _, err in rows))
        code, listing, _ = self.command('list')
        self.assertEqual(code, 0)
        self.assertIn('Invalid', listing)
        self.assertEqual(self.command('audit', 'windmill.py')[0], 1)

    def test_same_name_custom_upgrade_downgrade_and_reinstall(self):
        self.assertEqual(self.command('install', str(self.overridden()))[0], 0)
        self.assertEqual(self.command('install', str(self.overridden(version='3.0.0')))[0], 0)
        with patch('builtins.input', return_value='n'):
            self.assertEqual(self.command('install', str(self.overridden(version='2.0.0')))[0], 1)
        with patch('builtins.input', return_value='y'):
            self.assertEqual(self.command('install', str(self.overridden(version='2.0.0')))[0], 0)
        self.assertIn('2.0.0', (self.directory / 'windmill.py').read_text())

    def test_info_supports_display_name_and_filename(self):
        self.assertEqual(self.command('install', str(self.overridden()))[0], 0)
        for value in ('Windmill', 'windmill.py'):
            code, text, _ = self.command('info', value)
            self.assertEqual(code, 0)
            self.assertIn('Custom', text)
            self.assertIn('Built-in', text)

    def test_built_in_cannot_be_removed_directly(self):
        code, _, error = self.command('remove', 'PostgreSQL')
        self.assertEqual(code, 2)
        self.assertIn('Built-in', error)


if __name__ == '__main__':
    unittest.main()
