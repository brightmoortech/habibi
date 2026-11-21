"""v0.2.6 usage-contract and standalone Built-in plugin copy tests."""
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from habibi import cli
from habibi.plugins import manager, registry
from habibi._version import __version__


class PortablePlugins026(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.custom = self.root / 'plugins'
        self.custom.mkdir()
        patcher = patch.dict(os.environ, {'HABIBI_PLUGIN_DIR': str(self.custom)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_plugin(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as error:
            code = manager.plugin_command(list(args))
        return code, output.getvalue(), error.getvalue()

    def test_main_help_has_two_usage_paths(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as exc:
                cli.main(['-h'])
        self.assertEqual(exc.exception.code, 0)
        help_text = output.getvalue()
        self.assertIn('habibi [-h]', help_text)
        self.assertIn('habibi plugins <command> [arguments]', help_text)
        self.assertIn('usage:', help_text)

    def test_plugin_help_documents_all_syntax(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as exc:
                manager.plugin_command(['-h'])
        self.assertEqual(exc.exception.code, 0)
        text = output.getvalue()
        for command in ('list', 'info <name>', 'audit [name]', 'install <file>', 'remove <name>'):
            self.assertIn('habibi plugins ' + command, text)
        self.assertIn('Plugin management commands:', text)
        self.assertIn('Remove a Custom plugin', text)

    def test_each_plugin_subcommand_has_help(self):
        for command in ('list', 'info', 'audit', 'install', 'remove'):
            with self.subTest(command=command):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    with self.assertRaises(SystemExit) as exc:
                        manager.plugin_command([command, '--help'])
                self.assertEqual(exc.exception.code, 0)
                self.assertIn('usage:', output.getvalue())

    def test_copied_builtin_installs_as_custom_and_restores(self):
        for stem, display in (('windmill', 'Windmill'), ('postgresql', 'PostgreSQL')):
            with self.subTest(plugin=stem):
                original = registry.BUILTIN_DIRECTORY / (stem + '.py')
                source = self.root / (stem + '.py')
                content = original.read_text(encoding='utf-8')
                self.assertIn('from habibi.models import', content)
                source.write_text(content.replace('"version": "1.0.0"', '"version": "2.0.0"'), encoding='utf-8')
                self.assertIn('"version": "2.0.0"', source.read_text())
                before = original.read_bytes()
                code, _, error = self.run_plugin('install', str(source))
                self.assertEqual(code, 0, error)
                target = self.custom / (stem + '.py')
                self.assertTrue(target.exists())
                self.assertEqual(original.read_bytes(), before)
                rows = [r for r in registry.inventory() if r[2] and r[2]['name'] == display]
                self.assertEqual(len(rows), 2)
                self.assertEqual(len([r for r in rows if r[3] is None]), 1)
                self.assertEqual(len([r for r in rows if r[3] == 'overridden']), 1)
                code, _, error = self.run_plugin('remove', display)
                self.assertEqual(code, 0, error)
                self.assertFalse(target.exists())
                rows = [r for r in registry.inventory() if r[2] and r[2]['name'] == display]
                self.assertEqual(len(rows), 1)
                self.assertIsNone(rows[0][3])

    def test_version(self):
        self.assertRegex(__version__, r'^\d+\.\d+\.\d+$')


if __name__ == '__main__':
    unittest.main()
