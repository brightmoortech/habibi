"""Independent v0.3.0 rename and fresh-install requirements."""
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from habibi import cli
from habibi._version import __version__
from habibi.plugins import registry
ROOT = Path(__file__).resolve().parents[1]

class HabibiRenameTests(unittest.TestCase):
    def test_source_version_and_entrypoint(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as result: cli.main(['--version'])
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), 'habibi ' + __version__)
        run = subprocess.run([sys.executable, '-m', 'habibi', '--version'], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), 'habibi ' + __version__)

    def test_executable_sources_contain_no_old_names(self):
        source_files = list((ROOT/'habibi').rglob('*.py')) + [ROOT/'install.sh', ROOT/'pyproject.toml']
        for file in source_files:
            data = file.read_text(encoding='utf-8')
            for term in ('repo_sec_scan','repo-sec-scan','SECSCAN_','secscan'):
                self.assertNotIn(term, data, str(file))

    def test_custom_plugin_directory_is_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(Path, 'home', return_value=Path(tmp)):
                with patch.dict(os.environ, {}, clear=True):
                    self.assertEqual(registry.external_directory(), Path(tmp)/'.local/share/habibi/plugins')
            with patch.dict(os.environ, {'HABIBI_PLUGIN_DIR':tmp}):
                self.assertEqual(registry.external_directory(), Path(tmp).resolve())

    def test_built_in_plugin_copied_as_custom(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            source = (ROOT/'habibi/plugins/windmill.py').read_text()
            self.assertIn('from habibi.models import', source)
            (directory/'windmill.py').write_text(source.replace('1.0.0','2.0.1'))
            with patch.dict(os.environ, {'HABIBI_PLUGIN_DIR':str(directory)}):
                rows=registry.inventory()
            custom=[r for r in rows if r[0]==(directory/'windmill.py').resolve()]
            self.assertEqual(len(custom),1)
            self.assertIsNotNone(custom[0][1], custom[0][3])
            self.assertEqual(custom[0][2]['version'],'2.0.1')
            builtin=[r for r in rows if r[0]==registry.BUILTIN_DIRECTORY/'windmill.py']
            self.assertEqual(builtin[0][3],'overridden')

    def test_installer_and_documentation_consistency(self):
        installer=(ROOT/'install.sh').read_text()
        for item in ('HABIBI_PREFIX','lib/habibi','bin/habibi',"version('habibi')"):
            self.assertIn(item, installer)
        self.assertEqual(sorted(p.name for p in ROOT.glob('*.md')), ['README.md','RELEASE_NOTES.md'])
        readme=(ROOT/'README.md').read_text()
        self.assertIn('~/.local/share/secscan/plugins/',readme) # historical migration path
        self.assertIn('~/.local/share/habibi/plugins/',readme)

if __name__=='__main__': unittest.main()
