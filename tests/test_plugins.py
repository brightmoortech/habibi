import tempfile
import unittest
from pathlib import Path
from repo_sec_scan.discovery import discover
from repo_sec_scan.models import Context
from repo_sec_scan.plugins.postgresql import PLUGIN as PG
from repo_sec_scan.plugins.windmill import PLUGIN as WM
from repo_sec_scan.core import generic_scan

class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def ctx(self, files):
        paths=[]
        for name, value in files.items():
            p=self.root/name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(value)
            paths.append(p)
        return Context(self.root, paths)

    def test_discover(self):
        ctx=self.ctx({'pyproject.toml':'', 'windmill/test.flow.yaml':'$var:foo', 'pg_hba.conf':'host all all 0.0.0.0/0 trust'})
        tech=discover(ctx)
        self.assertIn('Python', tech)
        self.assertTrue(WM.detect(ctx))
        self.assertTrue(PG.detect(ctx))

    def test_windmill_ref_not_secret(self):
        ctx=self.ctx({'windmill/test.flow.yaml':'value: $var:u/user/secret\n'})
        self.assertFalse(WM.scan(ctx).findings)

    def test_windmill_literal(self):
        ctx=self.ctx({'windmill/test.flow.yaml':'client_secret: "example123456789"\n'})
        self.assertEqual(len(WM.scan(ctx).findings), 1)

    def test_postgres_trust(self):
        ctx=self.ctx({'pg_hba.conf':'# comment\nhost all all 0.0.0.0/0 trust\n'})
        self.assertEqual(PG.scan(ctx).findings[0].line, 2)

    def test_sql_cascade_is_warning(self):
        ctx=self.ctx({'schema.sql':'DROP TABLE app.clients CASCADE;\n'})
        self.assertEqual(PG.scan(ctx).findings[0].severity, 'warning')

    def test_postgres_stop_on_finding_ignores_review_warnings(self):
        ctx=self.ctx({'schema.sql': 'DROP TABLE app.clients CASCADE;\nGRANT ALL ON app.clients TO PUBLIC;\n'})
        self.assertEqual(len(PG.scan(ctx, stop_on_finding=True).findings), 2)

    def test_generic_literal(self):
        ctx=self.ctx({'settings.py':'password = "some-example-secret"\n'})
        self.assertEqual(generic_scan(ctx)[0].severity, 'high')

if __name__ == '__main__':
    unittest.main()
