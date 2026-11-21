import re
from ..models import Context, Finding, PluginResult

TRUST = re.compile(r'^\s*(?:local|host(?:ssl|nossl)?)\s+\S+\s+\S+(?:\s+\S+)?\s+trust(?:\s|$)', re.I)
SUPERUSER = re.compile(r'(?i)\b(?:CREATE|ALTER)\s+ROLE\b[^;\n]*\bSUPERUSER\b')
GRANT_PUBLIC = re.compile(r'(?i)\bGRANT\s+ALL(?:\s+PRIVILEGES)?\s+ON\b[^;\n]*\bTO\s+PUBLIC\b')
DANGEROUS = re.compile(r'(?i)\bDROP\s+(?:SCHEMA|TABLE|DATABASE)\b[^;\n]*\bCASCADE\b')
CONN_URL = re.compile(r'(?i)\bpostgres(?:ql)?://[^\s/@:]+:[^\s/@]+@')

class PostgreSQLPlugin:
    name = 'PostgreSQL'
    technologies = ('PostgreSQL',)

    def matches(self, package_name: str) -> bool:
        name = package_name.lower().split('@sha256:')[0].split(':')[0].split('/')[-1]
        return name in {'postgres', 'postgresql', 'psycopg', 'psycopg2', 'psycopg2-binary', 'asyncpg', 'pg', 'pg8000'}

    def detect(self, context: Context) -> bool:
        for path in context.files:
            rel = path.relative_to(context.root).as_posix().lower()
            if path.name in {'pg_hba.conf', 'postgresql.conf', 'pg_ident.conf'} or 'postgres' in rel:
                return True
        return False

    def scan(self, context: Context, stop_on_finding: bool = False) -> PluginResult:
        result = PluginResult(self.name, ['PostgreSQL'])
        for path in context.files:
            rel = path.relative_to(context.root).as_posix()
            if path.suffix.lower() not in {'.sql', '.conf', '.yaml', '.yml', '.toml', '.env', '.py', '.sh'}:
                continue
            try:
                if path.stat().st_size > 1_000_000:
                    result.coverage_issues.append(f'{rel}: PostgreSQL scan skipped oversized file')
                    continue
            except OSError:
                result.coverage_issues.append(f'{rel}: PostgreSQL scan could not stat file')
                continue
            try:
                with path.open(encoding='utf-8', errors='replace') as f:
                    for lineno, line in enumerate(f, 1):
                        checks = [(CONN_URL, 'embedded PostgreSQL connection credential', 'high')]
                        if path.name == 'pg_hba.conf':
                            checks.append((TRUST, 'pg_hba.conf trust authentication', 'high'))
                        if path.suffix.lower() == '.sql':
                            checks += [(SUPERUSER, 'superuser role declaration (review)', 'warning'),
                                       (GRANT_PUBLIC, 'broad PUBLIC privileges (review)', 'warning'),
                                       (DANGEROUS, 'destructive CASCADE statement (review context)', 'warning')]
                        for regex, category, severity in checks:
                            if regex.search(line):
                                result.findings.append(Finding(self.name, category, severity, rel, lineno))
                                if stop_on_finding and severity == 'high':
                                    return result
            except OSError:
                result.coverage_issues.append(f'{rel}: {self.name} scan could not read file')
        return result

PLUGIN = PostgreSQLPlugin()


def info():
    return {
        "name": "PostgreSQL",
        "version": "1.0.0",
        "technologies": ["PostgreSQL"],
        "description": "PostgreSQL repository security checks",
    }
