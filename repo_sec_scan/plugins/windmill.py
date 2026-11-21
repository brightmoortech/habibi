import re
from repo_sec_scan.models import Context, Finding, PluginResult

# This plugin inspects repository content only; it never calls a Windmill API.
CREDENTIAL = re.compile(r'''(?i)(?:client[_-]?secret|access[_-]?token|refresh[_-]?token|api[_-]?key|password)\s*[:=]\s*['"]([^'"\s]{8,})['"]''')
REFERENCE = re.compile(r'\$var:|\$res:|wmill\.get_(?:variable|resource)\s*\(', re.I)
RESOURCE_VALUE = re.compile(r'(?i)^\s*(?:value|secret|password|token)\s*:\s*(?!\s*(?:\$var:|\$res:|\$env:|\$res:|null|\{\}|\[\]|#|$))\S+')

class WindmillPlugin:
    name = 'Windmill'
    technologies = ('Windmill',)

    def matches(self, package_name: str) -> bool:
        return 'windmill' in package_name.lower().split('/')[-1].split(':')[0] or 'windmill' in package_name.lower().split('/')[-2:-1]

    def detect(self, context: Context) -> bool:
        for path in context.files:
            rel = path.relative_to(context.root).as_posix().lower()
            if (rel.startswith('windmill/') or path.name.endswith(('.flow.yaml', '.flow.yml')) or
                    path.name in {'wmill.yaml', 'wmill-lock.yaml'}):
                return True
        return False

    def scan(self, context: Context, stop_on_finding: bool = False) -> PluginResult:
        result = PluginResult(self.name, ['Windmill'])
        for path in context.files:
            rel = path.relative_to(context.root).as_posix()
            if not (rel.lower().startswith('windmill/') or path.name.endswith(('.flow.yaml', '.flow.yml')) or path.name == 'wmill.yaml'):
                continue
            if path.suffix.lower() not in {'.yaml', '.yml', '.json', '.py', '.ts', '.sh'}:
                continue
            try:
                if path.stat().st_size > 1_000_000:
                    result.coverage_issues.append(f'{rel}: Windmill scan skipped oversized file')
                    continue
            except OSError:
                result.coverage_issues.append(f'{rel}: Windmill scan could not stat file')
                continue
            try:
                with path.open(encoding='utf-8', errors='replace') as f:
                    for lineno, line in enumerate(f, 1):
                        if CREDENTIAL.search(line) or (('resources/' in rel or 'variables/' in rel) and RESOURCE_VALUE.search(line)):
                            result.findings.append(Finding(self.name, 'possible hardcoded Windmill credential or exported value', 'high', rel, lineno))
                        elif REFERENCE.search(line):
                            # References alone are expected and do not constitute exposures.
                            continue
                        if stop_on_finding and result.findings:
                            return result
            except OSError:
                result.coverage_issues.append(f'{rel}: {self.name} scan could not read file')
        return result

PLUGIN = WindmillPlugin()


def info():
    return {
        "name": "Windmill",
        "version": "1.0.0",
        "technologies": ["Windmill"],
        "description": "Windmill repository security checks",
    }
