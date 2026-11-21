"""Terminal-only progress rendering; the core scan and JSON stay UI-independent."""
from collections import Counter


def _short_package(package):
    """Hide long image digests in terminal output; JSON retains full references."""
    return package.split('@sha256:', 1)[0]


def _problems(findings, issues):
    for finding in findings:
        location = finding.get('path') or '(repository)'
        if finding.get('line'):
            location += f":{finding['line']}"
        print(f"      {finding['severity'].upper()}  {finding['category']} | {location}")
    for issue in issues:
        print(f'      INCOMPLETE  {issue}')


def _status(status, count):
    if 'error' in status or 'incomplete' in status:
        return 'INCOMPLETE'
    if count or status == 'findings':
        return f'FINDINGS ({count})'
    return 'PASS'


class TerminalReport:
    """Consumes optional core audit events without affecting audit execution."""

    def __init__(self):
        self.started = set()
        self.completed = set()
        self.unsupported = []
        self.section_counts = {"repository": 0, "technology": 0}
        self.section_findings = {"repository": 0, "technology": 0}
        self.section_limitations = {"repository": 0, "technology": 0}

    def __call__(self, event):
        kind = event['kind']
        if kind == 'discovery_start':
            print('\n[1] DISCOVERED TECHNOLOGIES')
            print('    Discovering repository technologies...')
        elif kind == 'discovery_complete':
            technologies = event['technologies']
            if not technologies:
                print('    None identified (generic scanning remains available)')
            for name, evidence in technologies.items():
                suffix = f" ({len(evidence)} evidence file(s))" if evidence else ' (configuration detected)'
                print(f'    {name:<22} Detected{suffix}')
            print(f'    Total: {len(technologies)} technologies')
            if event['issues']:
                print('    Discovery incomplete:')
                for issue in event['issues']:
                    print(f'      {issue}')
            self.completed.add('discovery')
        elif kind == 'repository_start':
            print('\n[2] REPOSITORY SECURITY')
            self.started.add('repository')
        elif kind == 'technology_start':
            self._section_summary('repository')
            print('\n[3] TECHNOLOGY SECURITY')
            self.started.add('technology')
        elif kind == 'check_start':
            print(f"    {event['label']:<22} STARTED", flush=True)
        elif kind == 'check_complete':
            findings = event['findings']
            issues = event['issues']
            self.section_counts[event['section']] += 1
            self.section_findings[event['section']] += len(findings)
            self.section_limitations[event['section']] += len(issues) + int('error' in event['status'] or 'incomplete' in event['status'])
            print(f"    {event['label']:<22} {_status(event['status'], len(findings))}")
            _problems(findings, issues)
        elif kind == 'unsupported':
            if not self.section_counts['technology']:
                print('    No specialized scanner selected')
            self._section_summary('technology')
            print('\n[4] UNSUPPORTED PACKAGES')
            self.unsupported = event['packages']
            if not self.unsupported:
                print('    None')
            for package in self.unsupported:
                print(f'    {_short_package(package)}  Generic checks only')
            print(f'    Total: {len(self.unsupported)} packages without specialized scanning')
            self.completed.add('unsupported')

    def _section_summary(self, section):
        print(f"    Checks: {self.section_counts[section]} | Findings: {self.section_findings[section]} | Coverage limitations: {self.section_limitations[section]}")

    def finish(self, result):
        if 'repository' in self.started and 'technology' not in self.started:
            self._section_summary('repository')
        if 'technology' in self.started and 'unsupported' not in self.completed:
            self._section_summary('technology')
        if 'technology' not in self.started:
            print('\n[3] TECHNOLOGY SECURITY')
            print('    NOT RUN (scan stopped early)' if result['stopped_early'] else '    None required')
        if 'unsupported' not in self.completed:
            print('\n[4] UNSUPPORTED PACKAGES')
            print('    NOT EVALUATED (scan stopped early)')

        counts = Counter(f['severity'].lower() for f in result['findings'])
        coverage = result['coverage']
        incomplete = (result['stopped_early'] or bool(result.get('coverage_issues'))
                      or any('error' in status or 'incomplete' in status
                             for status in coverage.values()))
        print('\nSCAN SUMMARY')
        print('    Technologies detected:      ', len(result['technologies']))
        print('    Specialized scanners run:   ', sum(k.startswith('plugin:') for k in coverage))
        print('    Unsupported packages:       ', len(self.unsupported) if 'unsupported' in self.completed else 'Not evaluated')
        print('    Security findings:          ', len(result['findings']),
              '(' + ', '.join(f'{n} {severity}' for severity, n in sorted(counts.items())) + ')' if counts else '(none)')
        limitation_keys = {f'issue:{issue}' for issue in result.get('coverage_issues', [])}
        for key, status in coverage.items():
            if 'error' in status or ('incomplete' in status and not result.get('coverage_issues')):
                limitation_keys.add(f'check:{key}')
        print('    Coverage limitations:       ', len(limitation_keys))
        print('    Scan coverage:              ', 'INCOMPLETE' if incomplete else 'COMPLETE')
        if result.get('coverage_issues'):
            print('    Coverage details:')
            for issue in result['coverage_issues']:
                print(f'      {issue}')
        for key, value in coverage.items():
            if 'error' in value or 'incomplete' in value:
                print(f'      {key}: {value}')
        if result['stopped_early']:
            print('    Scan stopped on a high-severity finding; remaining checks unverified.')
