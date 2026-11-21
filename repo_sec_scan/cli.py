"""Command line entry point. Read-only except explicit dependency installation/report writing."""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from .core import audit


def install_missing(missing):
    system = platform.system()
    brew = shutil.which('brew')
    apt = shutil.which('apt-get')
    for item in missing:
        if system == 'Darwin' and brew:
            command = ['brew', 'install', item]
        elif system == 'Linux' and brew:
            command = ['brew', 'install', item]
        elif system == 'Linux' and apt:
            command = ['sudo', 'apt-get', 'install', item]
        else:
            print(f'No supported package manager for {item}; install manually.', file=sys.stderr)
            return False
        print('Proposed installation:', ' '.join(command))
        try:
            answer = input('Approve this installation? [y/N] ')
        except EOFError:
            answer = ''
        if answer.lower() not in ('y', 'yes'):
            return False
        if subprocess.run(command, check=False).returncode:
            return False
    return all(shutil.which(item) for item in missing)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only public Git repository secret and configuration audit.')
    parser.add_argument('repository', nargs='?', default='.', help='Git project root or a path inside it (default: current directory)')
    parser.add_argument('--stop-on-finding', action='store_true', help='Stop at first high-severity potential exposure; warnings do not stop the audit')
    parser.add_argument('--install-missing', action='store_true', help='Offer interactive Homebrew/APT installation for missing Git/Gitleaks (never silent)')
    parser.add_argument('--report', metavar='PATH', help='Write JSON report (avoid placing report inside the repository)')
    parser.add_argument('--list-plugins', action='store_true', help='Show installed specialized scanner plugins and exit')
    args = parser.parse_args(argv)
    if args.list_plugins:
        from .plugins.registry import PLUGINS
        for p in PLUGINS:
            print(p.name)
        return 0
    missing = [item for item in ('git', 'gitleaks') if not shutil.which(item)]
    if missing and not (args.install_missing and install_missing(missing)):
        print('Missing dependencies: ' + ', '.join(missing), file=sys.stderr)
        print('Install them manually or rerun with --install-missing.', file=sys.stderr)
        return 2
    where = Path(args.repository).expanduser().resolve()
    repo = subprocess.run(['git','rev-parse','--show-toplevel'], cwd=where, capture_output=True, text=True)
    if repo.returncode:
        print('Not inside a Git repository.', file=sys.stderr)
        return 2
    root = Path(repo.stdout.strip()).resolve()
    if args.report:
        report_path = Path(args.report).expanduser().resolve()
        if report_path.is_relative_to(root):
            print('Refusing report path inside scanned repository; choose an external location.', file=sys.stderr)
            return 2
    else:
        report_path = None
    result = audit(root, args.stop_on_finding)
    print('Repository:', root)
    print('Detected technologies:')
    if not result['technologies']:
        print('  None identified; generic scanning only')
    for tech, evidence in result['technologies'].items():
        print(f'  {tech}: {len(evidence)} evidence file(s)')
    print('Declared packages/images:')
    if not result['packages']:
        print('  None identified')
    for package in result['packages']:
        print(f'  {package}')
    print('Scan coverage:')
    for name, status in result['coverage'].items():
        print(f'  {name}: {status}')
        if status.startswith('generic-only'):
            print(f'    No specialized handling for {name}; generic scan applied.')
    if result.get('coverage_issues'):
        print('Coverage limitations:')
        for issue in result['coverage_issues']:
            print('  ' + issue)
    print('Findings:', len(result['findings']))
    for finding in result['findings'][:100]:
        print(f"  [{finding['severity']}] {finding['source']}: {finding['category']} | {finding['path']}:{finding['line']}")
    if len(result['findings']) > 100:
        print(f"  ... {len(result['findings']) - 100} additional findings in report")
    if result['stopped_early']:
        print('Scan stopped early on a finding; remaining coverage unverified.')
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        try:
            os.chmod(report_path, 0o600)
        except OSError:
            pass
        print('Report saved:', report_path)
    incomplete = result['stopped_early'] or bool(result.get('coverage_issues')) or any(('error' in s or 'incomplete' in s) for s in result['coverage'].values())
    return 2 if incomplete else (1 if result['findings'] else 0)

if __name__ == '__main__':
    sys.exit(main())
