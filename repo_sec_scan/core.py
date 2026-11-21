"""Read-only repository audit orchestration. No source lines or secret values in reports."""
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from .models import Context, Finding
from .discovery import discover, discover_packages
from .plugins.registry import inventory

SENSITIVE_NAME = re.compile(r'(?i)(?:^|/)(?:\.env(?:\..+)?|id_rsa|id_ed25519|[^/]+\.(?:pem|p12|pfx|key)|credentials(?:\..+)?|secrets?(?:\..+)?)$')
ASSIGNMENT = re.compile(r'''(?i)\b(?:client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|password)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]''')
URL_CREDS = re.compile(r'(?i)\b(?:postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?)://[^\s/@:]+:[^\s/@]+@')
MAX_FILE_BYTES = 1_000_000


def run(args, cwd, timeout=300):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)


def enumerate_files(root: Path) -> list[Path]:
    cmd = subprocess.run(['git','ls-files','--cached','--others','--exclude-standard','-z'], cwd=root,
                         capture_output=True, check=False)
    if cmd.returncode:
        raise RuntimeError('cannot enumerate Git repository files')
    output = []
    for name in cmd.stdout.split(b'\0'):
        if not name:
            continue
        try:
            rel = Path(os.fsdecode(name))
            full = root / rel
            if not full.is_file() or full.is_symlink() or not full.resolve().is_relative_to(root.resolve()):
                continue
            output.append(full)
        except (OSError, ValueError):
            continue
    return sorted(set(output))


def generic_scan(ctx: Context, stop=False, issues=None) -> list[Finding]:
    findings = []
    for path in ctx.files:
        rel = path.relative_to(ctx.root).as_posix()
        if SENSITIVE_NAME.search(rel):
            findings.append(Finding('Generic', 'sensitive filename (review if tracked)', 'warning', rel))
        if stop and any(f.severity == 'high' for f in findings):
            return findings
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                if issues is not None:
                    issues.append(f'{rel}: generic scan skipped oversized file')
                continue
            with path.open(encoding='utf-8', errors='replace') as f:
                for lineno, line in enumerate(f, 1):
                    if ASSIGNMENT.search(line) or URL_CREDS.search(line):
                        findings.append(Finding('Generic', 'possible literal credential', 'high', rel, lineno))
                        if stop:
                            return findings
        except OSError:
            if issues is not None:
                issues.append(f'{rel}: generic scan could not read file')
    return findings


def gitleaks_scan(root: Path, mode: str) -> tuple[str, list[Finding]]:
    """Use Gitleaks JSON report; never include matched values in final report."""
    with tempfile.TemporaryDirectory(prefix='public-audit-') as temp:
        report = Path(temp) / 'findings.json'
        args = ['gitleaks', mode, '--redact', '--report-format', 'json', '--report-path', str(report)]
        if mode == 'git':
            args += ['--log-opts=--all', str(root)]
        else:
            args += [str(root)]
        try:
            proc = run(args, root)
        except (OSError, subprocess.TimeoutExpired):
            return 'error', []
        if proc.returncode not in (0, 1):
            return 'error', []
        try:
            data = json.loads(report.read_text()) if report.exists() and report.stat().st_size else []
            if not isinstance(data, list):
                return 'error', []
        except (OSError, ValueError):
            return 'error', []
        findings = []
        for item in data:
            # Do not serialize secret, match, entropy, offender, or context fields.
            if not isinstance(item, dict):
                continue
            rawfile = str(item.get('File', ''))
            if mode == 'dir':
                try:
                    rawfile = Path(rawfile).relative_to(root).as_posix()
                except ValueError:
                    rawfile = Path(rawfile).name
            findings.append(Finding(f'Gitleaks-{mode}', 'Gitleaks rule match', 'high',
                                    rawfile, int(item.get('StartLine') or 0),
                                    str(item.get('RuleID', ''))[:80]))
        if proc.returncode == 1 and not findings:
            # A code 1 indicates a finding even if report shape is unexpected.
            findings.append(Finding(f'Gitleaks-{mode}', 'findings reported (details unavailable)', 'high'))
        return 'findings' if findings else 'pass', findings


def staged_scan(root: Path) -> tuple[str, list[Finding]]:
    """Read staged blobs without writing them to the project or exposing blob contents."""
    names = subprocess.run(['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'],
                           cwd=root, capture_output=True, check=False)
    if names.returncode:
        return 'error', []
    findings = []
    with tempfile.TemporaryDirectory(prefix='public-audit-stage-') as temp:
        stage = Path(temp)
        for name in names.stdout.split(b'\0'):
            if not name:
                continue
            rel = Path(os.fsdecode(name))
            if rel.is_absolute() or '..' in rel.parts:
                return 'error', []
            blob = subprocess.run(['git', 'show', ':' + os.fsdecode(name)], cwd=root,
                                  capture_output=True, check=False)
            if blob.returncode:
                return 'error', []
            dest = stage / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(blob.stdout)
        # Scan staged content via Gitleaks and generic patterns. The temporary
        # checkout is removed automatically and never written to the repo.
        state, detected = gitleaks_scan(stage, 'dir')
        if state == 'error':
            return state, detected
        for f in detected:
            f.source = 'Gitleaks-staged'
        findings.extend(detected)
        stage_files = sorted(x for x in stage.rglob('*') if x.is_file())
        stage_issues = []
        findings.extend(generic_scan(Context(stage, stage_files), issues=stage_issues))
        if stage_issues:
            return 'incomplete', findings
        return ('findings' if findings else 'pass'), findings


def audit(root: Path, stop_on_finding=False):
    ctx = Context(root, enumerate_files(root))
    discovery_issues = []
    packages = discover_packages(ctx, discovery_issues)
    outcome = {'repository': str(root), 'technologies': discover(ctx),
               'packages': packages, 'coverage': {}, 'findings': [],
               'stopped_early': False, 'coverage_issues': discovery_issues}

    def append(findings):
        outcome['findings'].extend(vars(x) for x in findings)
        if stop_on_finding and any(x.severity == 'high' for x in findings):
            outcome['stopped_early'] = True
            return True
        return False

    for mode in ('git', 'dir'):
        status, found = gitleaks_scan(root, mode)
        outcome['coverage'][f'gitleaks_{mode}'] = status
        if append(found):
            return outcome
    status, found = staged_scan(root)
    outcome['coverage']['gitleaks_staged_and_generic'] = status
    if append(found):
        return outcome
    generic_issues = []
    found = generic_scan(ctx, stop_on_finding, generic_issues)
    outcome['coverage_issues'].extend(generic_issues)
    outcome['coverage']['generic'] = 'incomplete' if generic_issues else ('findings' if found else 'pass')
    if append(found):
        return outcome

    plugin_rows = inventory(exclude_root=root)
    plugins = [p for _, p, _, error in plugin_rows if error is None]
    for path, _, _, error in plugin_rows:
        if error:
            outcome['coverage'][f'plugin_load:{path.name}'] = 'plugin-error (incomplete): ' + error

    # Declared names are never normalized to guessed products by the core.
    # Each registered plugin owns its package and configuration recognition.
    active = {}
    for package in packages:
        matches = []
        for plugin in plugins:
            try:
                if plugin.matches(package):
                    matches.append(plugin)
            except Exception:
                outcome['coverage'][f'plugin_match:{plugin.name}'] = 'plugin-error (incomplete)'
        if matches:
            outcome['coverage'][f'package:{package}'] = 'specialized: ' + ', '.join(p.name for p in matches)
            for plugin in matches:
                active[plugin.name] = plugin
        else:
            outcome['coverage'][f'package:{package}'] = 'generic-only (no specialized plugin available)'

    for plugin in plugins:
        try:
            if plugin.detect(ctx):
                active[plugin.name] = plugin
        except Exception:
            outcome['coverage'][f'plugin_detect:{plugin.name}'] = 'plugin-error (incomplete)'

    for name, plugin in active.items():
        try:
            result = plugin.scan(ctx, stop_on_finding)
            outcome['coverage_issues'].extend(result.coverage_issues)
            outcome['coverage'][f'plugin:{name}'] = 'incomplete' if result.coverage_issues else ('findings' if result.findings else 'pass')
            if append(result.findings):
                return outcome
        except Exception:
            outcome['coverage'][f'plugin:{name}'] = 'plugin-error (incomplete)'
    return outcome
