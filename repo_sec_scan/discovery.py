"""Offline, evidence-based inventory of repository-declared software.

Package names remain as declared. Core does not maintain a package-to-product
lookup table; specialized plugins own their matching rules.
"""
from __future__ import annotations
import json
try:
    import tomllib
except ImportError:  # Python 3.9 and 3.10
    import tomli as tomllib
import re
from pathlib import Path
from .models import Context

MARKERS = {
    'Python': {'pyproject.toml', 'requirements.txt', 'poetry.lock', 'Pipfile'},
    'Node.js': {'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'},
    'Docker': {'Dockerfile', 'compose.yaml', 'compose.yml', 'docker-compose.yml', 'docker-compose.yaml'},
    'Terraform': {'.tf', '.tfvars'},
    'GitHub Actions': {'.github/workflows/'},
    'Kubernetes': {'kustomization.yaml', 'Chart.yaml'},
}
MAX_DISCOVERY_BYTES = 1_000_000


def discover(ctx: Context) -> dict[str, list[str]]:
    """Platform indicators, independent of specialized plugin availability."""
    evidence: dict[str, list[str]] = {}
    for path in ctx.files:
        rel = path.relative_to(ctx.root).as_posix()
        name = path.name
        low = rel.lower()
        for tech, markers in MARKERS.items():
            if any(name == m or (m.startswith('.') and low.endswith(m)) or
                   (m.endswith('/') and low.startswith(m)) for m in markers):
                evidence.setdefault(tech, []).append(rel)
    return {k: sorted(set(v)) for k, v in sorted(evidence.items())}


def _record(result: dict[str, list[str]], package: str, rel: str) -> None:
    package = package.strip()
    if package and len(package) <= 200:
        result.setdefault(package, []).append(rel)


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_DISCOVERY_BYTES:
            return None
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None


def _record_requirement(result: dict[str, list[str]], requirement: str, rel: str) -> None:
    # PEP 508 distribution name at the start; do not guess a product identity.
    match = re.match(r'^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)\s*(?:\[[^]]*\])?', requirement)
    if match:
        _record(result, match.group(1), rel)


def discover_packages(ctx: Context, issues: list[str] | None = None) -> dict[str, list[str]]:
    """List declared package/image names without guessing their technology."""
    result: dict[str, list[str]] = {}
    for path in ctx.files:
        rel = path.relative_to(ctx.root).as_posix()
        name = path.name.lower()
        if name not in {'package.json', 'pyproject.toml', 'compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml', 'dockerfile'} and not (name.startswith(('requirements-', 'dockerfile.')) or name.endswith('.compose.yaml') or name == 'requirements.txt'):
            continue
        content = _read(path)
        if content is None:
            if issues is not None:
                issues.append(f'{rel}: unreadable or oversized discovery source')
            continue
        if name == 'package.json':
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    for section in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
                        deps = data.get(section, {})
                        if isinstance(deps, dict):
                            for package in deps:
                                _record(result, package, rel)
            except ValueError:
                if issues is not None:
                    issues.append(f'{rel}: invalid JSON; dependency discovery incomplete')
        elif name in {'requirements.txt', 'requirements-dev.txt'} or (name.startswith('requirements-') and name.endswith('.txt')):
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(('#', '-', '.')):
                    continue
                match = re.match(r'^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*(?:\[[^]]*\])?(?:[=<>!~;@\s]|$)', line)
                if match:
                    _record(result, match.group(1), rel)
        elif name == 'pyproject.toml':
            try:
                data = tomllib.loads(content)
            except (ValueError, TypeError):
                if issues is not None:
                    issues.append(f'{rel}: invalid TOML; dependency discovery incomplete')
                continue
            project = data.get('project', {})
            if isinstance(project, dict):
                dependencies = project.get('dependencies', [])
                if isinstance(dependencies, list):
                    for requirement in dependencies:
                        if isinstance(requirement, str):
                            _record_requirement(result, requirement, rel)
                optional = project.get('optional-dependencies', {})
                if isinstance(optional, dict):
                    for group in optional.values():
                        if isinstance(group, list):
                            for requirement in group:
                                if isinstance(requirement, str):
                                    _record_requirement(result, requirement, rel)
            poetry = data.get('tool', {}).get('poetry', {}) if isinstance(data.get('tool'), dict) else {}
            if isinstance(poetry, dict):
                tables = [poetry.get('dependencies', {})]
                groups = poetry.get('group', {})
                if isinstance(groups, dict):
                    tables.extend(g.get('dependencies', {}) for g in groups.values() if isinstance(g, dict))
                for table in tables:
                    if isinstance(table, dict):
                        for package in table:
                            if package.lower() != 'python':
                                _record(result, package, rel)
            uv = data.get('dependency-groups', {})
            if isinstance(uv, dict):
                for group in uv.values():
                    if isinstance(group, list):
                        for requirement in group:
                            if isinstance(requirement, str):
                                _record_requirement(result, requirement, rel)
        elif name in {'compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml'} or name.endswith('.compose.yaml'):
            for line in content.splitlines():
                m = re.match(r'^\s*image\s*:\s*["\']?([^\s"\'#]+)', line)
                if m:
                    _record(result, m.group(1), rel)
        elif name == 'dockerfile' or name.startswith('dockerfile.'):
            for line in content.splitlines():
                m = re.match(r'^\s*FROM\s+(?:(?:--\S+)\s+)*([^\s#]+)', line, re.I)
                if m and not m.group(1).startswith('$'):
                    _record(result, m.group(1), rel)
    return {key: sorted(set(value)) for key, value in sorted(result.items(), key=lambda item: item[0].lower())}
