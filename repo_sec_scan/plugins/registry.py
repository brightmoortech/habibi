"""Discover and load self-describing plugins, with no technology-specific imports."""
import os
from pathlib import Path
from .security import inspect

BUILTIN_DIRECTORY = Path(__file__).resolve().parent


def external_directory():
    if 'SECSCAN_PLUGIN_DIR' in os.environ:
        return Path(os.environ['SECSCAN_PLUGIN_DIR']).expanduser().resolve()
    # Third-party plugins belong to the invoking user. This avoids requiring
    # administrator privileges to inspect or execute third-party code.
    return Path.home() / '.local' / 'share' / 'secscan' / 'plugins'


def candidates():
    """Only dedicated trusted installation directories, never scanned repositories."""
    files = sorted(p for p in BUILTIN_DIRECTORY.glob('*.py') if p.name not in {'__init__.py', 'base.py', 'registry.py', 'security.py', 'manager.py'})
    directory = external_directory()
    if directory.exists():
        files += sorted(p for p in directory.glob('*.py') if p.is_file() and not p.is_symlink())
    return files


def validate_info(info):
    if not isinstance(info, dict):
        raise ValueError('info() must return a dictionary')
    for key in ('name', 'version', 'description'):
        if not isinstance(info.get(key), str) or not info[key].strip():
            raise ValueError(f'missing or invalid {key}')
    import re
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", info["version"]):
        raise ValueError("version must be numeric, e.g. 1.2.0")
    tech = info.get('technologies')
    if not isinstance(tech, (list, tuple)) or not tech or not all(isinstance(x, str) and x.strip() for x in tech):
        raise ValueError('technologies must be a nonempty list of names')
    if not info['name'].replace('_', '').replace('-', '').isalnum():
        raise ValueError('plugin name must use letters, digits, hyphens or underscores')
    return info


def load(path):
    """Static check ALWAYS precedes importing or calling candidate Python code."""
    from types import ModuleType
    path = Path(path).resolve(strict=True)
    source = path.read_text(encoding='utf-8')
    findings = inspect(path, source=source)
    if findings:
        raise ValueError('prohibited operations: ' + ', '.join(f'{line}:{name}' for line, name in findings))
    if os.geteuid() == 0:
        raise ValueError('plugin execution disabled under root; run as a normal user')
    is_bundled = path.parent == BUILTIN_DIRECTORY
    name = f'{__package__}.{path.stem}' if is_bundled else '_secscan_external_' + path.stem
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = __package__ if is_bundled else ''
    # Execute exactly the same snapshot that the AST inspected.
    exec(compile(source, str(path), 'exec'), module.__dict__)
    info_function = getattr(module, 'info', None)
    if not callable(info_function):
        raise ValueError('missing info() function')
    info = validate_info(info_function())
    plugin = getattr(module, 'PLUGIN', None)
    if plugin is None or not all(callable(getattr(plugin, item, None)) for item in ('matches', 'detect', 'scan')):
        raise ValueError('missing PLUGIN or matches/detect/scan methods')
    if getattr(plugin, 'name', None) != info['name']:
        raise ValueError('PLUGIN.name must match info().name')
    return plugin, info


def inventory(exclude_root=None):
    """One result per file; noncompliant files remain visible in audit."""
    rows = []
    names = set()
    for path in candidates():
        try:
            if exclude_root is not None and path.resolve().is_relative_to(Path(exclude_root).resolve()):
                raise ValueError('plugin path is inside repository being scanned')
            if os.geteuid() == 0:
                raise ValueError('plugin execution disabled under root; run as a normal user')
            plugin, info = load(path)
            if info['name'].casefold() in names:
                raise ValueError('duplicate plugin name')
            names.add(info['name'].casefold())
            rows.append((path, plugin, info, None))
        except Exception as exc:
            rows.append((path, None, None, str(exc)))
    return rows


def load_plugins():
    return [plugin for _, plugin, _, error in inventory() if error is None]
