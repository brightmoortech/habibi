"""Minimal CLI plugin manager. No persistent registry or state database."""
import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path
from . import registry
from .security import inspect, inspect_interface, read_rules


def _table(rows):
    cols = ('PLUGIN NAME', 'VERSION', 'FILENAME', 'TYPE', 'STATUS')
    data = [cols] + [tuple(map(str, row)) for row in rows]
    widths = [max(len(row[i]) for row in data) for i in range(len(cols))]
    for index, row in enumerate(data):
        print('  '.join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        if index == 0:
            print('  '.join('-' * width for width in widths))


def _matching(name):
    """Use direct filenames first, avoiding a full inventory for common lookups.

    Display names can differ from filenames, so retain a fallback for those.
    """
    stem = name[:-3] if name.lower().endswith('.py') else name
    paths = [directory / (stem.lower() + '.py') for directory in
             (registry.BUILTIN_DIRECTORY, registry.external_directory())]
    # Actual case-preserving filenames may differ on case-sensitive systems.
    found = [path for path in paths if path.is_file() and not path.is_symlink()]
    if found:
        rows = []
        for path in found:
            try:
                plugin, info = registry.load(path)
                if not name.lower().endswith('.py') and info['name'].casefold() != name.casefold():
                    continue
                rows.append((path, plugin, info, None))
            except Exception as exc:
                rows.append((path, None, None, str(exc)))
        if rows:
            return rows
    rows = registry.inventory()
    return [row for row in rows if (row[2] and row[2]['name'].casefold() == name.casefold())
            or row[0].stem.casefold() == stem.casefold()]



def _execute_as_user():
    # Running self-describing plugin Python code as root is prohibited.
    if os.geteuid() == 0:
        raise ValueError('Refusing to execute plugin code as root. Run plugin commands without sudo; configure a writable plugin directory.')


def _trusted_file(path):
    path = Path(path).expanduser().resolve(strict=True)
    if path.suffix != '.py' or not path.is_file():
        raise ValueError('plugin must be a regular .py file')
    return path


def _install(path):
    source = _trusted_file(path)
    # Parse first. Source may be untrusted: no calls to info before static scan.
    violations = inspect(source)
    if violations:
        raise ValueError('static security inspection failed: ' + repr(violations))
    _execute_as_user()
    plugin, meta = registry.load(source)
    directory = registry.external_directory()
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / (meta['name'].lower() + '.py')
    if source == destination:
        raise ValueError('source is already the installed file')
    existing = _matching(meta['name'])
    for candidate, _, details, error in existing:
        if candidate.parent == registry.BUILTIN_DIRECTORY:
            # Built-in remains intact; installed Custom plugin takes precedence.
            continue
        if error:
            # A damaged installation must remain repairable with the same
            # install command. We cannot compare its unavailable version.
            if candidate != destination:
                raise ValueError('invalid existing plugin has a different filename')
            print(f'Existing {candidate.name} failed audit; replacing after preserving backup.')
            continue
        old = tuple(int(x) for x in details['version'].split('.'))
        new = tuple(int(x) for x in meta['version'].split('.'))
        width = max(len(old), len(new))
        if new + (0,) * (width - len(new)) < old + (0,) * (width - len(old)):
            response = input(f"Downgrade {meta['name']} {details['version']} -> {meta['version']}? [y/N] ")
            if response.strip().lower() not in {'y', 'yes'}:
                print('Downgrade cancelled.')
                return 1
        if candidate != destination:
            raise ValueError('existing plugin uses another filename; no replacement performed')
    if destination.exists() and not existing:
        raise ValueError('destination exists but is not a valid managed plugin')
    # Stage on the same filesystem and replace atomically. Existing file remains
    # untouched until all validation has passed. A backup restores failed activation.
    staged = None
    backup = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix='.plugin-new-', suffix='.py', delete=False) as f:
            staged = Path(f.name)
        shutil.copyfile(source, staged)
        if inspect(staged):
            raise ValueError('staged plugin failed security inspection')
        # Validate staged copy as well, catching modified content before activation.
        registry.load(staged)
        if destination.exists():
            with tempfile.NamedTemporaryFile(dir=directory, prefix='.plugin-old-', suffix='.py', delete=False) as f:
                backup = Path(f.name)
            shutil.copyfile(destination, backup)
        os.replace(staged, destination)
        staged = None
        try:
            registry.load(destination)
        except Exception:
            if backup:
                try:
                    os.replace(backup, destination)
                    backup = None
                except OSError as rollback_error:
                    # Never discard the backup if rollback itself fails.
                    protected_backup = backup
                    backup = None
                    raise RuntimeError(f'Rollback failed; previous plugin preserved at {protected_backup}') from rollback_error
            else:
                destination.unlink(missing_ok=True)
            raise
        print(f"Installed {meta['name']} {meta['version']} ({destination.name}).")
    finally:
        if staged:
            staged.unlink(missing_ok=True)
        if backup:
            backup.unlink(missing_ok=True)
    return 0


def plugin_command(argv):
    parser = argparse.ArgumentParser(
        prog='secscan plugins',
        description='Manage trusted Python security plugins.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage='\n  secscan plugins list\n  secscan plugins info <name>\n  secscan plugins audit [name]\n  secscan plugins install <file>\n  secscan plugins remove <name>',
        epilog='''Plugin management commands:
  list             List installed plugins
  info <name>      Display plugin information
  audit [name]     Audit all plugins or one plugin
  install <file>   Install, reinstall, upgrade or downgrade a plugin
  remove <name>    Remove a Custom plugin

Use secscan plugins <command> --help for command-specific options.''')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('list', help='List installed plugins')
    for name in ('info', 'audit', 'remove'):
        item = sub.add_parser(name, help={'info': 'Display plugin information', 'audit': 'Audit plugins', 'remove': 'Remove a Custom plugin'}[name])
        item.add_argument('name', nargs='?' if name == 'audit' else None)
        if name == 'audit':
            item.add_argument('--static-only', action='store_true', help=argparse.SUPPRESS)
    item = sub.add_parser('install', help='Install, reinstall, upgrade or downgrade a plugin')
    item.add_argument('file')
    args = parser.parse_args(argv)
    try:
        if args.action == 'install':
            return _install(args.file)
        if args.action == 'list':
            _execute_as_user()
            rows = []
            for path, _, info, error in registry.inventory():
                kind = 'Built-in' if path.parent == registry.BUILTIN_DIRECTORY else 'Custom'
                status = 'Overridden' if error == 'overridden' else 'Invalid' if error else 'Active'
                rows.append((info['name'] if info else '[INVALID]',
                             info['version'] if info else '-', path.name, kind, status))
            _table(rows)
            return 0
        if args.action == 'audit':
            # Static checks run before importing plugin code, including info().
            if args.name:
                # Filter candidate paths by file stem first; only load after static scan.
                stem = args.name[:-3] if args.name.lower().endswith('.py') else args.name
                targets = [p for p in registry.candidates() if p.stem.casefold() == stem.casefold()]
                if not targets:
                    _execute_as_user()
                    targets = [path for path, _, info, _ in registry.inventory() if info and info['name'].casefold() == args.name.casefold()]
            else:
                targets = registry.candidates()
            if not targets:
                print('Plugin not found.', file=sys.stderr)
                return 2
            failures = 0
            read_rules()  # Missing, unreadable or invalid policy fails closed.
            for path in targets:
                try:
                    violations = inspect(path)
                    if violations:
                        raise ValueError('prohibited operations: ' + repr(violations))
                    if args.static_only:
                        inspect_interface(path)
                        print(f'PASS  static inspection ({path.name})')
                    else:
                        _execute_as_user()
                        _, info = registry.load(path)
                        print(f"PASS  {info['name']} {info['version']} ({path.name})")
                except Exception as exc:
                    failures += 1
                    print(f'FAIL  {path.name}: {exc}')
            return 1 if failures else 0
        _execute_as_user()
        matching = _matching(args.name)
        if not matching:
            print('Plugin not found.', file=sys.stderr)
            return 2
        if args.action == 'info':
            for path, _, info, error in matching:
                if error and error != 'overridden':
                    print(f'{path.name}: {error}')
                    return 1
                print('Name:', info['name'])
                print('Version:', info['version'])
                print('Technologies:', ', '.join(info['technologies']))
                print('Description:', info['description'])
                print('Filename:', path.name)
                print('Type:', 'Built-in' if path.parent == registry.BUILTIN_DIRECTORY else 'Custom')
                overridden = (path.parent == registry.BUILTIN_DIRECTORY and any(
                    other[0].parent != registry.BUILTIN_DIRECTORY and other[2] and info and
                    other[2]['name'].casefold() == info['name'].casefold() and other[3] is None
                    for other in matching))
                print('Status:', 'Overridden' if overridden or error == 'overridden' else 'Active')
            return 0
        if args.action == 'remove':
            custom = [path for path, _, _, _ in matching if path.parent != registry.BUILTIN_DIRECTORY]
            if not custom:
                raise ValueError('Built-in plugin cannot be removed; install a Custom override instead')
            for path in custom:
                path.unlink()
                print('Removed:', path.name)
            return 0
    except (ValueError, OSError, EOFError, SyntaxError, RuntimeError) as exc:
        print('Plugin error:', exc, file=sys.stderr)
        return 2
    return 2
