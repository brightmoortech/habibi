"""Rule-driven, non-executing inspection of Python plugin sources."""
import ast
import os
from pathlib import Path

DEFAULT_RULES = Path(__file__).with_name('plugin_security_rules.txt')


def rules_path():
    if 'HABIBI_PLUGIN_RULES' in os.environ:
        return Path(os.environ['HABIBI_PLUGIN_RULES']).expanduser()
    import sys
    prefix = Path(sys.prefix).resolve()
    if prefix.parent.name == 'releases' and prefix.parent.parent.name == 'habibi':
        installed = prefix.parents[3] / 'share' / 'habibi' / 'plugin_security_rules.txt'
        if installed.exists():
            return installed
    return DEFAULT_RULES


def read_rules(path=None):
    path = Path(path) if path else rules_path()
    items = []
    for line in path.read_text(encoding='utf-8').splitlines():
        rule = line.strip()
        if not rule or rule.startswith('#'):
            continue
        if not all(part.isidentifier() for part in rule.split('.')):
            raise ValueError(f'Invalid security rule: {rule!r}')
        items.append(rule)
    if not items:
        raise ValueError('Security rules file is empty')
    return set(items)


def _name(expr, aliases):
    if isinstance(expr, ast.Name):
        return aliases.get(expr.id, expr.id)
    if isinstance(expr, ast.Attribute):
        base = _name(expr.value, aliases)
        return f'{base}.{expr.attr}' if base else None
    return None


def inspect(path, rules=None, source=None):
    """Return (line, operation) matches. Raises on unreadable/invalid source/rules."""
    rules = read_rules() if rules is None else rules
    tree = ast.parse(source if source is not None else Path(path).read_text(encoding='utf-8'), filename=str(path))
    aliases = {}
    # Import aliases are resolved independently of their location in the module.
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for entry in node.names:
                aliases[entry.asname or entry.name.split('.')[0]] = entry.name if entry.asname else entry.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for entry in node.names:
                if entry.name != '*':
                    aliases[entry.asname or entry.name] = node.module + '.' + entry.name
    matches = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            operation = _name(node.func, aliases)
            if operation in rules:
                matches.add((node.lineno, operation))
        # Shell-like operations in literal arguments to process runners must be
        # checked separately; do not pretend this AST walker detects all variants.
    return sorted(matches)


def inspect_interface(path):
    """Static-only structural preflight; does not replace runtime compliance audit."""
    tree = ast.parse(Path(path).read_text(encoding='utf-8'), filename=str(path))
    functions = {node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assigned = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned.add(target.id)
    if 'info' not in functions or 'PLUGIN' not in assigned:
        raise ValueError('missing top-level info() or PLUGIN declaration')
