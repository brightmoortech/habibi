"""Built-in and installed third-party scanners (Python entry-point plugins)."""
from importlib import metadata
from .windmill import PLUGIN as windmill
from .postgresql import PLUGIN as postgresql

ENTRY_POINT_GROUP = 'repo_sec_scan.plugins'


def load_plugins():
    plugins = [windmill, postgresql]
    try:
        entries = metadata.entry_points()
        candidates = entries.select(group=ENTRY_POINT_GROUP) if hasattr(entries, 'select') else entries.get(ENTRY_POINT_GROUP, [])
        for entry in candidates:
            try:
                plugin = entry.load()
                if isinstance(plugin, type):
                    plugin = plugin()
                if all(callable(getattr(plugin, attr, None)) for attr in ('matches', 'detect', 'scan')) and getattr(plugin, 'name', None):
                    if plugin.name not in {p.name for p in plugins}:
                        plugins.append(plugin)
            except Exception:
                # Discovery failures are surfaced in the plugin loading diagnostics
                # only if extended in a subsequent release; avoid importing user repo code.
                continue
    except Exception:
        pass
    return plugins

PLUGINS = load_plugins()
