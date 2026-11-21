# Repo Security Scanner

A modular, **read-only-by-default** security audit tool for Git repositories that you intend to publish or make public. It combines broad secret scanning with repository technology discovery and optional technology-specific checks.

**A clean audit is not a guarantee that a repository is safe to publish.** Gitleaks detects recognizable secrets; additional checks are heuristic. Review licenses, private information, test data, exported infrastructure settings and upstream forks/caches before changing repository visibility.

## Features

- Runs [Gitleaks](https://github.com/gitleaks/gitleaks) against **Git history** (all locally available refs), the **working directory**, and the **staged snapshot**.
- Scans accessible repository files for recognizable credential assignments and sensitive filenames.
- Inventories declared package and image names from supported repository manifests without guessing product names. It does not inspect machine-installed software or execute detected code.
- Runs a dedicated scanner when a supported technology is detected. Otherwise explicitly reports **no specialized handling; generic scan applied**.
- **Included independent security plugins:** Windmill and PostgreSQL. Plugins own their package matching and configuration detection. Additional plugins are discovered from a dedicated plugin directory without changing the core.
- Default completes all checks; `--stop-on-finding` exits early when a **high-severity potential exposure** is reported; review-only warnings do not stop the scan.
- Does not print matched secret values or source lines. Optional JSON report is written outside the repository with restricted file permissions when supported.
- Works on macOS and Linux with Python 3.9+.

## Architecture

```text
CLI (repo_sec_scan/cli.py)
  ├── dependency preflight: Git / Gitleaks
  ├── core.py: file enumeration and scan orchestration
  │     ├── Gitleaks Git history / working directory / staged snapshot
  │     ├── generic repository scanning
  │     └── discovery.py: project markers + raw declared package/image names
  ├── plugins/registry.py: directory discovery + security-first validation
  │     └── plugin.matches(package) / plugin.detect(context) → plugin.scan(context)
  │     ├── plugins/windmill.py: Windmill export/credential heuristics
  │     └── plugins/postgresql.py: SQL, authentication and credential heuristics
  └── report aggregation: findings and coverage, no matched values
```

Generic scanning always runs. A plugin supplements rather than replaces it. Plugin failures are marked **incomplete**, never as a pass. The scan does not call Windmill APIs, query PostgreSQL, modify repositories, or fetch remote Git refs.

## Installation and upgrades (macOS and Linux)

From the downloaded or cloned `repo-sec-scan` folder, use the **same command** for a first install and an upgrade:

```bash
sudo ./install.sh
```

The installer makes `secscan` available to all users through `/usr/local/bin/secscan`. The Python package runs in its own environment under `/usr/local/lib/repo-sec-scan/releases/`, rather than changing the system Python installation. Python 3.9+ and its `venv` module are required; the included wheel avoids downloading build dependencies for a normal install on current Python versions. A Python 3.9/3.10 installation may additionally need the `tomli` dependency from a configured package index.

The installer checks the current release and upgrades only when the new version is higher. It does nothing when versions match, blocks core downgrades, statically checks bundled plugins without executing them as root, and retains the previous release for rollback if verification fails. It refuses to overwrite an unrelated existing `/usr/local/bin/secscan` command. Do not use an unreviewed or untrusted source archive with `sudo`.

After installation:

```bash
secscan --help
secscan /path/to/project
secscan /path/to/project --stop-on-finding
```

For installation options: `./install.sh --help`. `SECSCAN_PREFIX` allows testing under a different prefix without changing the host installation. The installer does not install Git or Gitleaks; these are scanning prerequisites. At scan time, `secscan --install-missing` can offer to install them interactively through Homebrew/APT. The scanner itself never upgrades `secscan`.

For developers who do not want a host-level installation, `python3 -m repo_sec_scan --help` remains available from the source directory. Normal users should use `secscan`.

Before scanning remote history, refresh Git references in the target repository if permitted:

```bash
cd /path/to/project
git fetch origin --prune --tags
```

The scanner does not fetch, push, rewrite Git history or modify tracked project files.

## CLI options

| Option | Behavior |
| --- | --- |
| `repository` | Optional path inside target Git repository; default `.`. |
| `-h`, `--help` | Display help text and all arguments, including plugin command syntax. |
| `--version` | Display the installed secscan version. |
| `--stop-on-finding` | Stop on the first high-severity potential exposure. Review-only warnings do not stop the audit. Default runs all checks. |
| `--install-missing` | Offer approved package-manager installation of missing Git/Gitleaks tools. No automatic installation by default. |
| `--report PATH` | Save a JSON report; the script rejects a destination inside the audited repository. |

Example:

```bash
secscan ~/Development/develop/automation_lab --report ~/audit-output.json
secscan /path/to/repo --stop-on-finding
secscan plugins list
```

Exit codes: **0** completed without findings, **1** completed with findings, **2** error or incomplete scan (including early stop and skipped supported files). A zero exit code does not certify safe public release.

## Technology discovery and handling

The core reads **declared names** from supported repository files, without a catalog that guesses which product each name represents. Sources include `requirements*.txt`, PEP 621 `project.dependencies` and `project.optional-dependencies`, Poetry dependency groups, PEP 735 `[dependency-groups]` in `pyproject.toml`, `package.json`, Docker Compose `image:` declarations, and Dockerfile `FROM` declarations. Some project markers (such as `pyproject.toml`, Helm files and `.github/workflows/`) are also reported.

For each declared package or image, `secscan` asks each installed plugin whether it **matches** the name. A plugin may also recognize configuration paths through its own `detect(context)` method. The generic scan always runs; matching plugins provide additional checks.

Example:

```text
Declared packages/images:
  metabase/metabase:latest
  postgres:18
  psycopg
  some-unknown-package
Scan coverage:
  package:metabase/metabase:latest: generic-only (no specialized plugin available)
    No specialized handling for package:metabase/metabase:latest; generic scan applied.
  package:postgres:18: specialized: PostgreSQL
  package:psycopg: specialized: PostgreSQL
  package:some-unknown-package: generic-only (no specialized plugin available)
  plugin:PostgreSQL: pass
```

This does not claim that `metabase/metabase:latest` has been validated by a Metabase-specific scanner. `psycopg` indicates a declared PostgreSQL client library; it does not prove that a local PostgreSQL server is deployed. Package inventories are best-effort and do not resolve transitive dependencies or all package-manager lock formats.

**Included Built-in plugins:**

- **Windmill:** examines repository workflow exports for possible embedded credentials and exported values. Detects Windmill paths and flow files, and recognizes relevant declared Windmill packages/images.
- **PostgreSQL:** checks applicable `pg_hba.conf` rules, SQL privileges/destructive operations, and credential-bearing connection URLs. Recognizes relevant PostgreSQL drivers and images.

Neither plugin connects to a live service or reads live Windmill variables. Findings are candidates for review, not automatically proven security vulnerabilities.

## Plugin development and security

All plugins, including the Built-in Windmill and PostgreSQL modules, are discovered from their installed Python files. There are **no hardcoded plugin names or registry entries**. Every plugin implements `info()` plus `PLUGIN.matches()`, `PLUGIN.detect()` and `PLUGIN.scan()`. Generic scanning continues when a plugin is absent or rejected, and coverage is marked incomplete for plugin loading failures.

**Security warning:** Python plugins are executable code and may read, change or delete anything permitted to the running user. Only install code from trusted authors. An AST-based scan reduces the risk of some prohibited operations but **does not prove a plugin is safe**. Dynamic calls, aliases and indirect library behavior can evade detection. Never load plugins from a repository being scanned. Do not invoke plugin inspection or execution with `sudo`.

### Complete Python plugin template

Save as `example.py` (the filename is used during discovery):

```python
from repo_sec_scan.models import PluginResult

class ExamplePlugin:
    name = "Example"

    def matches(self, package_name: str) -> bool:
        return package_name.lower() == "example-package"

    def detect(self, context) -> bool:
        return any(path.name == "example.conf" for path in context.files)

    def scan(self, context, stop_on_finding=False):
        result = PluginResult(self.name, ["Example"])
        # Read repository files and append sanitized findings if necessary.
        # Do not connect to services or modify the scanned repository.
        return result

PLUGIN = ExamplePlugin()

def info():
    return {
        "name": "Example",
        "version": "1.0.0",
        "technologies": ["Example"],
        "description": "Example repository security checks",
    }
```

`info()` must return a dictionary with a unique plugin name, a numeric dot-separated version, a nonempty list of technologies and a nonempty description. `PLUGIN.name` must match the `info()` name. Plugin code is inspected statically before it is imported or `info()` is called.

### Plugin lookup and listing

`secscan plugins list` prints **PLUGIN NAME, VERSION, FILENAME, TYPE, STATUS**. `TYPE` is `Built-in` or `Custom`; `STATUS` is `Active`, `Overridden` or `Invalid`. A Custom plugin replaces the Built-in plugin **by declared name**, regardless of whether its filename differs. Both can use `windmill.py`. `info` and `remove` first try a direct filename lookup (accepting `windmill` or `windmill.py`) to avoid inventorying every plugin for ordinary operations. Where the requested display name does not match a filename, they fall back to inspecting the dedicated plugin directories; they do not recursively search arbitrary libraries or repositories. `list` and scanning must inspect all installed plugins to discover and validate their metadata.

Example after installing a Custom Windmill override:

```text
PLUGIN NAME  VERSION  FILENAME       TYPE      STATUS
PostgreSQL   1.0.0    postgresql.py  Built-in  Active
Windmill     1.0.0    windmill.py    Built-in  Overridden
Windmill     2.0.0    windmill.py    Custom    Active
```

A rejected Custom candidate does not replace the Built-in version, and an invalid Custom file is reported rather than executed. Static security scanning still occurs before any plugin Python execution. Passing inspection **does not prove a plugin is safe**.

### Commands

```bash
secscan plugins list                 # Table: name, version, filename, type, status
secscan plugins info Example         # Metadata for one plugin (supports filename too)
secscan plugins audit                # Static security and interface audit of all
secscan plugins audit Example        # Audit one plugin (supports filename too)
secscan plugins install ./example.py # New install, reinstall, upgrade or downgrade
secscan plugins remove Example       # Remove a Custom plugin (restores overridden Built-in)
```

A third-party plugin is installed under `~/.local/share/secscan/plugins/` for the current user (or under the directory specified by `SECSCAN_PLUGIN_DIR`). The installer stages and validates replacement files before activation. Same-version installs replace the file, newer versions upgrade, and older versions ask for confirmation. If validation or activation fails, the existing file is retained or restored. Built-in plugins are distributed with the core release. A Custom plugin may declare the same name and filename as a Built-in plugin; because the two live in different directories, the Custom plugin becomes Active while the Built-in becomes Overridden, without changing its file. Removing the Custom plugin automatically restores the Built-in as Active. Built-in plugin files cannot be removed with the plugin manager. No separate metadata database is maintained.

**Never run plugin commands with `sudo`.** The system-wide core installation (`sudo ./install.sh`) uses static inspection only and does not execute plugin Python code with administrator privileges. Third-party plugins are installed per-user to avoid elevated execution. The same plugin discovery and validation rules apply to Built-in and Custom plugins.

### Security rules file

The user-editable file `plugin_security_rules.txt` contains prohibited function names, one per line. For system-wide installations the initial policy is placed at `/usr/local/share/secscan/plugin_security_rules.txt` (under the selected installation prefix); it is **not overwritten on upgrades**. To supply a different policy, set `SECSCAN_PLUGIN_RULES=/path/to/rules.txt`. When working from the source tree, the bundled default file is used if no override exists.

Example:

```text
# Calls to these functions are rejected
os.remove
shutil.rmtree
subprocess.run
eval
exec
```

The Python AST inspector ignores comments, detects direct function calls and some imported aliases, and reports the line number and operation. Invalid rules, malformed source and recognized prohibited calls fail inspection. This is a heuristic policy, not a sandbox or guarantee of safety. Add additional names to the flat file as needed. Installation and audit perform security inspection before any plugin code is executed.

## Audit coverage and limitations

- The Git scan covers objects reachable from **local** refs (including fetched remote-tracking refs), not unreachable objects, inaccessible remote refs, deleted hosted history, other forks, issue attachments, CI artifacts or already-copied public material. Run `git fetch` yourself if appropriate.
- Scanning the staging snapshot separately helps catch a staged secret that differs from the working copy. The staged snapshot is written only to a temporary directory and removed on completion.
- `git ls-files` plus unignored files controls generic/plugin file enumeration. Git-ignored files may still be examined by Gitleaks directory mode, depending on its configuration; review exclusions.
- Generic/plugin heuristic scans skip files larger than 1 MB and are not parsers for every configuration language. Skipped/unreadable/oversized applicable files and malformed dependency manifests are now shown as **incomplete coverage**, with a nonzero error exit code; Gitleaks has separate scanning behavior. The output does not claim that every possible file format or Gitleaks exclusion was audited.
- This is **not** a live Windmill variable audit or a PostgreSQL server/role audit. Secrets stored only in Windmill's database are not automatically in Git, but exports or scripts may have copied their values.
- Reports do not contain matched values by design, but file paths and infrastructure names may themselves be sensitive. Store reports outside the public repository.
- Dependency installation is opt-in and changes the machine; the audit itself does not modify the target repository.

## Testing

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q repo_sec_scan
```

Tests do not require a real Windmill or PostgreSQL server. Live Gitleaks end-to-end behavior needs to be verified in your own environment; test scans here use a simulated scanner.

## Public release checklist

Complete all checks, investigate findings, confirm staged/working/history coverage, check for credentials not recognized by scanners, review committed personal/client data and proprietary assets, and rotate any credential that was ever exposed. Do not assume removing a secret from the current branch removes it from earlier commits. History rewrites require explicit planning and may not remove copies already fetched by others.

## Release history

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for version changes, issue resolutions, validation records and test traceability.

## License

MIT. See [LICENSE](LICENSE).
