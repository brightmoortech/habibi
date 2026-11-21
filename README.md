# Habibi

*Formerly Repo Security Scanner (`repo-sec-scan` / `secscan`), prior to v0.3.0.*

A modular, **read-only-by-default** security audit tool for Git repositories that you intend to publish or make public. It combines secret scanning, repository technology discovery, and technology-specific checks when a matching plugin is available.

**A clean audit is not a guarantee that a repository is safe to publish.** Gitleaks detects recognizable secrets; additional checks are heuristic. Review licenses, private information, test data, exported infrastructure settings and upstream forks/caches before changing repository visibility.

## Features

- Runs [Gitleaks](https://github.com/gitleaks/gitleaks) against **Git history** (locally available refs), the **working directory**, and a temporary copy of **changed files in the Git index** (staged additions, copies, modifications and renames). It does not independently scan every unchanged staged file.
- Scans accessible repository files for recognizable credential assignments and sensitive filenames.
- Inventories declared package and image names from supported repository manifests without guessing product names. It does not inspect machine-installed software or execute detected code.
- Runs a dedicated scanner when a supported technology is detected. Otherwise explicitly reports **no specialized handling; generic scan applied**.
- **Included independent security plugins:** Windmill and PostgreSQL. Plugins own their package matching and configuration detection. Additional plugins are discovered from a dedicated plugin directory without changing the core.
- Default completes all checks; `--stop-on-finding` exits early when a **high-severity potential exposure** is reported; review-only warnings do not stop the scan.
- The core and included plugins do not put matched credential values or source lines into findings. A JSON report is written only when requested, outside the audited repository, and the tool attempts to restrict its permissions. Custom plugins are executable code and must be reviewed separately for data disclosure.
- Targets macOS and Linux with Python 3.9+. Platform compatibility depends on the selected Python interpreter, required tools, and their availability; native platform testing is still recommended.

## Architecture

```text
CLI (habibi/cli.py)
  ├── dependency preflight: Git / Gitleaks
  ├── core.py: file enumeration and scan orchestration
  │     ├── Gitleaks Git history / working directory / changed staged files
  │     ├── generic repository scanning
  │     └── discovery.py: project markers + raw declared package/image names
  ├── plugins/registry.py: directory discovery + security-first validation
  │     └── plugin.matches(package) / plugin.detect(context) → plugin.scan(context)
  │     ├── plugins/windmill.py: Windmill export/credential heuristics
  │     └── plugins/postgresql.py: SQL, authentication and credential heuristics
  └── reporting.py: terminal progress and summary (core results also support JSON)
```

Generic scanning always runs. A plugin supplements rather than replaces it. Plugin failures are marked **incomplete**, never as a pass. The scan does not call Windmill APIs, query PostgreSQL, modify repositories, or fetch remote Git refs.

## Installation and upgrades (macOS and Linux)

From the downloaded or cloned `habibi` folder, use the **same command** for a first install and an upgrade:

```bash
sudo ./install.sh
```

By default, the installer links `habibi` at `/usr/local/bin/habibi`; it is available as a shell command when that directory is in the user’s `PATH`. The Python package runs in its own environment under `/usr/local/lib/habibi/releases/`, rather than changing the system Python installation. Python 3.9+ and its `venv` module are required; the included wheel avoids downloading build dependencies for a normal install on current Python versions. A Python 3.9/3.10 installation may additionally need the `tomli` dependency from a configured package index.

The new Habibi installer does not migrate or remove the old `secscan` installation or its Custom plugins. See **Renaming from secscan** below.

The installer checks the current release and upgrades only when the new version is higher. It does nothing when versions match, blocks core downgrades, statically checks bundled plugins without executing them as root, and retains the previous release for rollback if verification fails. It refuses to overwrite an unrelated existing `/usr/local/bin/habibi` command. Do not use an unreviewed or untrusted source archive with `sudo`.

After installation:

```bash
habibi --help
habibi /path/to/project
habibi /path/to/project --stop-on-finding
```

For installation options: `./install.sh --help`. `HABIBI_PREFIX` allows testing under a different prefix without changing the host installation. The installer does not install Git or Gitleaks; these are scanning prerequisites. At scan time, `habibi --install-missing` can offer to install them interactively through Homebrew/APT. The scanner itself never upgrades `habibi`.

For developers who do not want a host-level installation, `python3 -m habibi --help` remains available from the source directory. Normal users should use `habibi`.

Before scanning remote history, refresh Git references in the target repository if permitted:

```bash
cd /path/to/project
git fetch origin --prune --tags
```

The scanner does not fetch, push, rewrite Git history or modify tracked project files.

## Renaming from secscan (v0.2.x)

Habibi is a **fresh installation**, not an in-place upgrade of the old `secscan` application. The `secscan` command and `/usr/local/lib/repo-sec-scan` release directory are *not* modified automatically. After installing and verifying Habibi, you may remove the old installation separately. Do not delete existing Custom plugins until you have copied and validated the ones you still need.

Custom plugins from `~/.local/share/secscan/plugins/` must be installed again under `~/.local/share/habibi/plugins/` using `habibi plugins install FILE`. Update any imports from `repo_sec_scan` to `habibi` before installing. Only trusted, reviewed plugin code should be installed. No automatic migration, backward-compatibility aliases, or registry files are introduced.

## CLI options

| Option | Behavior |
| --- | --- |
| `repository` | Optional path inside target Git repository; default `.`. |
| `-h`, `--help` | Display help text and all arguments, including plugin command syntax. |
| `--version` | Display the habibi application version (including when run from source). |
| `--stop-on-finding` | Stop on the first high-severity potential exposure. Review-only warnings do not stop the audit. Default runs all checks. |
| `--install-missing` | Offer approved package-manager installation of missing Git/Gitleaks tools. No automatic installation by default. |
| `--report PATH` | Save a JSON report; the script rejects a destination inside the audited repository. |

Example:

```bash
habibi ~/Development/develop/automation_lab --report ~/audit-output.json
habibi /path/to/repo --stop-on-finding
habibi plugins list
```

Exit codes: **0** completed without findings, **1** completed with findings, **2** error or incomplete scan (including early stop and skipped supported files). A zero exit code does not certify safe public release.

## Technology discovery and handling

The core reads **declared names** from supported repository files, without a catalog that guesses which product each name represents. Sources include `requirements.txt` and `requirements-*.txt`, PEP 621 `project.dependencies` and `project.optional-dependencies`, Poetry dependency groups, PEP 735 `[dependency-groups]` in `pyproject.toml`, `package.json`, Docker Compose `image:` declarations, and Dockerfile `FROM` declarations. Some project markers (such as `pyproject.toml`, Helm files and `.github/workflows/`) are also reported.

For each declared package or image, `habibi` asks each active, validated plugin whether it **matches** the name. A plugin may also recognize configuration paths through its own `detect(context)` method. The generic scan always runs; matching plugins provide additional checks. Generic credential heuristics recognize quoted and unquoted assignments using names such as `password`, `user_password`, `USER1_PWD`, `api_key`, and `access_token`. They flag suspicious assignments for review but cannot reliably distinguish real credentials from examples in every programming language. Core-generated findings do not include matched values; Custom plugins must follow the same convention.

The terminal presents the scan in execution order, showing each completed check once, followed by its findings or coverage limitations:

```text
[1] DISCOVERED TECHNOLOGIES
    Docker                 Detected
    Python                 Detected
    PostgreSQL             Detected
    Windmill               Detected
    Total: 4 technologies

[2] REPOSITORY SECURITY
    Git history            PASS
    Working files          PASS
    Staged files           PASS
    Generic checks         FINDINGS (1)
      WARNING  sensitive filename (review if tracked) | compose/.env.example
    Checks: 4 | Findings: 1 | Coverage limitations: 0

[3] TECHNOLOGY SECURITY
    Windmill               PASS
    PostgreSQL             PASS
    Checks: 2 | Findings: 0 | Coverage limitations: 0

[4] UNSUPPORTED PACKAGES
    caddy-l4:2.11.4-1      Generic checks only
    pip                    Generic checks only
    Total: 2 packages without specialized scanning

SCAN SUMMARY
    Technologies detected:       4
    Specialized scanners run:    2
    Unsupported packages:        2
    Security findings:           1 (1 warning)
    Scan coverage:               COMPLETE
```

The example is illustrative; actual entries and counts depend on the repository. Findings or coverage problems are printed immediately below the completed check; redundant `STARTED` lines are omitted. The discovery phase lists both platform markers (such as Docker and Python) and technologies identified by specialized plugin matching (such as Windmill and PostgreSQL). A technology match signals a declared dependency or recognizable configuration, **not** proof that a service is running.

Unsupported packages are grouped separately; they have no specialized scanner, although repository-level generic checks still run on eligible files. Docker image SHA-256 digests are omitted from terminal labels for readability; the optional JSON report retains the **complete original** image references, findings, and coverage details. Missing plugins and incomplete checks are never represented as successful specialized scans. With `--stop-on-finding`, remaining sections are marked not run or not evaluated.

This does not claim that `metabase/metabase:latest` has been validated by a Metabase-specific scanner. `psycopg` indicates a declared PostgreSQL client library; it does not prove that a local PostgreSQL server is deployed. Package inventories are best-effort and do not resolve transitive dependencies or all package-manager lock formats.

**Included Built-in plugins:**

- **Windmill:** examines repository workflow exports for possible embedded credentials and exported values. Detects Windmill paths and flow files, and recognizes relevant declared Windmill packages/images.
- **PostgreSQL:** checks applicable `pg_hba.conf` rules, SQL privileges/destructive operations, and credential-bearing connection URLs. Recognizes relevant PostgreSQL drivers and images.

Neither plugin connects to a live service or reads live Windmill variables. Findings are candidates for review, not automatically proven security vulnerabilities.

## Plugin development and security

All plugins, including the Built-in Windmill and PostgreSQL modules, are discovered from their installed Python files. There are **no hardcoded plugin names or registry entries**. Every plugin implements `info()` plus `PLUGIN.matches()`, `PLUGIN.detect()` and `PLUGIN.scan()`. Generic scanning continues when a plugin is absent or rejected, and coverage is marked incomplete for plugin loading failures.

**Security warning:** Python plugins are executable code and may read, change or delete anything permitted to the running user. Only install code from trusted authors. An AST-based scan reduces the risk of some prohibited operations but **does not prove a plugin is safe**. Dynamic calls, aliases and indirect library behavior can evade detection. Never load plugins from a repository being scanned. Do not invoke plugin inspection or execution with `sudo`.

### Command help

`habibi --help` shows both forms of the command: repository scanning and `habibi plugins <command> [arguments]`. `habibi plugins --help` lists each plugin command, its required or optional arguments, and its purpose. Individual commands also accept `--help`.

### Complete Python plugin template

Save as `example.py` (the filename is used during discovery):

```python
from habibi.models import PluginResult

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

Use **absolute imports** for scanner interfaces, for example `from habibi.models import Context, Finding, PluginResult`. Do not use package-relative imports such as `from ..models import ...`: Custom plugins are independently loaded Python files and have no parent package context. You can copy a Built-in plugin file, adjust its `info()` version, and install it as a Custom override without rewriting its imports.

`info()` must return a dictionary with a unique plugin name, a numeric dot-separated version, a nonempty list of technologies and a nonempty description. `PLUGIN.name` must match the `info()` name. Plugin code is inspected statically before it is imported or `info()` is called.

### Plugin lookup and listing

`habibi plugins list` prints **PLUGIN NAME, VERSION, FILENAME, TYPE, STATUS**. `TYPE` is `Built-in` or `Custom`; `STATUS` is `Active`, `Overridden` or `Invalid`. A Custom plugin replaces the Built-in plugin **by declared name**, regardless of whether its filename differs. Both can use `windmill.py`. `info` and `remove` first try a direct filename lookup (accepting `windmill` or `windmill.py`) to avoid inventorying every plugin for ordinary operations. Where the requested display name does not match a filename, they fall back to inspecting the dedicated plugin directories; they do not recursively search arbitrary libraries or repositories. `list` and scanning must inspect all installed plugins to discover and validate their metadata.

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
habibi plugins list                 # Table: name, version, filename, type, status
habibi plugins info Example         # Metadata for one plugin (supports filename too)
habibi plugins audit                # Security inspection and runtime interface audit of all
habibi plugins audit Example        # Audit one plugin (supports filename too)
habibi plugins install ./example.py # New install, reinstall, upgrade or downgrade
habibi plugins remove Example       # Remove a Custom plugin (restores overridden Built-in)
```

A third-party plugin is installed under `~/.local/share/habibi/plugins/` for the current user (or under the directory specified by `HABIBI_PLUGIN_DIR`). The installer stages and validates replacement files before activation. Same-version installs replace the file, newer versions upgrade, and older versions ask for confirmation. If validation or activation fails, the existing file is retained or restored. Built-in plugins are distributed with the core release. A Custom plugin may declare the same name and filename as a Built-in plugin; because the two live in different directories, the Custom plugin becomes Active while the Built-in becomes Overridden, without changing its file. Removing the Custom plugin automatically restores the Built-in as Active. Built-in plugin files cannot be removed with the plugin manager. No separate metadata database is maintained.

**Never run plugin commands with `sudo`.** The system-wide core installation (`sudo ./install.sh`) uses static inspection only and does not execute plugin Python code with administrator privileges. Third-party plugins are installed per-user to avoid elevated execution. The same plugin discovery and validation rules apply to Built-in and Custom plugins.

### Security rules file

The user-editable file `plugin_security_rules.txt` contains prohibited function names, one per line. For system-wide installations the initial policy is placed at `/usr/local/share/habibi/plugin_security_rules.txt` (under the selected installation prefix); it is **not overwritten on upgrades**. To supply a different policy, set `HABIBI_PLUGIN_RULES=/path/to/rules.txt`. When working from the source tree, the bundled default file is used if no override exists.

Example:

```text
# Calls to these functions are rejected
os.remove
shutil.rmtree
subprocess.run
eval
exec
```

The Python AST inspector ignores comments, detects direct function calls and some imported aliases, and reports the line number and operation. Invalid rules, malformed source and recognized prohibited calls fail inspection. This is a heuristic policy, not a sandbox or guarantee of safety. Add additional names to the flat file as needed. Plugin installation and audit perform static security inspection **before** executing plugin code; normal plugin audits then load the plugin to validate its runtime interface. An audit is therefore not a safe way to execute arbitrary untrusted plugin files.

## Audit coverage and limitations

- The Git scan covers objects reachable from **local** refs (including fetched remote-tracking refs), not unreachable objects, inaccessible remote refs, deleted hosted history, other forks, issue attachments, CI artifacts or already-copied public material. Run `git fetch` yourself if appropriate.
- Changed staged files are reconstructed from the Git index and scanned separately. This helps catch staged secrets that differ from the working copy, but unchanged files in the index are **not** duplicated into the temporary scan. The temporary files are removed on completion.
- `git ls-files` plus unignored files controls generic/plugin file enumeration. Symbolic links and files outside the repository are not included in that enumeration. Git-ignored files may still be examined by Gitleaks directory mode, depending on its configuration; review exclusions.
- Generic/plugin heuristic scans skip applicable files larger than 1,000,000 bytes and are not parsers for every configuration language. Detected unreadable/oversized applicable files and malformed supported dependency manifests are reported as **incomplete coverage**, with a nonzero error exit code; enumeration exclusions and unrecognized file formats are not exhaustive coverage checks. Gitleaks has separate scanning behavior. The output does not claim that every possible file format or Gitleaks exclusion was audited.
- This is **not** a live Windmill variable audit or a PostgreSQL server/role audit. Secrets stored only in Windmill's database are not automatically in Git, but exports or scripts may have copied their values.
- Core and Built-in plugin findings deliberately omit matched values, but Custom plugins control their own results, and file paths and infrastructure names may themselves be sensitive. Review Custom plugins and store reports outside the public repository.
- Dependency installation is opt-in and changes the machine; the audit itself does not modify the target repository.

## Testing

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q habibi
```

Tests do not require a real Windmill or PostgreSQL server. Live Gitleaks end-to-end behavior needs to be verified in your own environment; test scans here use a simulated scanner.

## Public release checklist

Complete all checks, investigate findings, confirm staged/working/history coverage, check for credentials not recognized by scanners, review committed personal/client data and proprietary assets, and rotate any credential that was ever exposed. Do not assume removing a secret from the current branch removes it from earlier commits. History rewrites require explicit planning and may not remove copies already fetched by others.

## Roadmap (not implemented)

### Optional local-LLM security analysis

Consider an opt-in mode (proposed `--llm`) that uses a **locally hosted** model, such as Ollama, to analyze suspicious repository configuration and code in context, identify potential security risks missed by deterministic rules, and explain findings. This would supplement, **not replace**, Gitleaks, generic checks or specialized plugins.

Design safeguards for any future implementation:

- Verify that the configured LLM endpoint is local; do not send repository content to an external service.
- Treat repository text as untrusted input, not instructions to the model.
- Track which files or excerpts were analyzed and report failed, skipped or incomplete analysis explicitly.
- Prefer targeted files or excerpts to limit runtime and resource use.
- Do not silently dismiss deterministic findings based on LLM output.

This capability is **a future proposal only**. The current release does not provide an `--llm` option. Generic credential assignment detection is independent of an LLM and remains heuristic.

## Release history

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for version changes, issue resolutions, validation records and test traceability.

## License

MIT. See [LICENSE](LICENSE).
