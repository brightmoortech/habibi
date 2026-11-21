# Repo Security Scanner

A modular, **read-only-by-default** security audit tool for Git repositories that you intend to publish or make public. It combines broad secret scanning with repository technology discovery and optional technology-specific checks.

**A clean audit is not a guarantee that a repository is safe to publish.** Gitleaks detects recognizable secrets; additional checks are heuristic. Review licenses, private information, test data, exported infrastructure settings and upstream forks/caches before changing repository visibility.

## Features

- Runs [Gitleaks](https://github.com/gitleaks/gitleaks) against **Git history** (all locally available refs), the **working directory**, and the **staged snapshot**.
- Scans accessible repository files for recognizable credential assignments and sensitive filenames.
- Inventories declared package and image names from supported repository manifests without guessing product names. It does not inspect machine-installed software or execute detected code.
- Runs a dedicated scanner when a supported technology is detected. Otherwise explicitly reports **no specialized handling; generic scan applied**.
- **Included independent security plugins:** Windmill and PostgreSQL. Plugins own their package matching and configuration detection. Additional plugins can be installed using Python entry points without changing the core.
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
  ├── plugins/registry.py: built-ins + third-party entry-point plugins
  │     └── plugin.matches(package) / plugin.detect(context) → plugin.scan(context)
  │     ├── plugins/windmill.py: Windmill export/credential heuristics
  │     └── plugins/postgresql.py: SQL, authentication and credential heuristics
  └── report aggregation: findings and coverage, no matched values
```

Generic scanning always runs. A plugin supplements rather than replaces it. Plugin failures are marked **incomplete**, never as a pass. The scan does not call Windmill APIs, query PostgreSQL, modify repositories, or fetch remote Git refs.

## Installation

Required tools:

- Python **3.9 or newer** (`tomli` is installed as a conditional dependency on Python 3.9–3.10; Python 3.11+ uses built-in `tomllib`).
- Git.
- Gitleaks **v8** with `git` and `dir` commands.

Clone or extract this repository and run it without installing the Python package:

```bash
cd repo-sec-scan
python3 -m repo_sec_scan --help
python3 -m repo_sec_scan /path/to/a/git/project
```

Or install the CLI locally:

```bash
python3 -m pip install .
secscan /path/to/a/git/project
```

Before scanning all remote history, **manually** refresh refs in the *target* repository if allowed:

```bash
cd /path/to/a/git/project
git fetch origin --prune --tags
```

The auditor never fetches, pushes, rewrites history or edits tracked files. `--install-missing` offers installation for Git/Gitleaks **only** after a per-tool confirmation: Homebrew on macOS (or Linux with Homebrew), APT via `sudo` on supported Linux machines. The Linux package source may not provide Gitleaks; failure is reported. Python itself must already be installed. Never run installation on production machines without reviewing the proposed package-manager command.

## CLI options

| Option | Behavior |
| --- | --- |
| `repository` | Optional path inside target Git repository; default `.`. |
| `-h`, `--help` | Display help text and all arguments. |
| `--stop-on-finding` | Stop on the first high-severity potential exposure. Review-only warnings do not stop the audit. Default runs all checks. |
| `--install-missing` | Offer approved package-manager installation of missing Git/Gitleaks tools. No automatic installation by default. |
| `--report PATH` | Save a JSON report; the script rejects a destination inside the audited repository. |
| `--list-plugins` | List installed specialized scanners and exit. |

Example:

```bash
python3 -m repo_sec_scan ~/Development/develop/automation_lab --report ~/audit-output.json
python3 -m repo_sec_scan /path/to/repo --stop-on-finding
python3 -m repo_sec_scan --list-plugins
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

**Included plugins:**

- **Windmill:** examines repository workflow exports for possible embedded credentials and exported values. Detects Windmill paths and flow files, and recognizes relevant declared Windmill packages/images.
- **PostgreSQL:** checks applicable `pg_hba.conf` rules, SQL privileges/destructive operations, and credential-bearing connection URLs. Recognizes relevant PostgreSQL drivers and images.

Neither plugin connects to a live service or reads live Windmill variables. Findings are candidates for review, not automatically proven security vulnerabilities.

## How to extend it

A plugin supplies three operations: `matches(package_name)`, `detect(context)` and `scan(context, stop_on_finding=False)`. `matches` recognizes declared names, `detect` recognizes other repository evidence, and `scan` returns sanitized findings. **No core discovery rules need changing to support a new plugin.**

```python
from repo_sec_scan.models import Finding, PluginResult

class ExamplePlugin:
    name = "Example"

    def matches(self, package_name):
        return package_name.lower() == "example-package"

    def detect(self, context):
        return any(path.name == "example.conf" for path in context.files)

    def scan(self, context, stop_on_finding=False):
        result = PluginResult(self.name, [self.name])
        # Inspect context.files under context.root; do not execute repository code.
        # Never store matched secrets in Finding.detail or log output.
        return result

PLUGIN = ExamplePlugin()
```

**Bundled plugin:** Add the module inside `repo_sec_scan/plugins/` and import its `PLUGIN` into `plugins/registry.py`.

**Independently installed plugin:** Publish a Python distribution with this `pyproject.toml` entry-point declaration:

```toml
[project.entry-points."repo_sec_scan.plugins"]
example = "example_scanner.plugin:PLUGIN"
```

When the distribution is installed in the same Python environment as `secscan`, its plugin is discovered through Python package metadata. It does not need changes to the core or registry. The plugin must provide a unique `name`, and all three methods. Run `secscan --list-plugins` to verify installation.

Treat third-party plugins as **trusted executable code**: installing a plugin allows its Python code to run during plugin discovery and scanning. Only install plugins you trust. Plugin import errors are currently ignored during loading; `--list-plugins` shows what was successfully loaded, not a comprehensive import-error report.

Test clean results, positive findings, false-positive boundaries, package matching, configuration-only detection, and early-stop behavior. Do not add network calls or file modification to scanners without an explicitly authorized separate feature.

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

## License

MIT. See [LICENSE](LICENSE).

## v0.2.1 changes

- Structured TOML parsing improves recognition of optional and grouped dependencies without guessing technology names.
- `--stop-on-finding` only stops on high-severity suspected exposures; warning-only conditions allow the audit to finish.
- Oversized/unreadable files and invalid supported manifests are explicitly reported as coverage limitations. A clean finding count cannot override incomplete coverage.
- Regression tests include a repository with a fictitious, unsupported package name; it is listed verbatim and receives the generic-only fallback.
