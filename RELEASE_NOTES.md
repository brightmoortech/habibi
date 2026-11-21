# Release Notes

Release history and validation records for Repo Security Scanner. For installation, usage, plugin development and security precautions, see [README.md](README.md).

## v0.2.7 — Grouped terminal security report

- **ISS-012:** "Discovered Technologies" includes both repository platform markers and technologies recognized through declared packages and specialized plugins, with available evidence file counts. Technology inventory no longer presents a misleading "Problems" count; genuine discovery limitations remain visible.
- **ISS-013:** Live, ordered terminal sections for discovered technologies, repository security, technology security, unsupported packages, and a consolidated scan summary. Each check reports STARTED and its result, followed by the specific findings and coverage limitations associated with that check. Per-section totals and a final security finding breakdown accompany the details.
- Docker image digests are shortened **only in terminal output**. Full original package references remain in JSON. Unsupported packages are explicitly described as generic-only coverage. Early-stop paths identify unfinished sections and incomplete coverage.
- The scanner core supplies optional structured progress events; terminal formatting lives separately in `repo_sec_scan/reporting.py`. Existing JSON result fields and security detection rules remain supported.
- Regression tests: `tests/test_reporting_027.py` covers discovery merging, execution order, grouped findings, per-section counts, unsupported packages, full JSON references, incomplete discovery, early-stop behavior, and CLI report output. All previous suites are retained.
- **Review cycle:** First specification and code-quality inspection identified the need to keep discovery separate from findings and avoid changing JSON identifiers. Implementation fixes separated terminal rendering from scanning and added early-stop handling. Updated automated tests passed. Second inspection corrected no-plugin message ordering, avoided counting the same coverage issue twice in the final summary, and removed an unused reporting field. Final full regression: **83 tests passed, 0 failures** under a non-root Linux account; Python compilation and installer Bash syntax checks passed.
- Remaining limitations: heuristic scanning does not establish safety; real Gitleaks execution and native macOS validation require end-user verification.

## v0.2.6 — Help clarity and portable Built-in plugin imports

- **ISS-009:** Main `secscan --help` usage now shows both repository scanning and plugin-management command forms.
- **ISS-010:** `secscan plugins --help` now shows each subcommand, required or optional arguments, and a description; individual subcommand help remains available.
- **ISS-011:** Windmill and PostgreSQL plugins now use absolute `repo_sec_scan.models` imports, so their files can be copied and installed unchanged as Custom plugins. This fixes the relative-import failure reported on macOS.
- Added regression tests for command-help output, all plugin subcommand help screens, and end-to-end copied Built-in plugin installation and override restoration. Updated installer integration test for the two-line usage format. No changes to plugin loader design, detection rules, or core scanning behavior.
- **Validation:** 72 tests passed, 0 failures or skips under a non-root Linux account, with the v0.2.6 wheel present. Python compilation and Bash syntax checks passed. Native macOS testing and live Gitleaks integration remain to be verified for this release.

## v0.2.5 — Source execution and macOS test portability

**Scope:** Targeted correction of issues ISS-006–ISS-008. Scanner functionality, plugin architecture and security policy are unchanged.

| Issue | Correction | Verification |
| --- | --- | --- |
| ISS-006: version lookup fails without installed metadata | `repo_sec_scan/_version.py` is the single authoritative version source. CLI imports it directly, setuptools obtains its version using dynamic attribute metadata, and `install.sh` reads the literal using the Python AST without executing application code as root. | `tests/test_version_025.py` (3 cases), CLI source-run tests and installer integration |
| ISS-007: macOS `/var` vs `/private/var` comparisons | Resolve both expected and actual paths in affected tests. No macOS-specific production branches added. | `tests/test_cli_overrides_024.py`, `tests/test_plugin_lifecycle_023.py` |
| ISS-008: rollback failure injection not triggered | Normalize the destination path comparison in the injected failure hook; verify failed installation, original file bytes and successful loading of the restored plugin. | `test_failed_activation_restores_existing` |

**Review:** Version source is declared once; wheel metadata contains `0.2.5` and `_version.py`. The loader, plugin management and repository scan implementation were left unchanged for these fixes. Validation in this environment: **67 tests passed, 0 failures** as an unprivileged Linux user; source `--version`, Python compilation and installer Bash syntax checks passed. Native macOS regression testing, live Gitleaks end-to-end testing and system-wide macOS upgrade remain unverified.

## v0.2.4 — CLI improvements and plugin overrides

| Issue | Change | Tests |
| --- | --- | --- |
| ISS-001 | Added `secscan --version` | `test_version_and_help_show_commands` |
| ISS-002 | Top-level help shows plugin subcommand syntax | `test_version_and_help_show_commands` |
| ISS-003 | Removed redundant `--list-plugins`; installer uses `plugins list` | `test_redundant_option_removed`, installer integration |
| ISS-004 | Plugin lookup tries direct filenames before fallback discovery by display name | `test_direct_filename_lookup_does_not_inventory_all`, `test_fallback_display_name`, `test_info_supports_display_name_and_filename` |
| ISS-005 | Custom plugins override Built-in plugins by declared name even with identical filenames; removing Custom restores Built-in, with Type and Status columns in listings | `test_install_custom_same_filename_overrides_and_remove_restores`, `test_install_override_does_not_modify_builtin`, `test_built_in_list_has_type_and_status`, `test_override_security_failure_does_not_replace_builtin_or_load_custom`, `test_built_in_cannot_be_removed_directly`, `test_same_name_custom_upgrade_downgrade_and_reinstall` |

`.DS_Store` is ignored in `.gitignore`. Plugin inventories still inspect installed candidates to obtain their metadata; static inspection remains heuristic. Native macOS system-wide installation and live Gitleaks integration were not verified for this release.

## v0.2.3 — Self-describing plugins and lifecycle management

Introduced automatic directory discovery, uniform plugin `info()` metadata and interface validation, a configurable flat list of AST-based prohibited calls, plugin list/info/audit/install/remove commands, per-user Custom plugins, downgrade confirmation and rollback. Built-in Windmill/PostgreSQL modules use the same discovery and validation interface as Custom plugins; no plugin-name registry or metadata database is maintained. The system installer performs only static inspection as root.

**Specification review:** Checked discovery, `info()`, CLI, security rules, installer, normal scanning, downgrade and rollback against requirements. Existing repository audit entry points retained.

**Code-quality review and corrections:**

1. Replaced root-executed plugin verification with static-only installer inspection.
2. Prevented stale information caused by Python bytecode caching during rapid plugin replacement by compiling a fresh source snapshot.
3. Ensured inspected AST source bytes are the exact bytes executed.
4. Adjusted PostgreSQL early-stop logic so review-only warnings do not stop the audit.
5. Allowed reinstall to repair a corrupt existing plugin while preserving rollback safety.
6. Preserved recovery copies if rollback itself fails.
7. Prevented discovery and execution of plugin files inside the audited repository.
8. Blocked runtime plugin loading under root; root installer uses static inspection only.

**Post-correction review:** Rechecked registry, security rules, manager, core dispatch, bundled plugins, installer and README. Confirmed no hardcoded Windmill/PostgreSQL imports in registry, no metadata database, and separation of core-bundled modules from user-installed modules.

### v0.2.3 specification-to-test traceability

The following test cases remain in the included `tests/` directory. Their names document the validated behavior; tests do not establish that plugin execution is safe or sandboxed.

| Agreed requirement | Verification |
| --- | --- |
| Windmill and PostgreSQL use the same plugin discovery as other plugins | `test_bundled_no_hardcoded_registry`, `test_builtin_metadata_and_interfaces` |
| No hardcoded built-in imports or registry metadata database | `test_bundled_no_hardcoded_registry`, `test_automatic_directory_discovery` |
| Automatically discover newly added plugins | `test_automatic_directory_discovery`, `test_directory_plugin_loading` |
| Each plugin exports `info()` with name, version, technologies, description | `test_builtin_metadata_and_interfaces`, `test_plugin_list_columns_and_info` |
| Require `matches`, `detect`, `scan` interface | `test_builtin_metadata_and_interfaces`, `test_invalid_plugin_skipped_and_audited` |
| Ignore noncompliant plugins during scan and report failures | `test_invalid_plugin_skipped_and_audited`, `test_plugin_error_reduces_coverage` |
| Detect duplicate plugin names | `test_duplicate_name_reported` |
| Maintain generic scan when plugin unsupported | `test_repository_e2e_unknown_package_fallback`, `test_unknown_dummy_package_is_reported_exactly_no_plugin` |
| Recognize packages and configuration markers | `test_declared_package_names_are_not_guessed`, `test_discover` |
| Never discover plugin files inside repository being scanned | `test_plugins_inside_scanned_repo_never_discovered` |
| `plugins list` formatted table with name, version, filename | `test_plugin_list_columns_and_info`, `test_legacy_cli_and_help` |
| `plugins info <name>` | `test_plugin_list_columns_and_info`, `test_unknown_plugin_reported` |
| `plugins audit` all | `test_audit_one_name_and_all`, `test_invalid_plugin_skipped_and_audited` |
| `plugins audit <name>` one | `test_audit_one_name_and_all`, `test_unknown_plugin_reported` |
| `plugins install <file>` initial install | `test_install_reinstall_upgrade` |
| Same-version installation replaces file, even if existing file is damaged | `test_install_reinstall_upgrade`, `test_reinstall_repairs_corrupt_existing_plugin` |
| Newer-version installation upgrades | `test_install_reinstall_upgrade` |
| Downgrade requires confirmation; refusal preserves prior version | `test_downgrade_declined_then_confirmed` |
| Approved downgrade installs older version | `test_downgrade_declined_then_confirmed` |
| Invalid replacement preserves installed version | `test_install_blocked_preserves_existing` |
| Activation failure restores prior version | `test_failed_activation_restores_existing` |
| Third-party plugin removal; bundled plugins protected | `test_remove_external_but_not_bundled` |
| No separate upgrade command | `test_plugin_commands_do_not_offer_upgrade` |
| Security rules from user-editable flat file | `test_custom_flat_rule` |
| AST scanner finds executable prohibited calls and reports line | `test_static_scanner_ignores_comments_detects_calls` |
| AST scanner ignores comments | `test_static_scanner_ignores_comments_detects_calls` |
| Import aliases resolve before rule matching | `test_static_scanner_ignores_comments_detects_calls` |
| Invalid rules and invalid Python fail closed | `test_invalid_rules_and_syntax_fail_closed` |
| Static check and executed code use identical inspected bytes | `test_inspected_bytes_are_executed` |
| Explicit plugin directory inside scanned repository cannot be executed | `test_repo_plugin_dir_env_is_never_executed_during_audit` |
| Static inspection before loading or calling `info()` | `test_static_scan_precedes_code_execution`, `test_install_blocked_preserves_existing` |
| No root execution of plugin code | `test_no_root_execution`, `test_installer_static_only` |
| System installer validates bundled plugins statically | `test_installer_static_only`, `test_install_repeat_and_failed_upgrade_preserves_installation` |
| New bundled plugins installed automatically with core | `test_bundled_new_file_auto_discovered` |
| Third-party plugins survive core upgrades | `test_external_plugin_directory_not_tied_to_release`, `test_install_repeat_and_failed_upgrade_preserves_installation` |
| Core installer rollback on failed upgrade | `test_install_repeat_and_failed_upgrade_preserves_installation` |
| Legacy `--list-plugins` and normal scan options retained | `test_legacy_cli_and_help`, `test_all_scans_with_simulated_gitleaks` |
| Git history, worktree, staged snapshot | `test_all_scans_with_simulated_gitleaks`, `test_staged_oversized_file_incomplete` |
| High severity stop, warnings do not cause early stop | `test_stop_on_first_literal`, `test_warning_does_not_cause_early_stop`, `test_postgres_stop_on_finding_ignores_review_warnings` |
| Coverage gap for unreadable/oversized or malformed files | `test_oversized_generic_file_incomplete`, `test_oversized_plugin_file_incomplete`, `test_malformed_pyproject_reported_incomplete` |
| README template, lifecycle instructions and trust warning | `test_readme_contract` |
| Static checks are heuristic, not safety proof | `test_readme_contract` (documentation only; not a guarantee) |
| System-wide installer and isolated release | `test_install_repeat_and_failed_upgrade_preserves_installation` |

**Limits:** Static AST rules are heuristic, not a safety proof. Custom plugins execute with their user's permissions; no live Windmill/PostgreSQL server is queried. Source-based tests simulate Gitleaks output; native macOS installation and live Gitleaks integration were not verified in this environment.

## v0.2.2 — System-wide installation

Added `sudo ./install.sh` for first install and upgrades; isolated versioned installations with current-release activation and rollback, a bundled wheel and `secscan` as the primary command. CLI help identifies `secscan`; installation verifies the new release and preserves the previous version on failed upgrade. Native macOS installation was not exercised during the original release validation.

## v0.2.1 — Repository audit coverage

- Structured TOML parsing supports optional and grouped dependencies without guessing technology names.
- `--stop-on-finding` stops only on high-severity suspected exposures; warnings do not end the scan.
- Oversized/unreadable files and malformed supported manifests produce explicit incomplete-coverage reports.
- Regression tests cover fictitious package names verbatim with generic-only fallback.

## General testing notes

Run from the source directory without `sudo`:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q repo_sec_scan
bash -n install.sh
```

Tests do not require live Windmill or PostgreSQL instances. Integration checks use simulated Gitleaks output; live Gitleaks scans and platform-specific installer validation should be performed separately. A passing static plugin inspection does not establish code safety.
