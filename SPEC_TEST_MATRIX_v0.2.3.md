# v0.2.3 requirement-to-test matrix

This matrix traces every agreed requirement to an explicit automated assertion or integration check. Existing v0.2.2 repository-audit behavior is covered by the retained regression tests. No test demonstrates that Python plugin code is safe or fully sandboxed.

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

Not established by automated tests: native macOS behavior and a real installed Gitleaks binary against a live repository; source tests simulate the Gitleaks report format. Independently installed plugins are per-user to avoid executing code as root.
