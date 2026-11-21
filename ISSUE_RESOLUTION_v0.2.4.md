# v0.2.4 Issue resolutions and test traceability

- ISS-001: `secscan --version` now reports the installed distribution version. Test: `test_version_and_help_show_commands`.
- ISS-002: top-level `--help` now explains `secscan plugins <command>` and refers to its help. Test: `test_version_and_help_show_commands`.
- ISS-003: redundant `--list-plugins` removed. Test: `test_redundant_option_removed`; installer test uses `plugins list`.
- ISS-004: plugin `info`/`remove` lookups use direct filename paths first, with fallback for different display names. Tests: `test_direct_filename_lookup_does_not_inventory_all`, `test_fallback_display_name`, `test_info_supports_display_name_and_filename`.
- ISS-005: Custom plugins override Built-in plugins with same declared name, including identical filenames, without changing the Built-in file. Removing Custom restores Built-in. Listing shows Type and Status, including Overridden. Tests: `test_install_custom_same_filename_overrides_and_remove_restores`, `test_install_override_does_not_modify_builtin`, `test_built_in_list_has_type_and_status`, `test_override_security_failure_does_not_replace_builtin_or_load_custom`, `test_built_in_cannot_be_removed_directly`, `test_same_name_custom_upgrade_downgrade_and_reinstall`.
- `.DS_Store` added to `.gitignore`. Check: repository file.

**Limits:** Plugin inventory still loads each installed candidate, as needed to discover metadata. Static inspection is heuristic. macOS-specific installation and live Gitleaks scans require testing in the target environment.
