# v0.2.3 implementation verification

## Inspection 1: specification semantics

Reviewed the agreed design against plugin discovery, `info()`, the CLI, the flat AST rule list, the system installer, normal repository scanning, downgrade behavior and rollback. All existing repository scanning entry points were retained. The requirements-to-tests mapping is in `SPEC_TEST_MATRIX_v0.2.3.md`.

## Inspection 2: code quality

Issues detected and corrected before final testing:

1. Root-executed installer verification was replaced by non-executing static plugin auditing.
2. Python bytecode caching could display stale plugin information after rapid same-size upgrades; the loader now compiles a fresh source snapshot.
3. An AST-check/import race could allow executing bytes different from those inspected; the loader now executes the exact source string used by AST inspection.
4. The PostgreSQL plugin stopped early on review-only warnings; it now stops only on high-severity findings.
5. Installation of a valid replacement was blocked when an existing plugin was corrupted; the installer can now repair the installation while retaining rollback protection.
6. A failed rollback could cause accidental deletion of the recovery copy; recovery copies are preserved if rollback itself fails.
7. Plugin discovery was prevented from loading files inside the audited repository, even if an environment override points there.
8. Root executions of the runtime plugin loader were blocked; only static inspection is allowed in the root-level application installer.

## Inspection 3: post-correction review

Rechecked the plugin loader, security scanner, manager, core dispatch, bundled plugins, installer and README. Confirmed there are no Windmill/PostgreSQL imports in the registry; all installed plugin modules use the same interface, security-first inspection and load path. There is no metadata registry/database. Bundled plugins travel with the core version, while independently installed plugins reside in the user's plugin directory.

## Scope and limitations

- Passing AST rules reduces risk but **does not prove code safe**; Python plugins run with the user's normal permissions and can perform indirect operations that static rules miss.
- Bundled plugin verification as root is **static only**; runtime compliance is tested as a normal user.
- The installation is user-scoped for independently installed plugins. It avoids running plugins or their `info()` functions with root privileges.
- Native macOS execution and real Gitleaks integration have not been tested in this environment. Existing Gitleaks integration tests use simulated output.
