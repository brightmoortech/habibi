#!/usr/bin/env bash
# Install/upgrade habibi in an isolated system-wide Python environment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PREFIX="${HABIBI_PREFIX:-/usr/local}"
PYTHON="${HABIBI_PYTHON:-python3}"

usage() {
  cat <<'HELP'
Usage: sudo ./install.sh [--help]
Install or upgrade habibi for all users (macOS and Linux).

Default installation:
  /usr/local/bin/habibi
  /usr/local/lib/habibi/releases/<version>/

The same command handles fresh installs and upgrades. Equal versions are left
unchanged; downgrades are refused. Previous releases are retained for rollback.

Optional test/deployment overrides:
  HABIBI_PREFIX=/some/prefix    Alternate prefix (default /usr/local)
  HABIBI_PYTHON=/path/python3   Python 3.9+ interpreter

Run from a trusted source checkout. This installer needs Python with venv/pip,
network access or available installation dependencies, and permission to write
into the installation prefix. It never runs Git or Windmill operations.
HELP
}
if [[ $# -ne 0 ]]; then
  if [[ $# -eq 1 && ( "$1" == '--help' || "$1" == '-h' ) ]]; then usage; exit 0; fi
  usage >&2; exit 2
fi

case "$(uname -s)" in Darwin|Linux) ;; *) echo 'Unsupported operating system (macOS/Linux only).' >&2; exit 2;; esac
if [[ "$PREFIX" != /* || "$PREFIX" == '/' ]]; then echo 'HABIBI_PREFIX must be an absolute directory other than /.' >&2; exit 2; fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then echo "Python not found: $PYTHON" >&2; exit 2; fi
if [[ "$PREFIX" == /usr/local && "$(id -u)" -ne 0 ]]; then
  echo 'System-wide installation requires root. Run: sudo ./install.sh' >&2; exit 2
fi

VERSION="$($PYTHON - "$SCRIPT_DIR/habibi/_version.py" <<'PY'
import ast, pathlib, re, sys
path = pathlib.Path(sys.argv[1])
tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
values = [node.value.value for node in tree.body
          if isinstance(node, ast.Assign)
          and any(isinstance(target, ast.Name) and target.id == '__version__' for target in node.targets)
          and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
if len(values) != 1 or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}', values[0]):
    sys.exit('Cannot determine numeric release version from _version.py.')
print(values[0])
PY
)"
BASE="$PREFIX/lib/habibi"
RELEASES="$BASE/releases"
CURRENT="$BASE/current"
LAUNCHER="$PREFIX/bin/habibi"
mkdir -p "$RELEASES" "$PREFIX/bin"

# The current installation is managed only when it points to a release under this prefix.
OLD_VERSION=''
OLD_TARGET=''
if [[ -e "$CURRENT" || -L "$CURRENT" ]]; then
  if [[ ! -L "$CURRENT" ]]; then echo "Refusing unmanaged installation at $CURRENT" >&2; exit 2; fi
  OLD_TARGET="$(readlink "$CURRENT")"
  case "$OLD_TARGET" in "$RELEASES"/*) ;; *) echo 'Refusing current link outside managed releases.' >&2; exit 2;; esac
  OLD_VERSION="$(basename "$OLD_TARGET")"
  [[ -x "$CURRENT/bin/habibi" ]] || { echo 'Existing installation is incomplete.' >&2; exit 2; }
fi
if [[ -e "$LAUNCHER" || -L "$LAUNCHER" ]]; then
  if [[ ! -L "$LAUNCHER" || "$(readlink "$LAUNCHER")" != "$CURRENT/bin/habibi" ]]; then
    echo "Refusing to replace unmanaged command: $LAUNCHER" >&2; exit 2
  fi
fi

if [[ -n "$OLD_VERSION" ]]; then
  RELATION="$($PYTHON - "$VERSION" "$OLD_VERSION" <<'PY'
import sys
try:
    new, old = [[int(x) for x in v.split('.')] for v in sys.argv[1:]]
except ValueError:
    sys.exit('Installed version is not comparable; manual review required')
width = max(len(new), len(old))
new += [0] * (width - len(new)); old += [0] * (width - len(old))
print('same' if new == old else 'upgrade' if new > old else 'downgrade')
PY
)"
  case "$RELATION" in
    same) echo "habibi $VERSION is already installed; no changes made."; exit 0;;
    downgrade) echo "Refusing downgrade from $OLD_VERSION to $VERSION." >&2; exit 2;;
    upgrade) echo "Upgrading habibi from $OLD_VERSION to $VERSION.";;
  esac
else
  echo "Installing habibi $VERSION."
fi

if [[ -e "$RELEASES/$VERSION" ]]; then
  echo "Refusing to overwrite existing release directory: $RELEASES/$VERSION" >&2; exit 2
fi
COMMITTED=0
SWITCHED=0
cleanup() {
  status=$?
  if [[ $status -ne 0 && "$SWITCHED" -eq 1 ]]; then
    echo 'Installation check failed; restoring previous command.' >&2
    if [[ -n "$OLD_TARGET" ]]; then
      "$PYTHON" - "$CURRENT" "$OLD_TARGET" <<'PYROLLBACK'
import os, pathlib, sys
link = pathlib.Path(sys.argv[1]); tmp = link.with_name('.current.rollback.' + str(os.getpid()))
os.symlink(sys.argv[2], tmp)
os.replace(tmp, link)
PYROLLBACK
    else
      rm -f "$CURRENT" "$LAUNCHER"
    fi
  fi
  if [[ $status -ne 0 && "$COMMITTED" -eq 1 ]]; then rm -rf "$RELEASES/$VERSION"; fi
}
trap cleanup EXIT

# Create the venv at its final path: virtualenv executables and shebangs are not relocatable.
COMMITTED=1
"$PYTHON" -m venv "$RELEASES/$VERSION"
WHEEL="$SCRIPT_DIR/dist/habibi-${VERSION}-py3-none-any.whl"
if [[ -f "$WHEEL" ]]; then
  "$RELEASES/$VERSION/bin/python" -m pip install --disable-pip-version-check "$WHEEL"
else
  "$RELEASES/$VERSION/bin/python" -m pip install --disable-pip-version-check "$SCRIPT_DIR"
fi
"$RELEASES/$VERSION/bin/python" -I - "$VERSION" <<'PYVERIFY'
from importlib.metadata import version
import sys
actual = version('habibi')
if actual != sys.argv[1]: raise SystemExit(f'Installed version mismatch: {actual}')
PYVERIFY
"$RELEASES/$VERSION/bin/habibi" --help >/dev/null
RULES_DIR="$PREFIX/share/habibi"
mkdir -p "$RULES_DIR"
# User-editable policy survives core upgrades; never overwrite an existing policy.
if [[ ! -e "$RULES_DIR/plugin_security_rules.txt" ]]; then
  cp "$SCRIPT_DIR/habibi/plugins/plugin_security_rules.txt" "$RULES_DIR/plugin_security_rules.txt"
fi
"$RELEASES/$VERSION/bin/habibi" plugins audit --static-only >/dev/null

"$PYTHON" - "$CURRENT" "$RELEASES/$VERSION" <<'PY'
import os, pathlib, sys
link = pathlib.Path(sys.argv[1]); tmp = link.with_name('.current.new.' + str(os.getpid()))
os.symlink(sys.argv[2], tmp)
os.replace(tmp, link)
PY
SWITCHED=1
if [[ ! -L "$LAUNCHER" ]]; then ln -s "$CURRENT/bin/habibi" "$LAUNCHER"; fi
"$LAUNCHER" --help >/dev/null
"$LAUNCHER" plugins audit --static-only >/dev/null
SWITCHED=0
COMMITTED=0
printf 'Installed habibi %s at %s\n' "$VERSION" "$LAUNCHER"
