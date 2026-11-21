#!/usr/bin/env bash
# Install/upgrade secscan in an isolated system-wide Python environment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PREFIX="${SECSCAN_PREFIX:-/usr/local}"
PYTHON="${SECSCAN_PYTHON:-python3}"

usage() {
  cat <<'HELP'
Usage: sudo ./install.sh [--help]
Install or upgrade secscan for all users (macOS and Linux).

Default installation:
  /usr/local/bin/secscan
  /usr/local/lib/repo-sec-scan/releases/<version>/

The same command handles fresh installs and upgrades. Equal versions are left
unchanged; downgrades are refused. Previous releases are retained for rollback.

Optional test/deployment overrides:
  SECSCAN_PREFIX=/some/prefix    Alternate prefix (default /usr/local)
  SECSCAN_PYTHON=/path/python3   Python 3.9+ interpreter

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
if [[ "$PREFIX" != /* || "$PREFIX" == '/' ]]; then echo 'SECSCAN_PREFIX must be an absolute directory other than /.' >&2; exit 2; fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then echo "Python not found: $PYTHON" >&2; exit 2; fi
if [[ "$PREFIX" == /usr/local && "$(id -u)" -ne 0 ]]; then
  echo 'System-wide installation requires root. Run: sudo ./install.sh' >&2; exit 2
fi

VERSION="$($PYTHON - "$SCRIPT_DIR/pyproject.toml" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')
match = re.search(r'(?m)^version\s*=\s*"([0-9]+(?:\.[0-9]+){1,3})"\s*$', p)
if not match:
    sys.exit('Cannot determine a numeric release version from pyproject.toml.')
print(match.group(1))
PY
)"
BASE="$PREFIX/lib/repo-sec-scan"
RELEASES="$BASE/releases"
CURRENT="$BASE/current"
LAUNCHER="$PREFIX/bin/secscan"
mkdir -p "$RELEASES" "$PREFIX/bin"

# The current installation is managed only when it points to a release under this prefix.
OLD_VERSION=''
OLD_TARGET=''
if [[ -e "$CURRENT" || -L "$CURRENT" ]]; then
  if [[ ! -L "$CURRENT" ]]; then echo "Refusing unmanaged installation at $CURRENT" >&2; exit 2; fi
  OLD_TARGET="$(readlink "$CURRENT")"
  case "$OLD_TARGET" in "$RELEASES"/*) ;; *) echo 'Refusing current link outside managed releases.' >&2; exit 2;; esac
  OLD_VERSION="$(basename "$OLD_TARGET")"
  [[ -x "$CURRENT/bin/secscan" ]] || { echo 'Existing installation is incomplete.' >&2; exit 2; }
fi
if [[ -e "$LAUNCHER" || -L "$LAUNCHER" ]]; then
  if [[ ! -L "$LAUNCHER" || "$(readlink "$LAUNCHER")" != "$CURRENT/bin/secscan" ]]; then
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
    same) echo "secscan $VERSION is already installed; no changes made."; exit 0;;
    downgrade) echo "Refusing downgrade from $OLD_VERSION to $VERSION." >&2; exit 2;;
    upgrade) echo "Upgrading secscan from $OLD_VERSION to $VERSION.";;
  esac
else
  echo "Installing secscan $VERSION."
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
WHEEL="$SCRIPT_DIR/dist/repo_sec_scan-${VERSION}-py3-none-any.whl"
if [[ -f "$WHEEL" ]]; then
  "$RELEASES/$VERSION/bin/python" -m pip install --disable-pip-version-check "$WHEEL"
else
  "$RELEASES/$VERSION/bin/python" -m pip install --disable-pip-version-check "$SCRIPT_DIR"
fi
"$RELEASES/$VERSION/bin/python" -I - "$VERSION" <<'PYVERIFY'
from importlib.metadata import version
import sys
actual = version('repo-sec-scan')
if actual != sys.argv[1]: raise SystemExit(f'Installed version mismatch: {actual}')
PYVERIFY
"$RELEASES/$VERSION/bin/secscan" --help >/dev/null
"$RELEASES/$VERSION/bin/secscan" --list-plugins >/dev/null

"$PYTHON" - "$CURRENT" "$RELEASES/$VERSION" <<'PY'
import os, pathlib, sys
link = pathlib.Path(sys.argv[1]); tmp = link.with_name('.current.new.' + str(os.getpid()))
os.symlink(sys.argv[2], tmp)
os.replace(tmp, link)
PY
SWITCHED=1
if [[ ! -L "$LAUNCHER" ]]; then ln -s "$CURRENT/bin/secscan" "$LAUNCHER"; fi
"$LAUNCHER" --help >/dev/null
"$LAUNCHER" --list-plugins >/dev/null
SWITCHED=0
COMMITTED=0
printf 'Installed secscan %s at %s\n' "$VERSION" "$LAUNCHER"
