#!/usr/bin/env bash
# Works offline from the installed deploy directory or a verified release package.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cd /
exec python3 -I "$script_dir/lifecycle.py" uninstall "$@"
