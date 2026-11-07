#!/usr/bin/env bash
# Release-package installer. Downloading and archive verification live at the root.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  printf '%s\n' 'Usage: deploy/install.sh BIN_DIR [--version TAG]' >&2
  exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
package_root=$(cd -- "$script_dir/.." && pwd -P)
case $1 in
  /*) bin_dir=$1 ;;
  *) bin_dir=$PWD/$1 ;;
esac
shift
# Isolated Python and a trusted cwd prevent imports from the package/bin directory.
cd /
exec python3 -I "$script_dir/lifecycle.py" install --bin-dir "$bin_dir" --distribution-root "$package_root" "$@"
