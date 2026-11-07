#!/usr/bin/env bash
# Download and validate releases; installed deploy scripts own the lifecycle.
set -euo pipefail
umask 077

repository=yond36/xray-relay-panel
installed_root=/opt/xray-relay-panel
action=
version=latest
version_given=false
arch=
local_package=
verify_package=
stage=
python_command=python3
uninstall_flags=()

usage() {
  printf '%s\n' \
    'Xray Relay Panel installer (Linux/systemd, amd64 or arm64)' \
    'Usage: bash install.sh [install|upgrade|update|uninstall|status] [OPTIONS]' \
    '       bash install.sh --verify-package PATH --version TAG --arch amd64|arm64' \
    '' \
    '  --version TAG          Fixed release tag, e.g. v0.2.2; default: latest stable' \
    '  --local-package PATH   Offline package with its adjacent .sha256; requires TAG' \
    '  --verify-package PATH  Read-only verification; no root, Linux, or extraction' \
    '  --arch amd64|arm64     Required only for --verify-package' \
    '  --purge                Forward to uninstall: remove owned panel data/config' \
    '  --remove-local-node    Forward to uninstall: remove the owned local node' \
    '  --yes                  Forward to uninstall: confirm destructive options' \
    '  -h, --help             Show help without checking OS or privileges' \
    '' \
    'Without an action: show a menu on a terminal, otherwise install.' \
    'Offline install/upgrade requires python3 and sudo/visudo already installed.' \
    'Destructive confirmation and ownership checks belong to deploy/lifecycle.py.' \
    'Limits: package 256 MiB, file 128 MiB, total files 512 MiB, 4096 tar headers.'
}

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
need_value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || fail "$1 requires a value"; }
valid_tag() { [[ $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; }
absolute_path() {
  case $1 in
    /*|[[:alpha:]]:[\\/]*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$PWD" "$1" ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    install|upgrade|update|uninstall|status)
      [[ -z $action ]] || fail 'Specify only one action'
      action=$1; [[ $action != update ]] || action=upgrade; shift ;;
    --version)
      need_value "$@"; version=$2; version_given=true; shift 2 ;;
    --version=*) version=${1#*=}; version_given=true; shift ;;
    --local-package)
      need_value "$@"; [[ -z $local_package ]] || fail 'Repeated --local-package'
      local_package=$(absolute_path "$2"); shift 2 ;;
    --local-package=*)
      [[ -n ${1#*=} && -z $local_package ]] || fail 'Invalid --local-package'
      local_package=$(absolute_path "${1#*=}"); shift ;;
    --verify-package)
      need_value "$@"; [[ -z $verify_package ]] || fail 'Repeated --verify-package'
      verify_package=$(absolute_path "$2"); shift 2 ;;
    --verify-package=*)
      [[ -n ${1#*=} && -z $verify_package ]] || fail 'Invalid --verify-package'
      verify_package=$(absolute_path "${1#*=}"); shift ;;
    --arch) need_value "$@"; arch=$2; shift 2 ;;
    --arch=*) arch=${1#*=}; shift ;;
    --purge|--remove-local-node|--yes) uninstall_flags+=("$1"); shift ;;
    *) fail "Unknown argument: $1 (use --help)" ;;
  esac
done
[[ $version == latest ]] || valid_tag "$version" || fail 'Invalid release tag; expected vMAJOR.MINOR.PATCH[-prerelease]'

# This verifier is bootstrap-owned. No code from the archive is imported or run.
# An empty destination means read-only verification, including on macOS/Windows.
validate_package() {
  "$python_command" -I - "$1" "$version" "$arch" "${2:-}" <<'PY'
import contextlib
import gzip
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile

MAX_ARCHIVE = 256 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_STREAM = MAX_TOTAL + 16 * 1024 * 1024
MAX_HEADERS = 4096
MAX_METADATA = 64 * 1024
CHUNK = 1024 * 1024


def reject(message):
    raise ValueError(message)


def regular_open(path, limit):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        reject('not a regular file within the size limit: ' + path.name)
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    stream = os.fdopen(descriptor, 'rb')
    after = os.fstat(stream.fileno())
    if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        stream.close()
        reject('file changed while opening: ' + path.name)
    return stream


class LimitedReader:
    def __init__(self, stream):
        self.stream = stream
        self.count = 0

    def read(self, size=-1):
        remaining = MAX_STREAM - self.count
        size = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self.stream.read(size)
        self.count += len(data)
        if self.count > MAX_STREAM:
            reject('decompressed tar exceeds the size limit')
        return data


class CheckedInfo(tarfile.TarInfo):
    headers = 0

    def _proc_member(self, archive):
        # Python 3.12.16 parses headers through _frombuf(), bypassing public
        # frombuf() overrides. Both parser paths dispatch here before reading
        # PAX/GNU metadata, including the first header and nested headers.
        type(self).headers += 1
        if type(self).headers > MAX_HEADERS:
            reject('too many tar headers')
        metadata = (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME)
        if self.type in metadata:
            if self.size < 0 or self.size > MAX_METADATA:
                reject('tar metadata exceeds the size limit')
        elif self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            reject('links and special tar entries are forbidden')
        elif self.size < 0 or self.size > MAX_FILE:
            reject('tar member exceeds the file size limit')
        return super()._proc_member(archive)


def verify():
    path = Path(sys.argv[1])
    tag, arch, destination = sys.argv[2:5]
    if arch not in ('amd64', 'arm64') or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?', tag):
        reject('a fixed release tag and supported architecture are required')
    root = 'xray-relay-panel-linux-' + arch
    asset = root + '.tar.gz'
    if path.name != asset:
        reject('expected exact package filename: ' + asset)
    required = {
        root + '/' + name for name in (
            'install.sh', 'bin/xray-panel', 'bin/xray-panel-nodectl',
            'deploy/install.sh', 'deploy/uninstall.sh', 'deploy/lifecycle.py',
            'deploy/xray-relay-panel.service',
        )
    }
    with regular_open(Path(str(path) + '.sha256'), 1024) as checksum:
        record = checksum.read(1025)
    match = re.fullmatch(rb'([0-9a-fA-F]{64}) [ *]' + re.escape(asset.encode('ascii')) + rb'\r?\n?', record)
    if match is None:
        reject('SHA256 sidecar must contain one 64-hex digest and the exact package filename')
    expected = match.group(1).decode('ascii').lower()
    with contextlib.ExitStack() as stack:
        source = stack.enter_context(regular_open(path, MAX_ARCHIVE))
        initial = os.fstat(source.fileno())
        # Installation reads a private snapshot, so changing a local input after
        # hashing cannot substitute bytes between verification and extraction.
        snapshot = stack.enter_context(tempfile.TemporaryFile(dir=destination)) if destination else source
        digest = hashlib.sha256()
        compressed = 0
        while True:
            data = source.read(CHUNK)
            if not data:
                break
            compressed += len(data)
            if compressed > MAX_ARCHIVE:
                reject('compressed package exceeds the size limit')
            digest.update(data)
            if destination:
                snapshot.write(data)
        if digest.hexdigest() != expected:
            reject('SHA256 mismatch')
        snapshot.seek(0)
        extraction = Path(destination) / 'unpacked' if destination else None
        if extraction is not None:
            extraction.mkdir(mode=0o700)  # Never reuse an existing extraction tree.
        seen, files, directories = set(), set(), set()
        count = total = 0
        compressed_stream = stack.enter_context(gzip.GzipFile(fileobj=snapshot, mode='rb'))
        bounded = LimitedReader(compressed_stream)
        # One-block buffering leaves all trailing bytes available for validation.
        with tarfile.open(fileobj=bounded, mode='r|', bufsize=512, tarinfo=CheckedInfo) as archive:
            for item in archive:
                count += 1
                if count > MAX_HEADERS:
                    reject('too many tar members')
                name = item.name
                if item.isdir() and name.endswith('/'):
                    name = name[:-1]
                if not name or len(name) > 512 or '\\' in name or ':' in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
                    reject('unsafe tar member name')
                parts = name.split('/')
                if parts[0] != root or any(p in ('', '.', '..') for p in parts):
                    reject('absolute path, traversal, or unexpected package root: ' + name)
                if name in seen:
                    reject('duplicate tar member: ' + name)
                seen.add(name)
                if item.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE) or item.sparse is not None:
                    reject('links, sparse files, and special tar entries are forbidden')
                if item.mode & 0o7000:
                    reject('setuid, setgid, and sticky tar modes are forbidden')
                if item.size < 0 or item.size > MAX_FILE or (item.isdir() and item.size != 0):
                    reject('invalid tar member size')
                parents = {'/'.join(parts[:i]) for i in range(1, len(parts))}
                if parents & files or (item.isfile() and (name in directories or len(parts) == 1)):
                    reject('conflicting file/directory paths')
                directories.update(parents)
                if item.isdir():
                    directories.add(name)
                    if extraction is not None:
                        (extraction / name).mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                files.add(name)
                total += item.size
                if total > MAX_TOTAL:
                    reject('total file size exceeds the limit')
                if name in required and item.size == 0:
                    reject('empty required package file: ' + name)
                output = None
                if extraction is not None:
                    target = extraction.joinpath(*parts)
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    output = target.open('xb')
                with contextlib.ExitStack() as member_stack:
                    content = member_stack.enter_context(archive.extractfile(item))
                    if output is not None:
                        member_stack.enter_context(output)
                    remaining = item.size
                    while remaining:
                        data = content.read(min(CHUNK, remaining))
                        if not data:
                            reject('truncated tar member: ' + name)
                        remaining -= len(data)
                        if output is not None:
                            output.write(data)
                if extraction is not None:
                    target.chmod(0o755 if item.mode & 0o111 else 0o644)
        # Drain gzip to verify its trailer/CRC, enforce the stream limit, and
        # reject hidden concatenated tar members or other non-padding content.
        while True:
            padding = bounded.read(CHUNK)
            if not padding:
                break
            if padding.strip(b'\0'):
                reject('nonzero data after the tar end marker')
        missing = required - files
        if missing:
            reject('missing required package files: ' + ', '.join(sorted(missing)))
        final = os.fstat(source.fileno())
        if (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (final.st_size, final.st_mtime_ns, final.st_ctime_ns):
            reject('package changed during verification')
    print('Verified {} for {} ({}): {} members, {} file bytes'.format(asset, tag, arch, count, total))


try:
    verify()
except (OSError, ValueError, tarfile.TarError, EOFError, UnicodeError, RecursionError) as error:
    print('Package verification failed: ' + str(error), file=sys.stderr)
    sys.exit(1)
PY
}

if [[ -n $verify_package ]]; then
  [[ -z $action && -z $local_package && ${#uninstall_flags[@]} -eq 0 ]] || fail '--verify-package cannot be combined with lifecycle actions/options'
  [[ $version_given == true && $version != latest ]] || fail '--verify-package requires --version TAG (not latest)'
  [[ $arch == amd64 || $arch == arm64 ]] || fail '--verify-package requires --arch amd64|arm64'
  cd /  # Never import Python modules with an untrusted caller/extraction cwd.
  # Windows can expose a nonfunctional python3 app alias alongside real Python.
  if command -v python3 >/dev/null 2>&1 && python3 -I -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
    python_command=python3
  elif command -v python >/dev/null 2>&1 && python -I -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
    python_command=python
  else
    fail 'Read-only verification requires Python 3.8+ (python3 or python)'
  fi
  validate_package "$verify_package"
  exit 0
fi
[[ -z $arch ]] || fail '--arch is only supported with --verify-package; installation detects the host architecture'
if [[ -z $action ]]; then
  if [[ -t 0 && -t 1 ]]; then
    printf '%s\n' 'Xray Relay Panel 管理菜单' '1) 安装' '2) 升级' '3) 卸载' '4) 状态' '0) 退出'
    read -r -p '请选择 [1]: ' choice || choice=0
    case ${choice:-1} in 1) action=install ;; 2) action=upgrade ;; 3) action=uninstall ;; 4) action=status ;; 0) exit 0 ;; *) fail '无效选择' ;; esac
  else
    action=install
  fi
fi
if [[ $action != uninstall && ${#uninstall_flags[@]} -gt 0 ]]; then
  fail '--purge, --remove-local-node, and --yes are uninstall options'
fi
[[ $(uname -s) == Linux ]] || fail 'Installation and lifecycle actions require Linux with systemd; --help/--verify-package are portable'
[[ $EUID -eq 0 ]] || fail 'Run as root: sudo bash install.sh [install|upgrade|uninstall|status] [OPTIONS]'
command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] || fail 'A running systemd host is required'
cd /

# These paths are persistent and work without curl, a release lookup, or a stage.
if [[ $action == uninstall && -f $installed_root/deploy/uninstall.sh && ! -L $installed_root/deploy/uninstall.sh ]]; then
  exec bash "$installed_root/deploy/uninstall.sh" "${uninstall_flags[@]}"
fi
if [[ $action == status ]]; then
  if [[ -f $installed_root/deploy/lifecycle.py && ! -L $installed_root/deploy/lifecycle.py ]]; then
    exec python3 -I "$installed_root/deploy/lifecycle.py" status
  fi
  exec systemctl --no-pager status xray-relay-panel.service
fi

case $(uname -m) in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) fail 'Supported host architectures: amd64 and arm64' ;;
esac
if [[ -n $local_package ]]; then
  [[ $version_given == true && $version != latest ]] || fail '--local-package requires --version TAG for offline installation'
fi

have_ca() {
  local bundle
  for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/cert.pem; do
    [[ ! -s $bundle ]] || return 0
  done
  return 1
}
ensure_dependencies() {
  local missing=() command
  command -v python3 >/dev/null 2>&1 || missing+=(python3)
  if [[ $action == install || $action == upgrade ]]; then
    if ! command -v sudo >/dev/null 2>&1 || ! command -v visudo >/dev/null 2>&1; then missing+=(sudo); fi
  fi
  if [[ -z $local_package ]]; then
    command -v curl >/dev/null 2>&1 || missing+=(curl)
    have_ca || missing+=(ca-certificates)
  fi
  [[ ${#missing[@]} -gt 0 ]] || return 0
  [[ -z $local_package ]] || fail "Offline mode requires these dependencies to be preinstalled: ${missing[*]}"
  printf 'Installing missing runtime dependencies: %s\n' "${missing[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${missing[@]}"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${missing[@]}"
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install --no-recommends "${missing[@]}"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --needed --noconfirm "${missing[@]}"
  else
    fail "Install the missing runtime dependencies manually: ${missing[*]}"
  fi
  command -v python3 >/dev/null 2>&1 || fail 'Python 3 is still unavailable'
  if [[ $action == install || $action == upgrade ]]; then
    command -v sudo >/dev/null 2>&1 && command -v visudo >/dev/null 2>&1 || fail 'sudo/visudo is still unavailable'
  fi
  command -v curl >/dev/null 2>&1 && have_ca || fail 'curl and CA certificates are required for HTTPS downloads'
}
ensure_dependencies

cleanup() {
  if [[ -n $stage ]]; then rm -rf -- "$stage"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage=$(mktemp -d /tmp/xray-relay-panel.XXXXXXXXXX)
chmod 0700 "$stage"

download_https() {
  local url=$1 output=$2 limit=$3 seconds=$4
  [[ $url == https://* ]] || fail 'Only HTTPS downloads are allowed'
  # RLIMIT_FSIZE also bounds downloads on older curl versions that only check
  # Content-Length for --max-filesize. Outputs are always in our private stage.
  (
    ulimit -c 0
    ulimit -f "$(( (limit + 1023) / 1024 ))"
    exec curl --disable --fail --silent --show-error --location \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --connect-timeout 15 --max-time "$seconds" --max-filesize "$limit" \
      --user-agent xray-relay-panel-bootstrap --output "$output" "$url"
  ) || fail "HTTPS download failed: $url"
}

if [[ -n $local_package ]]; then
  package=$local_package
else
  if [[ $version == latest ]]; then
    download_https "https://api.github.com/repos/$repository/releases/latest" "$stage/release.json" 2097152 30
    version=$(python3 -I - "$stage/release.json" <<'PY'
import json
import re
import sys
from pathlib import Path
try:
    path = Path(sys.argv[1])
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('release metadata exceeds the size limit')
    release = json.loads(path.read_text(encoding='utf-8'))
    tag = release.get('tag_name')
    if release.get('draft') is not False or release.get('prerelease') is not False:
        raise ValueError('latest must be a published stable release')
    if not isinstance(tag, str) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise ValueError('invalid stable release tag')
    print(tag)
except (OSError, ValueError, TypeError, AttributeError) as error:
    print('Release lookup failed: ' + str(error), file=sys.stderr)
    sys.exit(1)
PY
    ) || fail 'Could not resolve the latest stable release to a fixed tag'
  fi
  valid_tag "$version" || fail 'Invalid resolved release tag'
  asset="xray-relay-panel-linux-$arch.tar.gz"
  base="https://github.com/$repository/releases/download/$version"
  package="$stage/$asset"
  printf 'Downloading %s (%s)\n' "$version" "$arch"
  download_https "$base/$asset" "$package" 268435456 180
  download_https "$base/$asset.sha256" "$package.sha256" 1024 30
fi
validate_package "$package" "$stage"
root="$stage/unpacked/xray-relay-panel-linux-$arch"
case $action in
  install|upgrade) bash "$root/deploy/install.sh" "$root/bin" --version "$version" ;;
  uninstall) bash "$root/deploy/uninstall.sh" "${uninstall_flags[@]}" ;;
esac
