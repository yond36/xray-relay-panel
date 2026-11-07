"""Verify archive contents, executable modes and checksums; prepare GitHub release assets."""
import argparse
import importlib.util
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import zipfile
import json

root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('_distribution', root / 'tools/distribution.py')
distribution = importlib.util.module_from_spec(spec)
spec.loader.exec_module(distribution)
parser = argparse.ArgumentParser()
parser.add_argument('--prepare-assets', action='store_true', help='Copy the one-key script and generate SHA256SUMS')
args = parser.parse_args()
dist = root / 'dist'
if args.prepare_assets:
    dist.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / 'install.sh', dist / 'install.sh')
    distribution.checksum(dist / 'install.sh')


def member_name(name, prefix):
    path = PurePosixPath(name)
    if (path.is_absolute() or '..' in path.parts or '\\' in name or
            any(ord(char) < 32 for char in name) or not name.startswith(prefix + '/')):
        raise ValueError('Unsafe archive path')
    if distribution.EXCLUDED_NAMES.intersection(path.parts) or name.endswith(('.secret', '.db', '.db-wal', '.db-shm', '.pyc', '.tsbuildinfo')):
        raise ValueError('Private or generated runtime file in archive')
    return name[len(prefix) + 1:]


def check_digest(path):
    text = path.with_name(path.name + '.sha256').read_text(encoding='utf-8').rstrip('\n')
    expected = distribution.digest(path) + '  ' + path.name
    if text != expected:
        raise ValueError('Checksum does not match ' + path.name)
    return expected


results = []
asset_paths = []
for arch, machine in (('amd64', 62), ('arm64', 183)):
    prefix = 'xray-relay-panel-linux-' + arch
    path = dist / (prefix + '.tar.gz')
    check_digest(path)
    expected = {p.relative_to(root).as_posix() for p in distribution.release_documents(root)} | {'bin/xray-panel', 'bin/xray-panel-nodectl'}
    found = set()
    total = 0
    with tarfile.open(path, 'r:gz') as archive:
        for entry in archive:
            relative = member_name(entry.name, prefix)
            if not entry.isfile() or relative in found:
                raise ValueError('Unexpected or duplicate archive entry')
            found.add(relative)
            total += entry.size
            if total > 128 * 1024 * 1024 or len(found) > 2000:
                raise ValueError('Archive is too large')
            if entry.mode != distribution.mode(relative):
                raise ValueError('Unexpected file permissions in archive')
            data = archive.extractfile(entry).read()
            if relative.startswith('bin/'):
                if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != machine:
                    raise ValueError('Binary architecture mismatch')
                if distribution.digest(root / 'dist' / ('linux-' + arch) / relative[len('bin/'):]) != __import__('hashlib').sha256(data).hexdigest():
                    raise ValueError('Packaged binary differs from build')
    if found != expected:
        raise ValueError('Unexpected or missing release files')
    results.append({'archive': path.name, 'files': len(found), 'sha256': distribution.digest(path)})
    asset_paths.append(path)
prefix = 'xray-relay-panel-source'
path = dist / (prefix + '.zip')
check_digest(path)
expected = {p.relative_to(root).as_posix() for p in distribution.source_files(root)}
found = set()
with zipfile.ZipFile(path) as archive:
    if archive.testzip() is not None:
        raise ValueError('ZIP integrity check failed')
    for entry in archive.infolist():
        relative = member_name(entry.filename, prefix)
        if relative in found or stat.S_IFMT(entry.external_attr >> 16) != stat.S_IFREG:
            raise ValueError('Unexpected ZIP file type')
        found.add(relative)
if found != expected:
    raise ValueError('Source archive does not match the public allowlist')
results.append({'archive': path.name, 'files': len(found), 'sha256': distribution.digest(path)})
asset_paths.append(path)
if args.prepare_assets:
    if (dist / 'install.sh').read_bytes() != (root / 'install.sh').read_bytes():
        raise ValueError('Release installer differs from reviewed source')
    asset_paths.append(dist / 'install.sh')
    lines = [check_digest(asset) for asset in sorted(asset_paths)]
    (dist / 'SHA256SUMS').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps({'status': 'passed', 'archives': results}, indent=2))
