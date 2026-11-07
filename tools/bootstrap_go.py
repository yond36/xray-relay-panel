"""Install a verified official Go toolchain into isolated development directories."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import urllib.request
import zipfile

root = Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
with urllib.request.urlopen('https://go.dev/dl/?mode=json', timeout=30) as response:
    releases = json.load(response)
release = next(item for item in releases if item.get('stable'))
asset = next(item for item in release['files'] if item['os'] == 'windows' and item['arch'] == 'amd64' and item['kind'] == 'archive')
download_dir = Path(tempfile.mkdtemp(prefix='download-', dir=root))
archive = download_dir / asset['filename']
with urllib.request.urlopen('https://go.dev/dl/' + asset['filename'], timeout=90) as response, archive.open('wb') as target:
    while chunk := response.read(1024 * 1024):
        target.write(chunk)
if hashlib.sha256(archive.read_bytes()).hexdigest() != asset['sha256']:
    raise SystemExit('Go archive checksum mismatch')
extract_dir = Path(tempfile.mkdtemp(prefix='toolchain-', dir=root))
with zipfile.ZipFile(archive) as bundle:
    for info in bundle.infolist():
        path = PurePosixPath(info.filename)
        if path.is_absolute() or '..' in path.parts or ':' in info.filename:
            raise SystemExit('Unsafe archive entry')
    bundle.extractall(extract_dir)
result = {'version': release['version'], 'sha256': asset['sha256'], 'bin': str(extract_dir / 'go' / 'bin'), 'exe': str(extract_dir / 'go' / 'bin' / 'go.exe')}
(root / 'go-toolchain.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result, indent=2), flush=True)
