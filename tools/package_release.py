"""Package static Linux binaries and public installation files deterministically."""
import argparse
import gzip
import importlib.util
from pathlib import Path
import tarfile

root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('_distribution', root / 'tools/distribution.py')
distribution = importlib.util.module_from_spec(spec)
spec.loader.exec_module(distribution)
parser = argparse.ArgumentParser()
parser.add_argument('--arch', default='amd64', choices=['amd64', 'arm64'])
args = parser.parse_args()
name = 'xray-relay-panel-linux-' + args.arch
binaries = root / 'dist' / ('linux-' + args.arch)
entries = [(distribution.regular(binaries / binary), 'bin/' + binary) for binary in ('xray-panel', 'xray-panel-nodectl')]
entries.extend((path, path.relative_to(root).as_posix()) for path in distribution.release_documents(root))
output = root / 'dist' / (name + '.tar.gz')
output.parent.mkdir(parents=True, exist_ok=True)
with output.open('wb') as target:
    with gzip.GzipFile(filename='', mode='wb', fileobj=target, mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.GNU_FORMAT) as bundle:
            for path, relative in sorted(entries, key=lambda item: item[1]):
                info = tarfile.TarInfo(name + '/' + relative)
                info.size = path.stat().st_size
                info.mode = distribution.mode(relative)
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = 'root'
                with path.open('rb') as stream:
                    bundle.addfile(info, stream)
distribution.checksum(output)
print(output)
print('SHA256 ' + distribution.digest(output))
