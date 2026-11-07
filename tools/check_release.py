"""Check release versions and emit the exact public-source manifest before Git staging."""
import argparse
import importlib.util
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('_distribution', root / 'tools/distribution.py')
distribution = importlib.util.module_from_spec(spec)
spec.loader.exec_module(distribution)
parser = argparse.ArgumentParser()
parser.add_argument('--tag', help='GitHub release tag, such as v0.2.2')
parser.add_argument('--manifest', type=Path, help='Write reviewed public paths, one per line')
args = parser.parse_args()
version = distribution.version(root)
if args.tag is not None and args.tag != 'v' + version:
    raise SystemExit('Release tag must match internal/model/model.go: v' + version)
package = json.loads((root / 'web/package.json').read_text(encoding='utf-8'))
lock = json.loads((root / 'web/package-lock.json').read_text(encoding='utf-8'))
if any(value != version for value in (package['version'], lock['version'], lock['packages']['']['version'])):
    raise SystemExit('Frontend package/lock versions do not match the backend')
if not (root / 'README.md').read_text(encoding='utf-8').splitlines()[0].endswith('v' + version):
    raise SystemExit('README release version does not match the backend')
files = distribution.source_files(root)
for path in files:
    relative = path.relative_to(root).as_posix()
    if '\n' in relative or '\r' in relative or not distribution.allowed(root, path):
        raise SystemExit('Invalid public source path')
    if path.suffix in ('.sh', '.yml', '.yaml') and b'\r\n' in path.read_bytes():
        raise SystemExit('Shell/workflow files must use LF: ' + relative)
    if relative.startswith('docs/verification'):
        text = path.read_text(encoding='utf-8')
        if re.search(r'PID\s*[`:]?\s*[1-9][0-9]{3,}|public-ip-|v0\.2.*upgrade-state\.secret|xrelay-private-', text, re.I):
            raise SystemExit('Machine-specific verification data remains in ' + relative)
if args.manifest:
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(''.join(path.relative_to(root).as_posix() + '\n' for path in files), encoding='utf-8')
print(json.dumps({'status': 'passed', 'tag': 'v' + version, 'public_files': len(files)}, indent=2))
