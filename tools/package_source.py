"""Package only the reviewed public source allowlist, with reproducible ZIP metadata."""
import importlib.util
from pathlib import Path
import stat
import zipfile

root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('_distribution', root / 'tools/distribution.py')
distribution = importlib.util.module_from_spec(spec)
spec.loader.exec_module(distribution)
output = root / 'dist/xray-relay-panel-source.zip'
output.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
    for path in distribution.source_files(root):
        relative = path.relative_to(root).as_posix()
        info = zipfile.ZipInfo('xray-relay-panel-source/' + relative, date_time=(1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (stat.S_IFREG | distribution.mode(relative)) << 16
        bundle.writestr(info, path.read_bytes(), compresslevel=9)
distribution.checksum(output)
print(output)
print('SHA256 ' + distribution.digest(output))
