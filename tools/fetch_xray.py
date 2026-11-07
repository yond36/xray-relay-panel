"""Download and verify an official fixed Xray release asset into fresh directories."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tempfile
import urllib.request
import zipfile

parser=argparse.ArgumentParser()
parser.add_argument('--version',default='v26.10.31')
parser.add_argument('--platform',default='windows-amd64',choices=['windows-amd64','linux-amd64','linux-arm64'])
parser.add_argument('--root',default='.tools/xray')
args=parser.parse_args()
assets={'windows-amd64':'Xray-windows-64.zip','linux-amd64':'Xray-linux-64.zip','linux-arm64':'Xray-linux-arm64-v8a.zip'}
req=urllib.request.Request('https://api.github.com/repos/XTLS/Xray-core/releases/tags/'+args.version,headers={'User-Agent':'xray-relay-panel-build'})
with urllib.request.urlopen(req,timeout=30) as response: release=json.load(response)
asset=next(item for item in release['assets'] if item['name']==assets[args.platform])
root=Path(args.root).resolve(); root.mkdir(parents=True,exist_ok=True)
download_dir=Path(tempfile.mkdtemp(prefix='download-',dir=root))
archive=download_dir/asset['name']
with urllib.request.urlopen(asset['browser_download_url'],timeout=120) as response,archive.open('wb') as target:
    while chunk:=response.read(1024*1024): target.write(chunk)
digest=asset.get('digest') or ''
if digest.startswith('sha256:'): expected=digest[7:]
else:
    checksum_asset=next(item for item in release['assets'] if item['name']==asset['name']+'.dgst')
    with urllib.request.urlopen(checksum_asset['browser_download_url'],timeout=30) as response: checksums=response.read().decode()
    matches=re.findall(r'(?i)\b[0-9a-f]{64}\b',checksums)
    if not matches: raise SystemExit('No official SHA256 checksum found')
    expected=matches[0].lower()
actual=hashlib.sha256(archive.read_bytes()).hexdigest()
if actual!=expected: raise SystemExit('Xray archive SHA256 mismatch')
extracted=Path(tempfile.mkdtemp(prefix='extracted-',dir=root))
with zipfile.ZipFile(archive) as bundle:
    for item in bundle.infolist():
        name=PurePosixPath(item.filename)
        if name.is_absolute() or '..' in name.parts or ':' in item.filename: raise SystemExit('Unsafe Xray archive entry')
    bundle.extractall(extracted)
result={'version':args.version,'platform':args.platform,'sha256':actual,'exe':str(extracted/('xray.exe' if args.platform.startswith('windows') else 'xray'))}
(root/('current-'+args.platform+'.json')).write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2),flush=True)
