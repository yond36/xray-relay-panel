"""Build embedded web assets and static panel/node binaries from trusted project source."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument('--os', default='')
parser.add_argument('--arch', default='amd64')
parser.add_argument('--skip-web', action='store_true')
args = parser.parse_args()
go = os.environ.get('GO_BIN') or shutil.which('go')
if not go and (root / '.tools/go-toolchain.json').exists():
    go = json.loads((root / '.tools/go-toolchain.json').read_text())['exe']
if not go:
    raise SystemExit('Go 1.24+ is required; install Go or run tools/bootstrap_go.py .tools')
if not args.skip_web:
    npm = shutil.which('npm.cmd') or shutil.which('npm')
    if not npm:
        raise SystemExit('Node.js/npm is required to build the frontend')
    subprocess.run([npm, 'run', 'build'], cwd=root / 'web', check=True)
if (root / 'web/dist').is_dir():
    target = root / 'ui/dist'
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(root / 'web/dist', target)
env = os.environ.copy()
env['CGO_ENABLED'] = '0'
if args.os:
    env['GOOS'] = args.os
    env['GOARCH'] = args.arch
platform = args.os or ('windows' if os.name == 'nt' else 'linux')
suffix = '.exe' if platform == 'windows' else ''
out = root / 'dist' / (platform + '-' + args.arch)
out.mkdir(parents=True, exist_ok=True)
for command in ['panel', 'nodectl']:
    output = out / (('xray-panel' if command == 'panel' else 'xray-panel-nodectl') + suffix)
    subprocess.run([go, 'build', '-trimpath', '-ldflags=-s -w', '-o', str(output), './cmd/' + command], cwd=root, env=env, check=True)
    print('Built', output, flush=True)
