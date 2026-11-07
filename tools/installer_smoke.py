"""Real systemd lifecycle acceptance, ONLY on an empty GitHub-hosted disposable VM."""
import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
PANEL = Path('/opt/xray-relay-panel')
DATA = Path('/var/lib/xray-relay-panel')
CONFIG = Path('/etc/xray-relay-panel')
NODE = Path('/opt/xray-relay-panel-node')
NODE_DATA = Path('/var/lib/xray-relay-panel-node')
WEB_UNIT = 'xray-relay-panel.service'
NODE_UNIT = 'xray-relay-panel-node.service'
UNRELATED_UNIT = 'x-ui.service'
SYSTEMD = Path('/etc/systemd/system')


def command(argv, check=True, timeout=120, **kwargs):
    return subprocess.run([str(value) for value in argv], cwd=ROOT, check=check,
                          timeout=timeout, **kwargs)


def ctl(action, unit, check=True):
    assert unit in (WEB_UNIT, NODE_UNIT, UNRELATED_UNIT)
    return command(['systemctl', action, '--', unit], check=check,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def pid(unit):
    result = command(['systemctl', 'show', '--property=MainPID', '--value', unit],
                     stdout=subprocess.PIPE, text=True)
    return int(result.stdout.strip())


def wait_active(unit):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if ctl('is-active', unit, check=False).returncode == 0 and pid(unit):
            return pid(unit)
        time.sleep(0.2)
    raise AssertionError('Fixture unit did not become active: ' + unit)


def file_hash(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def create_file(path, value, mode=0o600):
    assert not path.exists() and not path.is_symlink(), 'Fixture destination exists'
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(value, encoding='utf-8')
    path.chmod(mode)


def build_fixture(directory, output, source):
    path = directory / (output.name + '.go')
    path.write_text(source, encoding='utf-8')
    env = os.environ.copy()
    env.update({'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': 'amd64'})
    command(['go', 'build', '-o', output, path], env=env)


def node_fixture(directory):
    NODE.mkdir(mode=0o700)
    (NODE / 'revisions').mkdir(mode=0o700)
    NODE_DATA.mkdir(mode=0o700)
    revision = 'a' * 24
    target = NODE / 'revisions' / revision
    target.mkdir(mode=0o700)
    binary = directory / 'fake-core'
    build_fixture(directory, binary, '''package main
import("fmt";"os";"os/signal";"syscall")
func main(){if len(os.Args)>1&&os.Args[1]=="version"{fmt.Println("Xray 26.10.31");return};c:=make(chan os.Signal,1);signal.Notify(c,syscall.SIGTERM,syscall.SIGINT);<-c}
''')
    shutil.copyfile(binary, target / 'xray')
    (target / 'xray').chmod(0o755)
    create_file(target / 'config.json', '{"outbounds":[{"protocol":"blackhole"}]}\n')
    create_file(target / 'metadata.json', json.dumps({'revision': revision, 'core_version': 'v26.10.31', 'architecture': 'amd64', 'created_at': '2026-01-01T00:00:00Z'}))
    create_file(NODE_DATA / 'operation.lock', '')
    (NODE / 'current').symlink_to('revisions/' + revision)
    source = (ROOT / 'internal/engine/node.go').read_text(encoding='utf-8')
    marker = re.search(r'const unitMarker = "([^"]+)"', source).group(1)
    body = re.search(r'const serviceUnit = unitMarker \+ `(.*?)`', source, re.S).group(1)
    create_file(SYSTEMD / NODE_UNIT, marker + body, 0o644)
    command(['systemctl', 'daemon-reload'])
    ctl('enable', NODE_UNIT)
    ctl('start', NODE_UNIT)
    return wait_active(NODE_UNIT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    args = parser.parse_args()
    if (platform.system() != 'Linux' or getattr(os, 'geteuid', lambda: -1)() != 0 or
            os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise SystemExit('Refusing: smoke requires root on a disposable GitHub-hosted Linux VM')
    for path in (PANEL, DATA, CONFIG, NODE, NODE_DATA,
                 SYSTEMD / WEB_UNIT, SYSTEMD / NODE_UNIT, SYSTEMD / UNRELATED_UNIT,
                 Path('/usr/local/bin/xray-relay-panel'), Path('/etc/sudoers.d/xray-relay-panel')):
        if path.exists() or path.is_symlink():
            raise SystemExit('Refusing to touch an existing installation or fixture: ' + str(path))
    for unit in (WEB_UNIT, NODE_UNIT, UNRELATED_UNIT):
        state = command(['systemctl', 'show', '--property=LoadState', '--value', unit],
                        check=False, stdout=subprocess.PIPE, text=True).stdout.strip()
        if state != 'not-found':
            raise SystemExit('Refusing to use an already registered unit: ' + unit)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 8080))
    artifacts = args.artifacts.resolve()
    package = args.package.resolve()
    version = re.search(r'^const Version = "([^"]+)"', (ROOT / 'internal/model/model.go').read_text(), re.M).group(1)
    tag = 'v' + version
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    origin = 'http://127.0.0.1:8080'

    def api(method, path, body=None):
        req = urllib.request.Request(origin + path, data=json.dumps(body).encode() if body is not None else None,
                                     method=method, headers={'Origin': origin, 'Content-Type': 'application/json'})
        with client.open(req, timeout=5) as response:
            return json.load(response)

    def ready():
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if api('GET', '/healthz')['status'] == 'ok':
                    return
            except (OSError, ValueError, urllib.error.URLError):
                pass
            time.sleep(0.2)
        raise AssertionError('Panel did not become healthy')

    stages = []
    unrelated_created = False
    node_created = False
    try:
        with tempfile.TemporaryDirectory(prefix='xray-panel-ci-') as temporary:
            directory = Path(temporary)
            unrelated_config = directory / 'unrelated-config.json'
            create_file(unrelated_config, '{"unrelated":true}\n')
            create_file(SYSTEMD / UNRELATED_UNIT, '[Unit]\nDescription=Unrelated CI service\n[Service]\nExecStart=/usr/bin/sleep infinity\n', 0o644)
            unrelated_created = True
            command(['systemctl', 'daemon-reload'])
            ctl('start', UNRELATED_UNIT)
            unrelated_pid = wait_active(UNRELATED_UNIT)
            unrelated_hash = file_hash(unrelated_config)

            def protected():
                assert pid(UNRELATED_UNIT) == unrelated_pid and ctl('is-active', UNRELATED_UNIT).returncode == 0, 'Unrelated service changed'
                assert file_hash(unrelated_config) == unrelated_hash, 'Unrelated configuration changed'
                if node_created:
                    assert pid(NODE_UNIT) == node_pid and ctl('is-active', NODE_UNIT).returncode == 0, 'Retained node was restarted or stopped'

            command(['bash', ROOT / 'install.sh', 'install', '--local-package', package, '--version', tag])
            ready()
            protected()
            stages.append('offline bootstrap install and health')
            api('POST', '/api/auth/setup', {'username': 'installer_ci', 'password': secrets.token_urlsafe(24)})
            expected_user = api('GET', '/api/state')['current_user']
            settings = api('GET', '/api/settings')
            master_hash = file_hash(DATA / 'master.key')
            node_pid = node_fixture(directory)
            node_created = True
            binary_hash = file_hash(PANEL / 'xray-panel')
            command(['bash', ROOT / 'deploy/install.sh', artifacts, '--version', tag])
            ready()
            assert api('GET', '/api/state')['current_user'] == expected_user
            assert api('GET', '/api/settings') == settings and file_hash(DATA / 'master.key') == master_hash
            protected()
            stages.append('repeat installation preserves session, settings, key and node')
            bad = directory / 'bad-binaries'
            bad.mkdir()
            shutil.copyfile(artifacts / 'xray-panel-nodectl', bad / 'xray-panel-nodectl')
            (bad / 'xray-panel-nodectl').chmod(0o755)
            build_fixture(directory, bad / 'xray-panel', 'package main\nimport("fmt";"os")\nfunc main(){if len(os.Args)>1&&os.Args[1]=="--version"{fmt.Println("Xray Relay Panel ' + version + '");return};os.Exit(1)}\n')
            failed = command(['bash', ROOT / 'deploy/install.sh', bad, '--version', tag], check=False, timeout=180)
            assert failed.returncode != 0, 'Broken candidate unexpectedly installed'
            ready()
            assert file_hash(PANEL / 'xray-panel') == binary_hash
            assert file_hash(DATA / 'master.key') == master_hash and api('GET', '/api/state')['current_user'] == expected_user
            protected()
            stages.append('failed startup restores binary, database, key and old session')
            command(['/usr/local/bin/xray-relay-panel', 'status'])
            command(['/usr/local/bin/xray-relay-panel', 'uninstall'])
            assert not PANEL.exists() and DATA.is_dir() and CONFIG.is_dir()
            assert file_hash(DATA / 'master.key') == master_hash
            assert not (SYSTEMD / WEB_UNIT).exists()
            protected()
            stages.append('default uninstall retains private data and running node')
            command(['bash', ROOT / 'install.sh', 'install', '--local-package', package, '--version', tag])
            ready()
            assert api('GET', '/api/state')['current_user'] == expected_user
            assert api('GET', '/api/settings') == settings
            protected()
            stages.append('reinstall reuses retained data and old cookie')
            command(['/usr/local/bin/xray-relay-panel', 'uninstall', '--purge', '--remove-local-node', '--yes'])
            assert all(not path.exists() for path in (PANEL, DATA, CONFIG, NODE, NODE_DATA, SYSTEMD / WEB_UNIT, SYSTEMD / NODE_UNIT))
            assert pid(UNRELATED_UNIT) == unrelated_pid and file_hash(unrelated_config) == unrelated_hash
            stages.append('explicit owned-data and local-node removal; unrelated service retained')
    finally:
        if node_created:
            ctl('stop', NODE_UNIT, check=False)
        ctl('stop', WEB_UNIT, check=False)
        if unrelated_created:
            ctl('stop', UNRELATED_UNIT, check=False)
    print(json.dumps({'status': 'passed', 'environment': 'disposable GitHub-hosted Linux/systemd', 'checks': stages}, indent=2))


if __name__ == '__main__':
    main()
