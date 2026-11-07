"""Shared allowlist and deterministic metadata for public project distributions."""
from pathlib import Path
import hashlib
import re

ROOT_FILES = ('.env.example', '.gitattributes', '.gitignore', 'LICENSE', 'README.md',
              'THIRD_PARTY_NOTICES.md', 'go.mod', 'go.sum', 'install.sh')
SOURCE_ROOTS = ('.github', 'cmd', 'internal', 'ui', 'deploy', 'docs', 'tests', 'licenses')
PUBLIC_TOOLS = ('bootstrap_go.py', 'build.py', 'check_release.py', 'distribution.py',
                'fetch_xray.py', 'installer_smoke.py', 'package_release.py',
                'package_source.py', 'verify_artifacts.py', 'verify_multiuser.py')
EXCLUDED_NAMES = {'__pycache__', 'node_modules', '.git', '.local', '.tools', '.zcode'}
EXCLUDED_FILES = {'docs/installer-contract.md'}


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Distribution entry must be a regular file: ' + str(path))
    return path


def allowed(root, path):
    relative = path.relative_to(root)
    return not (EXCLUDED_NAMES.intersection(relative.parts) or
                relative.as_posix() in EXCLUDED_FILES or
                path.name.endswith(('.pyc', '.tsbuildinfo', '.secret', '.db', '.db-wal', '.db-shm')))


def source_files(root):
    root = Path(root)
    result = [regular(root / name) for name in ROOT_FILES]
    for name in SOURCE_ROOTS:
        folder = root / name
        if not folder.is_dir():
            raise ValueError('Required source directory is missing: ' + name)
        for path in folder.rglob('*'):
            if path.is_file() and allowed(root, path):
                result.append(regular(path))
    result.extend(regular(path) for path in (root / 'web/src').rglob('*') if path.is_file() and allowed(root, path))
    result.extend(regular(path) for path in (root / 'web').iterdir() if path.is_file() and path.suffix in ('.json', '.ts', '.html'))
    result.extend(regular(root / 'tools' / name) for name in PUBLIC_TOOLS)
    return sorted(set(result), key=lambda path: path.relative_to(root).as_posix())


def release_documents(root):
    root = Path(root)
    result = [regular(root / name) for name in ('install.sh', 'LICENSE', 'README.md', 'THIRD_PARTY_NOTICES.md')]
    for folder in ('deploy', 'docs', 'licenses'):
        result.extend(regular(path) for path in (root / folder).rglob('*') if path.is_file() and allowed(root, path))
    return sorted(set(result), key=lambda path: path.relative_to(root).as_posix())


def mode(name):
    return 0o755 if name.endswith('.sh') or '/bin/' in '/' + name else 0o644


def version(root):
    text = (Path(root) / 'internal/model/model.go').read_text(encoding='utf-8')
    found = re.search(r'^const Version = "([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)"$', text, re.M)
    if not found:
        raise ValueError('Cannot identify the backend release version')
    return found[1]


def checksum(path):
    path = Path(path)
    output = path.with_name(path.name + '.sha256')
    output.write_text(digest(path) + '  ' + path.name + '\n', encoding='utf-8')
    return output
