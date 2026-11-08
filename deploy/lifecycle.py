#!/usr/bin/env python3
"""Owned, offline filesystem lifecycle for the Linux/systemd release package.

Layout, Host and Filesystem are internal injection seams for temporary-directory
unit tests. The command line deliberately exposes no alternate system root or
ownership/health bypass. Backups are retained outside the installation.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

PRODUCT = "xray-relay-panel"
WEB = PRODUCT + ".service"
NODE = PRODUCT + "-node.service"
MARKER = ".managed-by-xray-relay-panel"
MANIFEST = ".installation.json"
PROGRAM_FILES = (
    "xray-panel", "xray-panel-nodectl", "manage.sh", "deploy/lifecycle.py",
    "deploy/install.sh", "deploy/uninstall.sh", "deploy/xray-relay-panel.service",
)
WEB_UNIT = """# Managed by xray-relay-panel installer.
[Unit]
Description=Xray Relay Panel
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=xray-panel
Group=xray-panel
Environment=XRAY_PANEL_BIND=127.0.0.1:8080
Environment=XRAY_PANEL_DATA=/var/lib/xray-relay-panel
Environment=XRAY_PANEL_NODECTL=/opt/xray-relay-panel/xray-panel-nodectl
EnvironmentFile=-/etc/xray-relay-panel/panel.env
ExecStart=/opt/xray-relay-panel/xray-panel
WorkingDirectory=/var/lib/xray-relay-panel
Restart=on-failure
RestartSec=3
TimeoutStopSec=30
UMask=0077
PrivateTmp=true
ProtectHome=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
NODE_UNIT = """# Managed by xray-relay-panel; isolated node service.
[Unit]
Description=Isolated Xray Relay Panel Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/xray-relay-panel-node/current/xray run -config /opt/xray-relay-panel-node/current/config.json
WorkingDirectory=/var/lib/xray-relay-panel-node
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/xray-relay-panel-node

[Install]
WantedBy=multi-user.target
"""
SUDOERS = "xray-panel ALL=(root) NOPASSWD: /opt/xray-relay-panel/xray-panel-nodectl helper\n"


class LifecycleError(RuntimeError):
    pass


def normalized(text):
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


@dataclass(frozen=True)
class Layout:
    root: Path = Path("/opt/xray-relay-panel")
    data: Path = Path("/var/lib/xray-relay-panel")
    config: Path = Path("/etc/xray-relay-panel")
    unit: Path = Path("/etc/systemd/system/xray-relay-panel.service")
    sudoers: Path = Path("/etc/sudoers.d/xray-relay-panel")
    command: Path = Path("/usr/local/bin/xray-relay-panel")
    backups: Path = Path("/var/backups/xray-relay-panel")
    lock: Path = Path("/run/lock/xray-relay-panel-installer.lock")
    node_root: Path = Path("/opt/xray-relay-panel-node")
    node_data: Path = Path("/var/lib/xray-relay-panel-node")
    node_unit: Path = Path("/etc/systemd/system/xray-relay-panel-node.service")

    def resources(self):
        return {name: getattr(self, name) for name in ("root", "data", "config", "unit", "sudoers")}


@dataclass(frozen=True)
class Account:
    uid: int
    gid: int


class Filesystem:
    def __init__(self, root_uid=0):
        self.root_uid = root_uid

    def guard(self, path):
        """Reject symlinks in every existing parent, including dangling links."""
        if not path.is_absolute() or ".." in path.parts:
            raise LifecycleError("Expected an absolute, canonical path: " + str(path))
        for parent in reversed(path.parents):
            if parent.exists() or parent.is_symlink():
                mode = parent.lstat().st_mode
                if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
                    raise LifecycleError("Unsafe parent directory: " + str(parent))

    def check(self, path, owners, directory=False, hardlinks=False):
        self.guard(path)
        info = path.lstat()
        kind_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not kind_ok or info.st_uid not in owners:
            raise LifecycleError("Unexpected type or owner: " + str(path))
        if not directory and not hardlinks and info.st_nlink != 1:
            raise LifecycleError("Refusing a hard-linked file: " + str(path))
        if os.name != "nt" and info.st_mode & 0o022:
            raise LifecycleError("Group/other writable managed path: " + str(path))
        return info

    def exists(self, path):
        self.guard(path)
        return os.path.lexists(path)

    def tree(self, path, owners, links=None, hardlinks=False):
        links = links or {}
        self.check(path, owners, directory=True)
        for entry in path.iterdir():
            if entry in links:
                self.link(entry, links[entry])
            elif entry.is_symlink():
                raise LifecycleError("Refusing a symlink: " + str(entry))
            elif entry.is_dir():
                self.tree(entry, owners, links, hardlinks)
            else:
                self.check(entry, owners, hardlinks=hardlinks)

    def link(self, path, target):
        self.guard(path)
        info = path.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != self.root_uid or os.readlink(path) != str(target):
            raise LifecycleError("Refusing an unrelated management/revision link: " + str(path))

    def create_link(self, path, target):
        self.guard(path)
        path.symlink_to(target)

    def read_link(self, path):
        return os.readlink(path)

    def unlink_link(self, path, target):
        self.link(path, target)
        path.unlink()

    def chown(self, path, uid, gid):
        os.chown(path, uid, gid, follow_symlinks=False)

    def chmod(self, path, mode):
        path.chmod(mode)

    def mkdir(self, path, mode=0o755, owner=None):
        self.guard(path)
        if not self.exists(path):
            if not path.parent.exists():
                self.mkdir(path.parent)
            self.check(path.parent, {self.root_uid}, directory=True)
            path.mkdir(mode=mode)
            self.chown(path, *(owner or (self.root_uid, 0)))
            self.chmod(path, mode)

    def write(self, path, content, mode=0o644):
        self.guard(path)
        self.mkdir(path.parent)
        if self.exists(path):
            self.check(path, {self.root_uid})
        fd, name = tempfile.mkstemp(prefix=".panel-", dir=str(path.parent))
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            self.chown(temporary, self.root_uid, 0)
            self.chmod(temporary, mode)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def json(self, path, value):
        self.write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(), 0o600)

    def read_json(self, path):
        self.check(path, {self.root_uid})
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as error:
            raise LifecycleError("Invalid ownership metadata: " + str(path)) from error
        if not isinstance(value, dict):
            raise LifecycleError("Invalid ownership metadata: " + str(path))
        return value

    def copy(self, source, target):
        """Copy a prevalidated tree without following links; preserve uid/gid/mode."""
        self.guard(source)
        info = source.lstat()
        if stat.S_ISDIR(info.st_mode):
            target.mkdir(mode=0o700)
            for entry in source.iterdir():
                self.copy(entry, target / entry.name)
        elif stat.S_ISREG(info.st_mode):
            with source.open("rb") as src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
                dst.flush()
                os.fsync(dst.fileno())
        else:
            raise LifecycleError("Refusing to back up a link/special file: " + str(source))
        shutil.copystat(source, target, follow_symlinks=False)
        self.chown(target, info.st_uid, info.st_gid)

    def remove_tree(self, path, owners, links=None, hardlinks=False):
        """Validate the whole tree before deleting, and recheck each deletion."""
        links = links or {}
        self.tree(path, owners, links, hardlinks)
        for entry in list(path.iterdir()):
            if entry in links:
                self.link(entry, links[entry])
                entry.unlink()
            elif entry.is_dir() and not entry.is_symlink():
                self.remove_tree(entry, owners, links, hardlinks)
            else:
                self.check(entry, owners, hardlinks=hardlinks)
                entry.unlink()
        self.check(path, owners, directory=True)
        path.rmdir()


class Host:
    def run(self, *args, check=True):
        result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=60, cwd="/")
        if check and result.returncode:
            raise LifecycleError("Command failed: %s: %s" % (" ".join(map(str, args)), result.stderr.strip()))
        return result

    def require_system(self):
        if sys.platform != "linux":
            raise LifecycleError("Linux with systemd is required.")
        if os.geteuid() != 0:
            raise LifecycleError("Run as root, for example: sudo bash deploy/install.sh BIN_DIR")
        for command in ("systemctl", "sudo", "visudo", "useradd"):
            if not shutil.which(command):
                raise LifecycleError("Required command missing: " + command)
        if not Path("/run/systemd/system").is_dir():
            raise LifecycleError("A running systemd system manager is required.")

    def account(self, data, create=False):
        # These modules are intentionally lazy: importing/testing on Windows works.
        import grp
        import pwd
        try:
            entry = pwd.getpwnam("xray-panel")
        except KeyError:
            try:
                grp.getgrnam("xray-panel")
            except KeyError:
                pass
            else:
                raise LifecycleError("An unrelated xray-panel group already exists.")
            if not create:
                return None
            self.run("useradd", "--system", "--user-group", "--home-dir", str(data),
                     "--shell", "/usr/sbin/nologin", "xray-panel")
            entry = pwd.getpwnam("xray-panel")
        if (not 0 < entry.pw_uid < 1000 or entry.pw_dir != str(data)
                or entry.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")):
            raise LifecycleError("Refusing to use an unrelated xray-panel account.")
        try:
            group = grp.getgrnam("xray-panel")
        except KeyError as error:
            raise LifecycleError("The xray-panel primary group is missing.") from error
        if group.gr_gid != entry.pw_gid or group.gr_mem:
            raise LifecycleError("The xray-panel group is not a dedicated primary group.")
        return Account(entry.pw_uid, entry.pw_gid)

    @contextmanager
    def lock(self, path, fs):
        import fcntl
        fs.mkdir(path.parent)
        if fs.exists(path):
            fs.check(path, {fs.root_uid})
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_uid != fs.root_uid or os.fstat(fd).st_nlink != 1:
                raise LifecycleError("Unsafe lifecycle lock: " + str(path))
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise LifecycleError("Another panel lifecycle/node operation is in progress.") from error
            yield
        finally:
            os.close(fd)

    def control(self, action, unit=WEB, check=True, runtime=False):
        if unit not in (WEB, NODE):
            raise LifecycleError("Refusing to control another systemd unit.")
        args = ("--runtime",) if runtime else ()
        return self.run("systemctl", action, *args, "--", unit, check=check)

    def reload(self):
        self.run("systemctl", "daemon-reload")

    def check_unit(self, unit, path):
        fragment = self.run("systemctl", "show", "--property=FragmentPath", "--value", "--", unit,
                            check=False).stdout.strip()
        dropins = self.run("systemctl", "show", "--property=DropInPaths", "--value", "--", unit,
                           check=False).stdout.strip()
        if fragment and fragment != str(path):
            raise LifecycleError("Refusing a unit loaded from another path: " + fragment)
        if dropins:
            raise LifecycleError("Review/remove systemd drop-ins before lifecycle changes: " + dropins)

    def state(self, unit=WEB):
        active = self.control("is-active", unit, check=False).stdout.strip() == "active"
        enabled = self.control("is-enabled", unit, check=False).stdout.strip()
        if enabled not in ("enabled", "enabled-runtime", "disabled", "not-found", ""):
            raise LifecycleError("Unsupported systemd enable state: " + enabled)
        return active, enabled

    def versions(self, binaries):
        panel = self.run(str(binaries / "xray-panel"), "--version").stdout.strip()
        helper = self.run(str(binaries / "xray-panel-nodectl"), "version").stdout.strip()
        if not panel.startswith("Xray Relay Panel ") or panel[len("Xray Relay Panel "):] != helper:
            raise LifecycleError("Panel/helper binary versions do not match.")
        return helper


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def health_url(env):
    bind = "127.0.0.1:8080"
    if env is not None:
        for line in env.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            key, separator, raw = line.partition("=")
            if key not in ("XRAY_PANEL_BIND", "XRAY_PANEL_DATA", "XRAY_PANEL_NODECTL"):
                continue
            try:
                values = shlex.split(raw, comments=False)
            except ValueError as error:
                raise LifecycleError("Unsupported environment assignment: " + key) from error
            if not separator or len(values) != 1:
                raise LifecycleError("Unsupported environment assignment: " + key)
            value = values[0]
            fixed = {"XRAY_PANEL_DATA": "/var/lib/xray-relay-panel",
                     "XRAY_PANEL_NODECTL": "/opt/xray-relay-panel/xray-panel-nodectl"}
            if key in fixed and value != fixed[key]:
                raise LifecycleError("Custom %s requires a manual backup/upgrade; no files were changed." % key)
            if key == "XRAY_PANEL_BIND":
                bind = value
    match = re.fullmatch(r"(\[[0-9a-fA-F:]+\]|[^:\s]*):([0-9]+)", bind)
    if not match or not 0 < int(match[2]) < 65536:
        raise LifecycleError("Unsupported XRAY_PANEL_BIND: " + bind)
    host = match[1].strip("[]")
    if host in ("", "0.0.0.0", "localhost"):
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    else:
        try:
            ipaddress.ip_address(host)
        except ValueError as error:
            raise LifecycleError("Health checks require a numeric bind address or localhost.") from error
    if ":" in host:
        host = "[" + host + "]"
    return "http://%s:%s/healthz" % (host, match[2])


def wait_healthy(host, url, version, timeout=30):
    # No authentication/bootstrap prerequisite, proxy environment or redirects.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with opener.open(url, timeout=1) as response:
                payload = json.loads(response.read(65537))
                if (response.status == 200 and isinstance(payload, dict)
                        and payload.get("status") == "ok" and payload.get("version") == version
                        and host.control("is-active", check=False).stdout.strip() == "active"):
                    return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.25)
    raise LifecycleError("Panel health check failed: " + url)


class Lifecycle:
    def __init__(self, layout=None, host=None, fs=None, health=None, output=print, confirm=None):
        self.p = layout or Layout()
        self.host = host or Host()
        self.fs = fs or Filesystem()
        self.health = health or wait_healthy
        self.output = output
        self.confirm = confirm or self._confirm
        self.root_owners = {self.fs.root_uid}

    @staticmethod
    def _confirm(message):
        if not sys.stdin.isatty():
            raise LifecycleError("Destructive options require a terminal confirmation or --yes.")
        if input(message + " Type 'yes' to continue: ").strip() != "yes":
            raise LifecycleError("Uninstall cancelled.")

    def _owners(self, account):
        return self.root_owners | ({account.uid} if account else set())

    def _marker(self, directory, role, identity):
        value = self.fs.read_json(directory / MARKER)
        if value != {"product": PRODUCT, "schema": 1, "id": identity, "role": role}:
            raise LifecycleError("Ownership marker does not match: " + str(directory))

    def _mark(self, directory, role, identity):
        self.fs.json(directory / MARKER, {"product": PRODUCT, "schema": 1, "id": identity, "role": role})

    def _unit(self, path, expected):
        self.fs.check(path, self.root_owners)
        if normalized(path.read_text(encoding="utf-8")) != normalized(expected):
            raise LifecycleError("Refusing an unrelated or customized service unit: " + str(path))

    def _program_tree(self, legacy=False):
        allowed = {"xray-panel", "xray-panel-nodectl", MARKER} if legacy else set(PROGRAM_FILES) | {MARKER, MANIFEST}
        self.fs.tree(self.p.root, self.root_owners)
        files = {str(path.relative_to(self.p.root)).replace(os.sep, "/")
                 for path in self.p.root.rglob("*") if path.is_file()}
        directories = {path for path in self.p.root.rglob("*") if path.is_dir()}
        if files != allowed or directories != (set() if legacy else {self.p.root / "deploy"}):
            raise LifecycleError("Installation contains missing/unrecognized files; manual review required: " + str(self.p.root))

    def _read_manifest(self, path):
        manifest = self.fs.read_json(path)
        files = manifest.get("files")
        if (manifest.get("product") != PRODUCT or manifest.get("schema") != 1
                or not re.fullmatch(r"[0-9a-f]{32}", str(manifest.get("id", "")))
                or type(manifest.get("installed")) is not bool
                or manifest.get("paths") != {key: str(value) for key, value in self.p.resources().items()}
                or not isinstance(files, dict) or set(files) != set(PROGRAM_FILES)
                or any(not re.fullmatch(r"[0-9a-f]{64}", str(value)) for value in files.values())):
            raise LifecycleError("Invalid installation manifest: " + str(path))
        return manifest

    def _inspect(self, account):
        """Prove ownership before any service control or filesystem mutation."""
        p, fs = self.p, self.fs
        for path in (*p.resources().values(), p.command):
            fs.guard(path)
        self.host.check_unit(WEB, p.unit)
        if fs.exists(p.command):
            fs.link(p.command, p.root / "manage.sh")
        root_exists = fs.exists(p.root)
        manifest = None
        legacy = False
        if root_exists:
            fs.check(p.root, self.root_owners, directory=True)
            if fs.exists(p.root / MANIFEST):
                manifest = self._read_manifest(p.root / MANIFEST)
                if not manifest["installed"]:
                    raise LifecycleError("Unexpected program tree in an uninstalled manifest.")
                self._marker(p.root, "program", manifest["id"])
                self._program_tree()
                for name, expected in manifest["files"].items():
                    if digest(p.root / name) != expected:
                        raise LifecycleError("Managed program file changed: " + str(p.root / name))
                if self._read_manifest(p.config / MANIFEST) != manifest:
                    raise LifecycleError("Program/config manifests disagree.")
            else:
                # The historical installer wrote exactly two binaries, an empty
                # root-owned marker, the fixed unit, env and fixed sudo rule.
                fs.check(p.root / MARKER, self.root_owners)
                if (p.root / MARKER).read_bytes() != b"":
                    raise LifecycleError("Unrecognized legacy ownership marker.")
                self._program_tree(legacy=True)
                legacy = True
            if not fs.exists(p.unit) or not fs.exists(p.sudoers):
                raise LifecycleError("An owned program tree requires its unit and sudoers rule.")
        elif fs.exists(p.config):
            manifest = self._read_manifest(p.config / MANIFEST)
            if manifest["installed"]:
                raise LifecycleError("Program directory is missing from an installed manifest.")
        if manifest or legacy:
            if account is None:
                raise LifecycleError("Owned persistent data requires the existing xray-panel account.")
            if manifest and manifest.get("account") != {"uid": account.uid, "gid": account.gid}:
                raise LifecycleError("Panel account identity changed; refusing to reassign data.")
            for role, directory in (("data", p.data), ("config", p.config)):
                owners = self._owners(account) if role == "data" else self.root_owners
                fs.tree(directory, owners)
                expected_uid = account.uid if role == "data" else fs.root_uid
                if directory.lstat().st_uid != expected_uid:
                    raise LifecycleError("Unexpected directory owner: " + str(directory))
                if manifest:
                    self._marker(directory, role, manifest["id"])
            if legacy:
                if {path.name for path in p.config.iterdir()} != {"panel.env"}:
                    raise LifecycleError("Legacy configuration directory has unrecognized contents.")
            fs.check(p.config / "panel.env", self.root_owners)
            health_url((p.config / "panel.env").read_text(encoding="utf-8"))
        else:
            for path in (p.data, p.config):
                if fs.exists(path):
                    raise LifecycleError("Refusing to claim an unmarked directory: " + str(path))
        for path, expected in ((p.unit, WEB_UNIT), (p.sudoers, SUDOERS)):
            if fs.exists(path):
                if not root_exists:
                    raise LifecycleError("Refusing an orphan/unrelated system file: " + str(path))
                if path == p.unit:
                    self._unit(path, expected)
                else:
                    fs.check(path, self.root_owners)
                    if path.read_text(encoding="utf-8") != expected:
                        raise LifecycleError("Refusing an unrelated sudoers file: " + str(path))
        return manifest, legacy

    def _manifest(self, identity, version, account, installed=True):
        return {"product": PRODUCT, "schema": 1, "id": identity, "version": version,
                "installed": installed, "account": {"uid": account.uid, "gid": account.gid},
                "paths": {name: str(path) for name, path in self.p.resources().items()},
                "files": {name: digest(self.p.root / name) for name in PROGRAM_FILES}}

    def _save_manifest(self, manifest):
        self.fs.json(self.p.config / MANIFEST, manifest)
        self.fs.json(self.p.root / MANIFEST, manifest)

    def _backup(self, state):
        p, fs = self.p, self.fs
        if fs.exists(p.backups):
            fs.check(p.backups, self.root_owners, directory=True)
            if fs.read_json(p.backups / MARKER) != {"product": PRODUCT, "schema": 1, "role": "backups"}:
                raise LifecycleError("Refusing an unrelated backup directory.")
        else:
            fs.mkdir(p.backups, 0o700)
            fs.json(p.backups / MARKER, {"product": PRODUCT, "schema": 1, "role": "backups"})
        backup = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"),
                                       dir=str(p.backups)))
        backup.chmod(0o700)
        present = {}
        for name, source in p.resources().items():
            present[name] = fs.exists(source)
            if present[name]:
                fs.copy(source, backup / name)
        link = fs.read_link(p.command) if fs.exists(p.command) else None
        fs.json(backup / "snapshot.json", {"product": PRODUCT, "schema": 1, "present": present,
                                          "command": link, "active": state[0], "enabled": state[1]})
        self.output("Backup retained at " + str(backup))
        return backup

    def _restore(self, backup, account, identity, state):
        p, fs = self.p, self.fs
        snapshot = fs.read_json(backup / "snapshot.json")
        # Never restore a database until the candidate has completely stopped.
        if fs.exists(p.unit):
            self._unit(p.unit, WEB_UNIT)
            self.host.control("stop")
            self.host.control("disable")
        for name, target in p.resources().items():
            if fs.exists(target):
                if name in ("root", "data", "config"):
                    marker = target / MARKER
                    # A failure between mkdir and marking can only leave an
                    # empty newly-created directory. Existing trees were proven
                    # by _inspect and copied before any changes.
                    if fs.exists(marker):
                        fs.check(marker, self.root_owners)
                    if fs.exists(marker) and marker.read_bytes():
                        self._marker(target, {"root": "program", "data": "data", "config": "config"}[name], identity)
                    elif not snapshot["present"][name] and any(target.iterdir()):
                        raise LifecycleError("Unmarked nonempty directory during rollback: " + str(target))
                    fs.remove_tree(target, self._owners(account) if name == "data" else self.root_owners)
                else:
                    fs.check(target, self.root_owners)
                    target.unlink()
            if snapshot["present"][name]:
                fs.copy(backup / name, target)
        if fs.exists(p.command):
            fs.unlink_link(p.command, p.root / "manage.sh")
        if snapshot["command"] is not None:
            fs.create_link(p.command, snapshot["command"])
        self.host.reload()
        if snapshot["present"]["unit"]:
            if state[1] in ("enabled", "enabled-runtime"):
                self.host.control("enable", runtime=state[1] == "enabled-runtime")
            if state[0]:
                self.host.control("start")
                if not self.host.state()[0]:
                    raise LifecycleError("Previous panel did not restart after rollback.")

    def install(self, bin_dir, distribution_root, version=None):
        self.host.require_system()
        p, fs = self.p, self.fs
        with self.host.lock(p.lock, fs):
            account = self.host.account(p.data)
            previous, legacy = self._inspect(account)
            package = Path(os.path.abspath(distribution_root))
            binaries = Path(os.path.abspath(bin_dir))
            sources = {name: (binaries / name if name in PROGRAM_FILES[:2] else
                             package / ("install.sh" if name == "manage.sh" else name)) for name in PROGRAM_FILES}
            for source in sources.values():
                fs.guard(source)
                info = source.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise LifecycleError("Expected a regular distribution file: " + str(source))
            if normalized(sources["deploy/xray-relay-panel.service"].read_text(encoding="utf-8")) != normalized(WEB_UNIT):
                raise LifecycleError("Distribution unit does not match the lifecycle contract.")
            actual_version = self.host.versions(binaries)
            if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", actual_version):
                raise LifecycleError("Invalid binary version: " + actual_version)
            if version and (version[1:] if version.startswith("v") else version) != actual_version:
                raise LifecycleError("Requested release and binary versions do not match.")
            url = health_url((p.config / "panel.env").read_text(encoding="utf-8") if fs.exists(p.config) else None)
            account = account or self.host.account(p.data, create=True)
            identity = previous["id"] if previous else uuid.uuid4().hex
            state = self.host.state() if fs.exists(p.unit) else (False, "not-found")
            backup = None
            stopped = False
            try:
                if fs.exists(p.unit):
                    self.host.control("stop")
                    stopped = True
                backup = self._backup(state)
                for directory, role, mode, owner in (
                    (p.root, "program", 0o755, None), (p.config, "config", 0o755, None),
                    (p.data, "data", 0o700, (account.uid, account.gid)),
                ):
                    fs.mkdir(directory, mode, owner)
                    self._mark(directory, role, identity)
                for name, source in sources.items():
                    mode = 0o644 if name.endswith((".py", ".service")) else 0o755
                    fs.write(p.root / name, source.read_bytes(), mode)
                if not fs.exists(p.config / "panel.env"):
                    fs.write(p.config / "panel.env", b"XRAY_PANEL_BIND=0.0.0.0:8080\n", 0o600)
                # Validate the exact rule before granting passwordless helper access.
                fs.mkdir(p.sudoers.parent)
                fd, temporary = tempfile.mkstemp(prefix=".xray-panel-", dir=str(p.sudoers.parent))
                os.close(fd)
                candidate = Path(temporary)
                try:
                    fs.write(candidate, SUDOERS.encode(), 0o440)
                    self.host.run("visudo", "-cf", str(candidate))
                    fs.write(p.sudoers, SUDOERS.encode(), 0o440)
                finally:
                    if fs.exists(candidate):
                        fs.check(candidate, self.root_owners)
                        candidate.unlink()
                fs.write(p.unit, sources["deploy/xray-relay-panel.service"].read_bytes())
                fs.mkdir(p.command.parent)
                if not fs.exists(p.command):
                    fs.create_link(p.command, p.root / "manage.sh")
                self._save_manifest(self._manifest(identity, actual_version, account))
                self.host.reload()
                self.host.control("enable")
                self.host.control("restart")
                self.health(self.host, url, actual_version)
            except (Exception, KeyboardInterrupt) as error:
                try:
                    if backup is not None:
                        self._restore(backup, account, identity, state)
                    elif stopped and state[0]:
                        self.host.control("start")
                except Exception as recovery:
                    raise LifecycleError("Install failed (%s); rollback also failed (%s). Backup: %s" %
                                         (error, recovery, backup or p.backups)) from error
                raise LifecycleError("Install failed (%s); previous program and complete data restored. Backup: %s" %
                                     (error, backup or p.backups)) from error
            self.output("Panel %s installed; health: %s" % (actual_version, url))
            self.output("Manage with: xray-relay-panel status | upgrade | uninstall")
            self.output("Fresh installations listen on 0.0.0.0:8080; open http://SERVER_IP:8080 to initialize the administrator.")
            self.output("Existing panel.env settings, including the bind address, are preserved.")

    def _node_owned(self):
        """Recognize only the layout emitted by internal/engine/node.go."""
        p, fs = self.p, self.fs
        self._unit(p.node_unit, NODE_UNIT)
        self.host.check_unit(NODE, p.node_unit)
        for directory in (p.node_root, p.node_root / "revisions", p.node_data):
            info = fs.check(directory, self.root_owners, directory=True)
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise LifecycleError("Local node directory must be root-owned 0700: " + str(directory))
        if {path.name for path in p.node_root.iterdir()} - {"revisions", "current", "previous"}:
            raise LifecycleError("Unrecognized files in local node installation.")
        links = {}
        for name in ("current", "previous"):
            link = p.node_root / name
            if not fs.exists(link):
                if name == "current":
                    raise LifecycleError("Local node has no verifiable active revision.")
                continue
            target = os.readlink(link) if link.is_symlink() else ""
            if not re.fullmatch(r"revisions/[0-9a-f]{24}", target):
                raise LifecycleError("Local node revision link escapes its managed revisions.")
            fs.link(link, target)
            if not fs.exists(p.node_root / target):
                raise LifecycleError("Local node revision link is dangling.")
            links[link] = target
        for revision in (p.node_root / "revisions").iterdir():
            fs.check(revision, self.root_owners, directory=True)
            if not re.fullmatch(r"[0-9a-f]{24}", revision.name):
                raise LifecycleError("Unrecognized local node revision.")
            if {path.name for path in revision.iterdir()} != {"xray", "config.json", "metadata.json"}:
                raise LifecycleError("Incomplete/unrecognized local node revision contents.")
            for name in ("xray", "config.json", "metadata.json"):
                fs.check(revision / name, self.root_owners, hardlinks=name == "xray")
            metadata = fs.read_json(revision / "metadata.json")
            if (metadata.get("revision") != revision.name or metadata.get("architecture") not in ("amd64", "arm64")
                    or not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", str(metadata.get("core_version", "")))
                    or not isinstance(metadata.get("created_at"), str)):
                raise LifecycleError("Unverifiable local node revision metadata.")
            try:
                datetime.fromisoformat(metadata["created_at"].replace("Z", "+00:00"))
                config = json.loads((revision / "config.json").read_text(encoding="utf-8"))
                if not isinstance(config, dict):
                    raise ValueError("config is not an object")
            except (ValueError, UnicodeError) as error:
                raise LifecycleError("Unverifiable local node config/timestamp.") from error
        if {entry.name for entry in p.node_data.iterdir()} != {"operation.lock"}:
            raise LifecycleError("Local node state has unknown files or outstanding probes; retained.")
        fs.check(p.node_data / "operation.lock", self.root_owners)
        fs.tree(p.node_root, self.root_owners, links, hardlinks=True)
        # Xray reuse uses os.Link across revisions; only accept links entirely
        # contained in this tree, never a link to an unrelated external file.
        inodes = {}
        for revision in (p.node_root / "revisions").iterdir():
            info = (revision / "xray").lstat()
            key = (info.st_dev, info.st_ino)
            inodes.setdefault(key, [info.st_nlink, 0])[1] += 1
        if any(expected != count for expected, count in inodes.values()):
            raise LifecycleError("Local node binary has hard links outside its owned revisions.")
        return links

    def uninstall(self, purge=False, remove_local_node=False, yes=False):
        self.host.require_system()
        p, fs = self.p, self.fs
        with self.host.lock(p.lock, fs):
            account = self.host.account(p.data)
            manifest, legacy = self._inspect(account)
            present = fs.exists(p.root)
            node_links = None
            if remove_local_node and any(fs.exists(path) for path in (p.node_unit, p.node_root, p.node_data)):
                try:
                    node_links = self._node_owned()
                except (LifecycleError, OSError) as error:
                    self.output("Local node retained: " + str(error))
            if (purge or remove_local_node) and not yes:
                targets = []
                if purge:
                    targets.extend((p.data, p.config))
                if remove_local_node:
                    targets.extend((p.node_root, p.node_data, p.node_unit))
                self.confirm("Permanently remove verified resources: " + ", ".join(map(str, targets)))
            if present:
                self.host.control("stop")
                self.host.control("disable")
                if legacy:
                    identity = uuid.uuid4().hex
                    # Retain proof for a later offline --purge/reinstall, even
                    # when this call only removes the historical program.
                    for directory, role in ((p.data, "data"), (p.config, "config")):
                        self._mark(directory, role, identity)
                    manifest = {"product": PRODUCT, "schema": 1, "id": identity, "version": "legacy",
                                "installed": False, "account": {"uid": account.uid, "gid": account.gid},
                                "paths": {name: str(path) for name, path in p.resources().items()},
                                "files": {name: "0" * 64 for name in PROGRAM_FILES}}
                else:
                    manifest = dict(manifest, installed=False)
                fs.json(p.config / MANIFEST, manifest)
                for path in (p.unit, p.sudoers):
                    fs.check(path, self.root_owners)
                    path.unlink()
                if fs.exists(p.command):
                    fs.unlink_link(p.command, p.root / "manage.sh")
                fs.remove_tree(p.root, self.root_owners)
                self.host.reload()
            if purge and manifest:
                for directory, role in ((p.data, "data"), (p.config, "config")):
                    self._marker(directory, role, manifest["id"])
                    fs.remove_tree(directory, self._owners(account) if role == "data" else self.root_owners)
                self.output("Verified panel data and configuration removed; system account retained.")
            elif manifest:
                self.output("Panel data, keys, configuration and system account retained.")
            if node_links is not None:
                # Cooperate with Go's operation.lock. Revalidate after acquiring
                # it, before touching a running dedicated node.
                with self.host.lock(p.node_data / "operation.lock", fs):
                    node_links = self._node_owned()
                    self.host.control("stop", NODE)
                    self.host.control("disable", NODE)
                    self._unit(p.node_unit, NODE_UNIT)
                    p.node_unit.unlink()
                    fs.remove_tree(p.node_root, self.root_owners, node_links, hardlinks=True)
                    fs.remove_tree(p.node_data, self.root_owners)
                    self.host.reload()
                self.output("Verified dedicated local node removed.")
            self.output("Panel Web unit uninstalled. Remote nodes, backups and other Xray services were retained.")

    def status(self):
        manifest, _ = self._inspect(self.host.account(self.p.data))
        self.output("Panel: " + ("installed" if self.fs.exists(self.p.root) else "not installed"))
        if manifest:
            self.output("Version: " + str(manifest.get("version", "unknown")))
        self.output("Web service: " + self.host.control("is-active", check=False).stdout.strip())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    install = commands.add_parser("install")
    install.add_argument("--bin-dir", required=True)
    install.add_argument("--distribution-root", required=True)
    install.add_argument("--version")
    uninstall = commands.add_parser("uninstall")
    uninstall.add_argument("--purge", action="store_true")
    uninstall.add_argument("--remove-local-node", action="store_true")
    uninstall.add_argument("--yes", action="store_true")
    commands.add_parser("status")
    args = parser.parse_args(argv)
    lifecycle = Lifecycle()
    try:
        if args.operation == "install":
            lifecycle.install(args.bin_dir, args.distribution_root, args.version)
        elif args.operation == "uninstall":
            lifecycle.uninstall(args.purge, args.remove_local_node, args.yes)
        else:
            lifecycle.status()
    except (LifecycleError, OSError, subprocess.SubprocessError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
