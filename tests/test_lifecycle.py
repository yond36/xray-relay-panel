"""Temporary-directory lifecycle tests; never invoke a real service or installer.

Run on Windows or Linux with:
    python -I -m unittest discover -s tests -p test_lifecycle.py -v
"""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("panel_lifecycle_tests_subject", ROOT / "deploy" / "lifecycle.py")
lc = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lc
SPEC.loader.exec_module(lc)


class TestFilesystem(lc.Filesystem):
    def __init__(self):
        super().__init__(os.getuid() if hasattr(os, "getuid") else 0)
        self.links = {}

    def create_link(self, path, target):
        # The management-link operations are injected so the main lifecycle
        # tests also run on Windows without Developer Mode/symlink privilege.
        self.links[path] = str(target)

    def read_link(self, path):
        return self.links[path] if path in self.links else super().read_link(path)

    def exists(self, path):
        self.guard(path)
        return path in self.links or super().exists(path)

    def link(self, path, target):
        if path not in self.links:
            return super().link(path, target)
        if self.links[path] != str(target):
            raise lc.LifecycleError("unrelated injected management link")

    def unlink_link(self, path, target):
        self.link(path, target)
        if path in self.links:
            del self.links[path]
        else:
            super().unlink_link(path, target)

    def chown(self, path, uid, gid):
        # Tests use the caller's own files. Linux chown is exercised by smoke.
        pass

    def chmod(self, path, mode):
        # Windows maps read-only POSIX modes to a delete-blocking DOS attribute.
        # POSIX permission assertions below run only on POSIX.
        path.chmod(mode | 0o200 if os.name == "nt" else mode)


class TestHost(lc.Host):
    def __init__(self, uid):
        self.calls = []
        self.account_value = lc.Account(uid, os.getgid() if hasattr(os, "getgid") else 0)
        self.units = {lc.WEB: [False, "not-found"], lc.NODE: [True, "enabled"]}
        self.restart_hook = None
        self.fail_visudo = False
        self.fail_stop = False
        self.fail_reload_once = False
        self.fail_unit_check = False

    def require_system(self):
        self.calls.append(("require_system",))

    def account(self, data, create=False):
        self.calls.append(("account", create))
        if create and self.account_value is None:
            self.account_value = lc.Account(0, 0)
        return self.account_value

    @contextmanager
    def lock(self, path, fs):
        self.calls.append(("lock", str(path)))
        yield

    def check_unit(self, unit, path):
        self.calls.append(("check_unit", unit))
        if self.fail_unit_check:
            raise lc.LifecycleError("unexpected systemd drop-in")

    def run(self, *args, check=True):
        self.calls.append(tuple(map(str, args)))
        if args[0] == "visudo":
            if self.fail_visudo:
                raise lc.LifecycleError("invalid sudoers")
            return subprocess.CompletedProcess(args, 0, "", "")
        if Path(args[0]).name in ("xray-panel", "xray-panel-nodectl"):
            return subprocess.CompletedProcess(args, 0, Path(args[0]).read_text(encoding="utf-8").strip(), "")
        raise AssertionError("A test attempted an unexpected external command: " + repr(args))

    def control(self, action, unit=lc.WEB, check=True, runtime=False):
        if unit not in self.units:
            raise AssertionError("Attempted to control an unrelated service")
        self.calls.append(("systemctl", action, unit))
        state = self.units[unit]
        if action == "stop":
            if self.fail_stop:
                raise lc.LifecycleError("stop failed")
            state[0] = False
        elif action in ("start", "restart"):
            state[0] = True
            if action == "restart" and self.restart_hook:
                self.restart_hook()
        elif action == "enable":
            state[1] = "enabled-runtime" if runtime else "enabled"
        elif action == "disable":
            state[1] = "disabled"
        output = "active" if state[0] else "inactive"
        if action == "is-enabled":
            output = state[1]
        return subprocess.CompletedProcess([], 0, output, "")

    def reload(self):
        self.calls.append(("systemctl", "daemon-reload"))
        if self.fail_reload_once:
            self.fail_reload_once = False
            raise lc.LifecycleError("reload failed")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="panel-lifecycle-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.fs = TestFilesystem()
        self.host = TestHost(self.fs.root_uid)
        system = self.base / "system"
        self.p = lc.Layout(
            root=system / "opt/xray-relay-panel", data=system / "var/lib/xray-relay-panel",
            config=system / "etc/xray-relay-panel", unit=system / "etc/systemd/system/xray-relay-panel.service",
            sudoers=system / "etc/sudoers.d/xray-relay-panel", command=system / "usr/local/bin/xray-relay-panel",
            backups=system / "var/backups/xray-relay-panel", lock=system / "run/lock/installer.lock",
            node_root=system / "opt/xray-relay-panel-node", node_data=system / "var/lib/xray-relay-panel-node",
            node_unit=system / "etc/systemd/system/xray-relay-panel-node.service",
        )
        for path in (*self.p.resources().values(), self.p.command, self.p.backups, self.p.lock,
                     self.p.node_root, self.p.node_data, self.p.node_unit):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.messages = []
        self.health_calls = []
        self.package = self.make_package("0.2.2")

    def make_package(self, version):
        package = self.base / ("package-" + version)
        (package / "bin").mkdir(parents=True)
        (package / "deploy").mkdir()
        (package / "bin/xray-panel").write_text("Xray Relay Panel " + version, encoding="utf-8")
        (package / "bin/xray-panel-nodectl").write_text(version, encoding="utf-8")
        (package / "install.sh").write_text("#!/usr/bin/env bash\n# manage fixture\n", encoding="utf-8")
        for name in ("install.sh", "uninstall.sh", "lifecycle.py", "xray-relay-panel.service"):
            (package / "deploy" / name).write_bytes((ROOT / "deploy" / name).read_bytes())
        return package

    def healthy(self, host, url, version):
        self.health_calls.append((url, version))

    def lifecycle(self, health=None, confirm=None):
        return lc.Lifecycle(self.p, self.host, self.fs, health or self.healthy,
                            self.messages.append, confirm=confirm)

    def install(self, package=None):
        package = package or self.package
        self.lifecycle().install(package / "bin", package, "v" + (package / "bin/xray-panel-nodectl").read_text())

    def require_symlinks(self):
        target = self.base / "link-test-target"
        link = self.base / "link-test-link"
        target.touch()
        try:
            link.symlink_to(target)
            link.unlink()
        except OSError:
            self.skipTest("This environment does not permit symlinks")
        finally:
            target.unlink()

    def snapshot(self, directory):
        result = {}
        for path in sorted(directory.rglob("*")):
            relative = str(path.relative_to(directory))
            if path.is_symlink():
                result[relative] = ("link", os.readlink(path))
            elif path.is_file():
                result[relative] = ("file", path.read_bytes())
            else:
                result[relative] = ("directory",)
        return result

    def seed_data(self):
        data = self.p.data
        database = sqlite3.connect(data / "panel.db")
        database.executescript("CREATE TABLE settings(value TEXT); INSERT INTO settings VALUES('old settings');"
                               "CREATE TABLE sessions(token TEXT); INSERT INTO sessions VALUES('old session');")
        database.close()
        (data / "master.key").write_bytes(bytes(range(32)))
        (data / "panel.db-wal").write_bytes(b"complete old WAL\x00")
        (data / "panel.db-shm").write_bytes(b"complete old SHM\x00")
        (data / "ssh").mkdir()
        (data / "ssh/known_hosts").write_bytes(b"host fingerprint\n")
        (data / "ssh/private.key").write_bytes(b"old private credential")

    def legacy(self):
        for directory in (self.p.root, self.p.config, self.p.data):
            directory.mkdir()
        (self.p.root / "xray-panel").write_bytes(b"old binary")
        (self.p.root / "xray-panel-nodectl").write_bytes(b"old helper")
        (self.p.root / lc.MARKER).touch()
        self.p.unit.write_text(lc.WEB_UNIT, encoding="utf-8")
        self.p.sudoers.write_text(lc.SUDOERS, encoding="utf-8")
        (self.p.config / "panel.env").write_text("XRAY_PANEL_BIND=127.0.0.1:18080\nXRAY_PANEL_SECURE_COOKIES=1\n", encoding="utf-8")
        self.p.data.chmod(0o700)
        self.seed_data()
        self.host.units[lc.WEB] = [True, "enabled"]

    def node_fixture(self):
        self.p.node_unit.write_text(lc.NODE_UNIT, encoding="utf-8")
        self.p.node_root.mkdir(mode=0o700)
        self.p.node_data.mkdir(mode=0o700)
        self.p.node_root.chmod(0o700)
        self.p.node_data.chmod(0o700)
        revisions = self.p.node_root / "revisions"
        revisions.mkdir(mode=0o700)
        revisions.chmod(0o700)
        revision = revisions / ("a" * 24)
        revision.mkdir(mode=0o700)
        revision.chmod(0o700)
        (revision / "xray").write_bytes(b"isolated core fixture")
        (revision / "xray").chmod(0o755)
        (revision / "config.json").write_text('{"inbounds": [], "outbounds": []}', encoding="utf-8")
        (revision / "config.json").chmod(0o600)
        metadata = {"revision": revision.name, "core_version": "v25.8.3", "architecture": "amd64",
                    "created_at": "2026-11-07T00:00:00Z"}
        (revision / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        (revision / "metadata.json").chmod(0o600)
        (self.p.node_root / "current").symlink_to("revisions/" + revision.name, target_is_directory=True)
        (self.p.node_data / "operation.lock").touch(mode=0o600)
        return revision

    def test_fresh_uninitialized_install_persists_management(self):
        self.install()
        self.assertEqual(self.health_calls, [("http://127.0.0.1:8080/healthz", "0.2.2")])
        self.assertFalse((self.p.data / "panel.db").exists())
        self.assertEqual(self.host.units[lc.WEB], [True, "enabled"])
        self.assertEqual(Path(self.fs.read_link(self.p.command)), self.p.root / "manage.sh")
        for name in lc.PROGRAM_FILES:
            self.assertTrue((self.p.root / name).is_file(), name)
        manifest = self.fs.read_json(self.p.config / lc.MANIFEST)
        self.assertEqual(manifest, self.fs.read_json(self.p.root / lc.MANIFEST))
        self.assertEqual(manifest["version"], "0.2.2")
        self.assertFalse(any(call[-1] == lc.NODE for call in self.host.calls))

    def test_upgrade_keeps_entire_data_settings_sessions_and_environment(self):
        self.install()
        self.seed_data()
        env = self.p.config / "panel.env"
        env.write_bytes(b"XRAY_PANEL_BIND='[::]:18081'\nXRAY_PANEL_SECURE_COOKIES=1\n")
        data_before = self.snapshot(self.p.data)
        env_before = env.read_bytes()
        next_package = self.make_package("0.2.3")
        self.install(next_package)
        self.assertEqual(self.snapshot(self.p.data), data_before)
        self.assertEqual(env.read_bytes(), env_before)
        self.assertEqual(self.health_calls[-1], ("http://[::1]:18081/healthz", "0.2.3"))
        backups = [path for path in self.p.backups.iterdir() if path.is_dir()]
        latest = next(path for path in backups if (path / "data/panel.db").exists())
        self.assertEqual((latest / "data/panel.db-wal").read_bytes(), b"complete old WAL\x00")
        self.assertEqual((latest / "data/master.key").read_bytes(), bytes(range(32)))
        self.assertFalse(any(call[-1] == lc.NODE for call in self.host.calls))

    def test_failed_health_restores_program_full_database_key_wal_env_and_link(self):
        self.install()
        self.seed_data()
        before = {name: self.snapshot(path) if path.is_dir() else path.read_bytes()
                  for name, path in self.p.resources().items()}
        before_link = Path(self.fs.read_link(self.p.command))
        package = self.make_package("0.2.3")

        def migrate_then_fail(host, url, version):
            (self.p.data / "master.key").write_bytes(b"new incompatible key")
            (self.p.data / "panel.db").write_bytes(b"incompatible schema")
            (self.p.data / "panel.db-wal").unlink()
            (self.p.data / "panel.db-shm").write_bytes(b"changed shm")
            (self.p.data / "new-migration-dir").mkdir()
            (self.p.data / "new-migration-dir/new-record").touch()
            raise lc.LifecycleError("health failed")

        with self.assertRaisesRegex(lc.LifecycleError, "complete data restored"):
            self.lifecycle(migrate_then_fail).install(package / "bin", package, "v0.2.3")
        for name, path in self.p.resources().items():
            self.assertEqual(self.snapshot(path) if path.is_dir() else path.read_bytes(), before[name], name)
        self.assertEqual(Path(self.fs.read_link(self.p.command)), before_link)
        self.assertEqual(self.host.units[lc.WEB], [True, "enabled"])
        self.assertTrue(any(path.name == "snapshot.json" for path in self.p.backups.rglob("*")))
        self.assertFalse(any(call[-1] == lc.NODE for call in self.host.calls))

    def test_legacy_claim_is_strict_and_preserves_data_on_success(self):
        self.legacy()
        old_data = {key: value for key, value in self.snapshot(self.p.data).items()}
        self.install()
        actual = self.snapshot(self.p.data)
        actual.pop(lc.MARKER)
        self.assertEqual(actual, old_data)
        self.assertEqual(self.health_calls[-1][0], "http://127.0.0.1:18080/healthz")
        self.assertTrue((self.p.root / lc.MANIFEST).is_file())

    def test_legacy_health_failure_restores_empty_marker_and_complete_old_tree(self):
        self.legacy()
        before = {name: self.snapshot(path) if path.is_dir() else path.read_bytes()
                  for name, path in self.p.resources().items()}
        self.host.units[lc.WEB] = [False, "disabled"]
        with self.assertRaisesRegex(lc.LifecycleError, "complete data restored"):
            self.lifecycle(lambda *args: (_ for _ in ()).throw(lc.LifecycleError("not healthy"))).install(
                self.package / "bin", self.package, "v0.2.2")
        for name, path in self.p.resources().items():
            self.assertEqual(self.snapshot(path) if path.is_dir() else path.read_bytes(), before[name], name)
        self.assertFalse(self.p.command.exists())
        self.assertEqual(self.host.units[lc.WEB], [False, "disabled"])

    def test_default_uninstall_retains_data_account_and_running_local_node(self):
        self.require_symlinks()
        self.install()
        self.seed_data()
        self.node_fixture()
        before = self.snapshot(self.p.data)
        node = self.snapshot(self.p.node_root)
        self.host.calls.clear()
        self.lifecycle().uninstall()
        self.assertFalse(self.p.root.exists())
        self.assertFalse(self.p.unit.exists())
        self.assertFalse(self.p.sudoers.exists())
        self.assertFalse(self.fs.exists(self.p.command))
        self.assertEqual(self.snapshot(self.p.data), before)
        self.assertTrue((self.p.config / "panel.env").exists())
        self.assertFalse(self.fs.read_json(self.p.config / lc.MANIFEST)["installed"])
        self.assertEqual(self.snapshot(self.p.node_root), node)
        self.assertEqual(self.host.units[lc.NODE], [True, "enabled"])
        self.assertFalse(any(call[-1] == lc.NODE for call in self.host.calls))
        self.assertTrue(self.host.account_value)
        self.lifecycle().uninstall()  # Retained metadata makes default uninstall idempotent.
        self.install()  # Reinstall adopts only the retained, proven data.
        self.assertEqual(self.snapshot(self.p.data), before)

    def test_purge_can_follow_default_uninstall_and_keeps_backups_and_node(self):
        self.install()
        self.seed_data()
        self.lifecycle().uninstall()
        self.lifecycle().uninstall(purge=True, yes=True)
        self.assertFalse(self.p.data.exists())
        self.assertFalse(self.p.config.exists())
        self.assertTrue(self.p.backups.is_dir())
        self.assertTrue(self.host.account_value)
        self.assertEqual(self.host.units[lc.NODE], [True, "enabled"])
        self.lifecycle().uninstall(purge=True, yes=True)

    def test_legacy_default_uninstall_retains_proof_for_later_purge(self):
        self.legacy()
        self.lifecycle().uninstall()
        self.assertTrue((self.p.data / lc.MARKER).exists())
        self.assertTrue((self.p.config / lc.MANIFEST).exists())
        self.lifecycle().uninstall(purge=True, yes=True)
        self.assertFalse(self.p.data.exists())

    def test_destructive_options_require_explicit_confirmation(self):
        self.install()
        before = self.snapshot(self.p.root)
        calls = []

        def decline(message):
            calls.append(message)
            raise lc.LifecycleError("confirmation required")

        with self.assertRaisesRegex(lc.LifecycleError, "confirmation required"):
            self.lifecycle(confirm=decline).uninstall(purge=True)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.snapshot(self.p.root), before)
        self.lifecycle(confirm=decline).uninstall(purge=True, yes=True)
        self.assertEqual(len(calls), 1)

    def test_remove_local_node_is_independent_of_purge(self):
        self.require_symlinks()
        self.install()
        self.seed_data()
        self.node_fixture()
        data = self.snapshot(self.p.data)
        self.lifecycle().uninstall(remove_local_node=True, yes=True)
        self.assertFalse(self.p.node_root.exists())
        self.assertFalse(self.p.node_data.exists())
        self.assertFalse(self.p.node_unit.exists())
        self.assertEqual(self.snapshot(self.p.data), data)
        self.assertEqual(self.host.units[lc.NODE], [False, "disabled"])

    def test_ambiguous_local_node_is_retained_and_reported(self):
        self.require_symlinks()
        self.install()
        self.node_fixture()
        (self.p.node_root / "foreign-file").write_bytes(b"keep me")
        self.host.calls.clear()
        self.lifecycle().uninstall(remove_local_node=True, yes=True)
        self.assertTrue((self.p.node_root / "foreign-file").exists())
        self.assertTrue(self.p.node_unit.exists())
        self.assertTrue(self.host.units[lc.NODE][0])
        self.assertTrue(any("Local node retained:" in message for message in self.messages))
        self.assertNotIn(("systemctl", "stop", lc.NODE), self.host.calls)

    def test_symlinked_node_revision_escape_is_retained(self):
        self.require_symlinks()
        self.install()
        self.node_fixture()
        current = self.p.node_root / "current"
        current.unlink()
        current.symlink_to(self.base, target_is_directory=True)
        self.lifecycle().uninstall(remove_local_node=True, yes=True)
        self.assertTrue(self.p.node_unit.exists())
        self.assertTrue(self.host.units[lc.NODE][0])

    def test_unknown_and_marker_only_program_directories_are_refused(self):
        self.p.root.mkdir()
        (self.p.root / lc.MARKER).touch()
        (self.p.root / "foreign-file").touch()
        with self.assertRaises(lc.LifecycleError):
            self.install()
        with self.assertRaises(lc.LifecycleError):
            self.lifecycle().uninstall(purge=True, yes=True)
        self.assertTrue((self.p.root / "foreign-file").exists())
        self.assertNotIn(("systemctl", "stop", lc.WEB), self.host.calls)

    def test_unmarked_existing_data_and_sudoers_are_not_claimed(self):
        self.p.data.mkdir()
        (self.p.data / "foreign-file").touch()
        with self.assertRaisesRegex(lc.LifecycleError, "unmarked"):
            self.install()
        self.assertTrue((self.p.data / "foreign-file").exists())
        (self.p.data / "foreign-file").unlink()
        self.p.data.rmdir()
        self.p.sudoers.write_text("foreign rule", encoding="utf-8")
        with self.assertRaisesRegex(lc.LifecycleError, "orphan/unrelated"):
            self.install()
        self.assertEqual(self.p.sudoers.read_text(), "foreign rule")

    def test_custom_legacy_unit_or_rule_is_refused_before_stop(self):
        self.legacy()
        self.p.unit.write_text(lc.WEB_UNIT + "\nExecStartPost=/bin/true\n", encoding="utf-8")
        with self.assertRaisesRegex(lc.LifecycleError, "customized"):
            self.install()
        self.assertNotIn(("systemctl", "stop", lc.WEB), self.host.calls)
        self.p.unit.write_text(lc.WEB_UNIT, encoding="utf-8")
        self.p.sudoers.write_text(lc.SUDOERS + "foreign rule\n", encoding="utf-8")
        with self.assertRaisesRegex(lc.LifecycleError, "sudoers"):
            self.lifecycle().uninstall(purge=True, yes=True)

    def test_unknown_program_file_and_changed_managed_binary_are_refused(self):
        self.install()
        stranger = self.p.root / "unrecognized"
        stranger.touch()
        with self.assertRaisesRegex(lc.LifecycleError, "unrecognized"):
            self.lifecycle().uninstall()
        stranger.unlink()
        (self.p.root / "xray-panel").write_bytes(b"foreign binary")
        with self.assertRaisesRegex(lc.LifecycleError, "changed"):
            self.lifecycle().uninstall()
        self.assertTrue(self.p.unit.exists())

    def test_data_symlink_blocks_purge_before_any_deletion(self):
        self.require_symlinks()
        self.install()
        external = self.base / "keep-secret"
        external.write_bytes(b"untouched")
        (self.p.data / "escaped").symlink_to(external)
        with self.assertRaisesRegex(lc.LifecycleError, "symlink"):
            self.lifecycle().uninstall(purge=True, yes=True)
        self.assertTrue(self.p.root.exists())
        self.assertEqual(external.read_bytes(), b"untouched")

    def test_symlinked_parent_and_unrelated_command_are_refused(self):
        self.require_symlinks()
        parent = self.p.root.parent
        parent.rmdir()
        target = self.base / "foreign-opt"
        target.mkdir()
        parent.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(lc.LifecycleError, "Unsafe parent"):
            self.install()
        parent.unlink()
        parent.mkdir()
        self.p.command.write_bytes(b"foreign command")
        with self.assertRaisesRegex(lc.LifecycleError, "unrelated"):
            self.install()
        self.assertEqual(self.p.command.read_bytes(), b"foreign command")

    def test_wrong_ownership_is_refused(self):
        self.install()
        original = Path.lstat
        target = self.p.root / "xray-panel"

        def foreign_owner(path):
            result = original(path)
            if path == target:
                fields = list(result)
                fields[4] = 987654
                return os.stat_result(fields)
            return result

        with mock.patch.object(Path, "lstat", foreign_owner):
            with self.assertRaisesRegex(lc.LifecycleError, "owner"):
                self.lifecycle().uninstall(purge=True, yes=True)
        self.assertTrue(target.exists())

    def test_manifest_tampering_does_not_redirect_deletion(self):
        self.install()
        manifest_path = self.p.root / lc.MANIFEST
        value = json.loads(manifest_path.read_text())
        value["paths"]["data"] = str(self.base)
        manifest_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(lc.LifecycleError, "manifest"):
            self.lifecycle().uninstall(purge=True, yes=True)
        self.assertTrue(self.p.data.exists())

    def test_malformed_manifest_file_map_is_rejected(self):
        self.install()
        path = self.p.root / lc.MANIFEST
        original = json.loads(path.read_text())
        for files in (None, 17, [], ["xray-panel"]):
            value = dict(original, files=files)
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(files=files), self.assertRaisesRegex(lc.LifecycleError, "manifest"):
                self.lifecycle().uninstall(purge=True, yes=True)
        self.assertTrue(self.p.unit.exists())
        self.assertTrue(self.p.data.exists())

    def test_retained_data_marker_must_match_the_trusted_manifest(self):
        self.install()
        self.lifecycle().uninstall()
        marker = self.p.data / lc.MARKER
        value = json.loads(marker.read_text())
        value["id"] = "a" * 32
        marker.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(lc.LifecycleError, "marker"):
            self.lifecycle().uninstall(purge=True, yes=True)
        with self.assertRaisesRegex(lc.LifecycleError, "marker"):
            self.install()
        self.assertTrue(self.p.data.exists())

    def test_version_mismatch_and_dropins_fail_before_stop(self):
        with self.assertRaisesRegex(lc.LifecycleError, "versions"):
            (self.package / "bin/xray-panel-nodectl").write_text("0.2.1", encoding="utf-8")
            self.install()
        self.assertFalse(self.p.root.exists())
        (self.package / "bin/xray-panel-nodectl").write_text("0.2.2", encoding="utf-8")
        with self.assertRaisesRegex(lc.LifecycleError, "Requested release"):
            self.lifecycle().install(self.package / "bin", self.package, "v0.2.3")
        self.host.fail_unit_check = True
        with self.assertRaisesRegex(lc.LifecycleError, "drop-in"):
            self.install()
        self.assertNotIn(("systemctl", "stop", lc.WEB), self.host.calls)

    def test_fresh_failure_cleans_only_created_resources(self):
        self.host.fail_visudo = True
        with self.assertRaisesRegex(lc.LifecycleError, "restored"):
            self.install()
        for path in (*self.p.resources().values(), self.p.command):
            self.assertFalse(self.fs.exists(path), str(path))
        self.assertTrue(self.p.backups.exists())
        self.assertTrue(self.host.account_value)

    def test_copy_failure_restarts_previous_without_modifying_it(self):
        self.legacy()
        data = self.snapshot(self.p.data)
        with mock.patch.object(self.fs, "copy", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(lc.LifecycleError, "disk full"):
                self.install()
        self.assertTrue(self.host.units[lc.WEB][0])
        self.assertEqual(self.snapshot(self.p.data), data)
        self.assertEqual((self.p.root / "xray-panel").read_bytes(), b"old binary")

    def test_stop_failure_prevents_backup_and_switch(self):
        self.legacy()
        self.host.fail_stop = True
        with self.assertRaisesRegex(lc.LifecycleError, "stop failed"):
            self.install()
        self.assertFalse(self.p.backups.exists())
        self.assertEqual((self.p.root / "xray-panel").read_bytes(), b"old binary")

    def test_health_url_is_local_anonymous_and_rejects_custom_data(self):
        self.assertEqual(lc.health_url(None), "http://127.0.0.1:8080/healthz")
        self.assertEqual(lc.health_url("XRAY_PANEL_BIND=0.0.0.0:8090"), "http://127.0.0.1:8090/healthz")
        self.assertEqual(lc.health_url("XRAY_PANEL_BIND='[::1]:8090'"), "http://[::1]:8090/healthz")
        for env in ("XRAY_PANEL_BIND=evil.example:80", "XRAY_PANEL_BIND=127.0.0.1:0",
                    "XRAY_PANEL_DATA=/other", "XRAY_PANEL_NODECTL=/other"):
            with self.subTest(env=env), self.assertRaises(lc.LifecycleError):
                lc.health_url(env)

    def test_health_probe_accepts_uninitialized_panel_without_bootstrap(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self, limit):
                return b'{"status":"ok","version":"0.2.2"}'

        opener = mock.Mock()
        opener.open.return_value = Response()
        self.host.units[lc.WEB][0] = True
        with mock.patch.object(lc.urllib.request, "build_opener", return_value=opener):
            lc.wait_healthy(self.host, "http://127.0.0.1:8080/healthz", "0.2.2", timeout=1)
        opener.open.assert_called_once_with("http://127.0.0.1:8080/healthz", timeout=1)

    @unittest.skipIf(os.name == "nt", "POSIX permissions are enforced by Linux smoke")
    def test_posix_modes_and_writable_tree_rejection(self):
        self.install()
        for path, mode in ((self.p.data, 0o700), (self.p.config / "panel.env", 0o600),
                           (self.p.sudoers, 0o440), (self.p.root / "xray-panel", 0o755),
                           (self.p.root / lc.MANIFEST, 0o600)):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode, str(path))
        (self.p.root / "xray-panel").chmod(0o777)
        with self.assertRaisesRegex(lc.LifecycleError, "writable"):
            self.lifecycle().uninstall()

    def test_cli_does_not_expose_test_roots_or_skip_checks(self):
        for flags in (("uninstall", "--root", str(self.base)), ("uninstall", "--skip-ownership"),
                      ("install", "--skip-health", "--bin-dir", "x", "--distribution-root", "x")):
            with self.subTest(flags=flags), mock.patch("sys.stderr"), self.assertRaises(SystemExit) as error:
                lc.main(flags)
            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
