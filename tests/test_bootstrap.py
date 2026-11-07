"""Offline, read-only bootstrap checks; never install or contact a release server."""
import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "install.sh"
TAG = "v0.2.2"
MAX_FILE = 128 * 1024 * 1024


class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = shutil.which("bash")
        if cls.bash is None:
            raise unittest.SkipTest("bash is required to exercise install.sh")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="xray-bootstrap-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.caller = self.work / "caller"
        self.caller.mkdir()
        self.archive_directory = self.work / "archive"
        self.archive_directory.mkdir()

    def run_bootstrap(self, *arguments, env=None):
        return subprocess.run(
            [self.bash, SCRIPT.as_posix(), *map(str, arguments)],
            cwd=self.caller,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )

    def checksum(self, package, record=None):
        if record is None:
            record = hashlib.sha256(package.read_bytes()).hexdigest() + "  " + package.name + "\n"
        Path(str(package) + ".sha256").write_bytes(record.encode("ascii"))

    def member(self, name, content=b"fixture\n", kind=tarfile.REGTYPE, linkname="", size=None, mode=0o644, pax=None):
        info = tarfile.TarInfo(name)
        info.type = kind
        info.mode = mode
        info.linkname = linkname
        info.size = len(content) if kind == tarfile.REGTYPE else 0
        if size is not None:
            info.size = size
        info.pax_headers = pax or {}
        return info, content

    def fixture(self, arch="amd64", extra=(), root=None, omit=()):
        root = root or "xray-relay-panel-linux-" + arch
        package = self.archive_directory / ("xray-relay-panel-linux-" + arch + ".tar.gz")
        contents = {
            "install.sh": b"#!/bin/bash\necho MUST_NOT_EXECUTE >&2; exit 99\n",
            "bin/xray-panel": b"fixture panel binary\n",
            "bin/xray-panel-nodectl": b"fixture helper binary\n",
            "deploy/install.sh": b"#!/bin/bash\necho MUST_NOT_EXECUTE >&2; exit 99\n",
            "deploy/uninstall.sh": b"#!/bin/bash\necho MUST_NOT_EXECUTE >&2; exit 99\n",
            "deploy/lifecycle.py": b"raise RuntimeError('MUST_NOT_EXECUTE')\n",
            "deploy/xray-relay-panel.service": b"[Service]\nExecStart=/opt/xray-relay-panel/xray-panel\n",
        }
        with tarfile.open(package, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            directory, _ = self.member(root, kind=tarfile.DIRTYPE, mode=0o755)
            archive.addfile(directory)
            for name, content in contents.items():
                if name in omit:
                    continue
                mode = 0o755 if name.endswith(".sh") or name.startswith("bin/") else 0o644
                info, data = self.member(root + "/" + name, content, mode=mode)
                archive.addfile(info, io.BytesIO(data))
            for info, data in extra:
                # Header-only malformed members exercise limits without creating
                # large files. The verifier must reject before reading their data.
                stream = io.BytesIO(data) if info.size == len(data) and info.isfile() else None
                archive.addfile(info, stream)
        self.checksum(package)
        return package

    def verify(self, package, arch="amd64", *extra, env=None):
        return self.run_bootstrap(
            "--verify-package", package.as_posix(), "--version", TAG, "--arch", arch, *extra, env=env
        )

    def assert_rejected(self, package, expected=None, arch="amd64"):
        result = self.verify(package, arch)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("MUST_NOT_EXECUTE", result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        if expected:
            self.assertIn(expected.lower(), result.stderr.lower())
        return result

    def test_bash_syntax(self):
        result = subprocess.run(
            [self.bash, "-n", SCRIPT.as_posix()], capture_output=True, text=True, timeout=15, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_is_portable_and_requires_no_package(self):
        result = self.run_bootstrap("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for text in ("--verify-package", "--local-package", "--remove-local-node", "latest", "status"):
            self.assertIn(text, result.stdout)

    def test_valid_amd64_and_arm64_are_read_only(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                package = self.fixture(arch)
                before = {p.name: p.read_bytes() for p in self.archive_directory.iterdir()}
                result = self.verify(package, arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Verified", result.stdout)
                self.assertIn(TAG, result.stdout)
                self.assertIn(arch, result.stdout)
                self.assertEqual(before, {p.name: p.read_bytes() for p in self.archive_directory.iterdir()})
                self.assertEqual(list(self.caller.iterdir()), [])

    def test_options_with_equals_and_binary_sha_record(self):
        package = self.fixture()
        digest = hashlib.sha256(package.read_bytes()).hexdigest().upper()
        self.checksum(package, digest + " *" + package.name + "\r\n")
        result = self.run_bootstrap(
            "--verify-package=" + package.as_posix(), "--version=" + TAG, "--arch=amd64"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_sidecar(self):
        package = self.fixture()
        Path(str(package) + ".sha256").unlink()
        self.assert_rejected(package)

    def test_bad_digest(self):
        package = self.fixture()
        self.checksum(package, "0" * 64 + "  " + package.name + "\n")
        self.assert_rejected(package, "SHA256 mismatch")

    def test_malformed_or_ambiguous_sha_records(self):
        package = self.fixture()
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        records = (
            "f" * 63 + "  " + package.name + "\n",
            "g" * 64 + "  " + package.name + "\n",
            digest + "  different.tar.gz\n",
            digest + "  ../" + package.name + "\n",
            digest + "  " + package.name + "\n" + digest + "  " + package.name + "\n",
            digest + "\n",
            digest + "  " + package.name + " trailing\n",
        )
        for record in records:
            with self.subTest(record=record):
                self.checksum(package, record)
                self.assert_rejected(package, "64-hex")

    def test_oversized_checksum(self):
        package = self.fixture()
        self.checksum(package, "a" * 1025)
        self.assert_rejected(package, "size limit")

    def test_exact_asset_filename_and_architecture(self):
        package = self.fixture()
        renamed = package.with_name("renamed.tar.gz")
        package.rename(renamed)
        self.checksum(renamed)
        self.assert_rejected(renamed, "exact package filename")
        renamed.rename(package)
        self.assert_rejected(package, "exact package filename", arch="arm64")

    def test_wrong_package_root(self):
        package = self.fixture(root="unrelated")
        self.assert_rejected(package, "package root")

    def test_traversal_absolute_and_windows_paths(self):
        root = "xray-relay-panel-linux-amd64"
        for name in (
            "../escaped", "/tmp/escaped", root + "/../../escaped", root + "/../escaped",
            root + "/./escaped", root + "//escaped", root + "\\escaped", "C:/escaped", root + "/file:stream",
        ):
            with self.subTest(name=name):
                package = self.fixture(extra=[self.member(name)])
                self.assert_rejected(package)
                self.assertFalse((self.work / "escaped").exists())

    def test_symlink_hardlink_and_special_files(self):
        root = "xray-relay-panel-linux-amd64"
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.GNUTYPE_SPARSE):
            with self.subTest(kind=kind):
                entry = self.member(root + "/unsafe", kind=kind, linkname="../../escaped")
                package = self.fixture(extra=[entry])
                self.assert_rejected(package, "forbidden")

    def test_pax_path_cannot_hide_traversal(self):
        root = "xray-relay-panel-linux-amd64"
        entry = self.member(root + "/innocent", pax={"path": root + "/../escaped"})
        self.assert_rejected(self.fixture(extra=[entry]), "traversal")

    def test_oversized_metadata(self):
        entry = self.member("xray-relay-panel-linux-amd64/docs/note", pax={"comment": "x" * (65 * 1024)})
        self.assert_rejected(self.fixture(extra=[entry]), "metadata")

    def test_duplicate_and_file_directory_conflicts(self):
        root = "xray-relay-panel-linux-amd64"
        variants = (
            [self.member(root + "/bin/xray-panel")],
            [self.member(root + "/parent"), self.member(root + "/parent/child")],
            [self.member(root + "/parent/child"), self.member(root + "/parent")],
        )
        for entries in variants:
            with self.subTest(entries=[i.name for i, _ in entries]):
                self.assert_rejected(self.fixture(extra=entries))

    def test_setuid_mode_is_rejected(self):
        entry = self.member("xray-relay-panel-linux-amd64/unsafe", mode=0o4755)
        self.assert_rejected(self.fixture(extra=[entry]), "modes")

    def test_oversized_file_header_is_rejected_without_large_fixture(self):
        entry = self.member("xray-relay-panel-linux-amd64/large", content=b"", size=MAX_FILE + 1)
        self.assert_rejected(self.fixture(extra=[entry]), "file size limit")

    def test_member_count_is_bounded(self):
        root = "xray-relay-panel-linux-amd64"
        entries = [self.member(root + "/empty-" + str(index), content=b"") for index in range(4097)]
        self.assert_rejected(self.fixture(extra=entries), "too many")

    def test_missing_or_empty_required_file(self):
        package = self.fixture(omit=("deploy/lifecycle.py",))
        self.assert_rejected(package, "missing required")
        # Include the empty member once, rather than merely hitting duplicates.
        entry = self.member("xray-relay-panel-linux-amd64/deploy/lifecycle.py", content=b"")
        package = self.fixture(omit=("deploy/lifecycle.py",), extra=[entry])
        self.assert_rejected(package, "empty required")

    def test_truncated_archive_and_bad_gzip_crc(self):
        package = self.fixture()
        original = package.read_bytes()
        variants = (original[:-5], original[:-8] + bytes([original[-8] ^ 0xFF]) + original[-7:])
        for data in variants:
            with self.subTest(length=len(data)):
                package.write_bytes(data)
                self.checksum(package)
                self.assert_rejected(package)

    def test_nonzero_content_after_tar_end_is_rejected(self):
        package = self.fixture()
        package.write_bytes(package.read_bytes() + gzip.compress(b"hidden archive data"))
        self.checksum(package)
        self.assert_rejected(package, "after the tar end")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_input_symlinks_are_rejected(self):
        package = self.fixture()
        original = self.archive_directory / "original-package"
        package.rename(original)
        try:
            package.symlink_to(original)
        except (OSError, NotImplementedError) as error:
            self.skipTest("cannot create a symlink on this host: " + str(error))
        self.assert_rejected(package, "regular file")
        package.unlink()
        original.rename(package)
        sidecar = Path(str(package) + ".sha256")
        saved = self.archive_directory / "original-sha"
        sidecar.rename(saved)
        sidecar.symlink_to(saved)
        self.assert_rejected(package, "regular file")

    def test_isolated_python_ignores_untrusted_cwd_and_pythonpath(self):
        for module in ("hashlib", "tarfile", "json", "gzip", "sitecustomize"):
            (self.caller / (module + ".py")).write_text("raise RuntimeError('MUST_NOT_EXECUTE')\n", encoding="utf-8")
        # Archive-owned code is equally inert, including modules with stdlib names.
        entry = self.member("xray-relay-panel-linux-amd64/json.py", b"raise RuntimeError('MUST_NOT_EXECUTE')\n")
        package = self.fixture(extra=[entry])
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(self.caller)
        result = self.verify(package, env=environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("MUST_NOT_EXECUTE", result.stdout + result.stderr)
        self.assertFalse((self.caller / "__pycache__").exists())

    def test_verify_requires_fixed_tag_arch_and_no_lifecycle_options(self):
        package = self.fixture()
        variants = (
            ("--verify-package", package.as_posix(), "--arch", "amd64"),
            ("--verify-package", package.as_posix(), "--version", "latest", "--arch", "amd64"),
            ("--verify-package", package.as_posix(), "--version", TAG),
            ("--verify-package", package.as_posix(), "--version", TAG, "--arch", "386"),
            ("uninstall", "--verify-package", package.as_posix(), "--version", TAG, "--arch", "amd64"),
            ("--verify-package", package.as_posix(), "--version", TAG, "--arch", "amd64", "--yes"),
            ("--verify-package", package.as_posix(), "--version", "v0.2.2/../../bad", "--arch", "amd64"),
        )
        for arguments in variants:
            with self.subTest(arguments=arguments):
                result = self.run_bootstrap(*arguments)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
