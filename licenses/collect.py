"""Copy exact-version legal notices using the Python standard library only.

Run from a trusted directory with Python -I. This script reads dependency files as
bytes/JSON, never imports them, executes no package code, and never downloads data.
Existing output is retained; the manifest describes only the current collection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

LEGAL_NAME = re.compile(r"^(?:licen[cs]e|copying|notice|copyright|authors|patents)(?:[._-]|$)", re.I)
CODE_SUFFIXES = {".go", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".map", ".c", ".h", ".s", ".svg", ".png", ".json"}
SKIP_DIRS = {".git", "node_modules", "testdata"}
GO_LICENSES = {
    "github.com/pkg/sftp": "BSD-2-Clause",
    "github.com/dustin/go-humanize": "MIT",
    "github.com/google/uuid": "BSD-3-Clause",
    "github.com/kr/fs": "BSD-3-Clause",
    "github.com/mattn/go-isatty": "MIT",
    "github.com/ncruces/go-strftime": "MIT",
    "github.com/remyoudompheng/bigfft": "BSD-3-Clause",
    "golang.org/x/crypto": "BSD-3-Clause; PATENTS",
    "golang.org/x/net": "BSD-3-Clause; PATENTS",
    "golang.org/x/exp": "BSD-3-Clause; PATENTS",
    "golang.org/x/sys": "BSD-3-Clause; PATENTS",
    "modernc.org/sqlite": "BSD-3-Clause; SQLite public-domain dedication in generated source",
    "modernc.org/libc": "BSD-3-Clause; MIT and other notices in COPYRIGHT-MUSL; embedded netdb MIT",
    "modernc.org/mathutil": "BSD-3-Clause; mersenne BSD-3-Clause",
    "modernc.org/memory": "BSD-3-Clause and supplementary LICENSE-* files",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def go_escape(text: str) -> str:
    return "".join("!" + c.lower() if c.isupper() else c for c in text)


def legal_files(base: Path) -> list[Path]:
    found = []
    for current, dirs, files in os.walk(base, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(current) / d).is_symlink())
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink():
                continue
            if LEGAL_NAME.match(name) and path.suffix.lower() not in CODE_SUFFIXES:
                found.append(path)
    return found


def copy_notices(base: Path, target: Path, output: Path) -> list[dict]:
    result = []
    for source in legal_files(base):
        relative = source.relative_to(base)
        destination = target / relative
        data = source.read_bytes()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        result.append({"source": relative.as_posix(), "file": destination.relative_to(output).as_posix(), "sha256": sha256(data), "bytes": len(data)})
    return result


def source_notice(base: Path, relative: str, pattern: bytes, destination: Path, output: Path) -> dict:
    """Preserve a known embedded legal comment without copying executable code."""
    source = base / relative
    data = source.read_bytes()
    match = next((block for block in re.findall(rb"/\*.*?\*/", data, re.S) if re.search(pattern, block, re.I)), None)
    if match is None:
        raise ValueError("Expected legal comment not found: " + relative)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(match)
    return {"source": relative, "kind": "source_comment", "source_file_sha256": sha256(data), "file": destination.relative_to(output).as_posix(), "sha256": sha256(match), "bytes": len(match)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--gomodcache", required=True, type=Path)
    parser.add_argument("--goroot", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    output = root / "licenses"
    output.mkdir(exist_ok=True)
    go_mod = root / "go.mod"
    npm_lock = root / "web/package-lock.json"
    lock = json.loads(npm_lock.read_text(encoding="utf-8"))
    entries = []
    for name, version, indirect in re.findall(r"^\s*([\w.\-/]+)\s+(v\S+)([^\n]*)", go_mod.read_text(encoding="utf-8"), re.M):
        base = args.gomodcache / (go_escape(name) + "@" + go_escape(version))
        entry = {"ecosystem": "go", "name": name, "version": version, "scope": "indirect" if "indirect" in indirect else "direct", "license_summary": GO_LICENSES.get(name, "See original files"), "files": []}
        if base.is_dir():
            target = output / "go" / (name + "@" + version)
            entry["files"] = copy_notices(base, target, output)
            if name == "modernc.org/sqlite":
                for arch in ("amd64", "arm64"):
                    relative = "lib/sqlite_linux_" + arch + ".go"
                    entry["files"].append(source_notice(base, relative, rb"The author disclaims copyright", target / ("SQLITE-PUBLIC-DOMAIN-linux-" + arch + ".txt"), output))
            entry["status"] = "collected" if entry["files"] else "missing_license_file"
        else:
            entry["status"] = "not_in_local_cache"
        entries.append(entry)
    for key, locked in sorted(lock["packages"].items()):
        if not key:
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        version = locked["version"]
        base = root / "web" / key
        entry = {"ecosystem": "npm", "name": name, "version": version, "scope": "development" if locked.get("dev") else "runtime", "lock_path": key, "license_summary": locked.get("license", "See original files"), "files": []}
        metadata = base / "package.json"
        if not metadata.is_file():
            entry["status"] = "not_installed_locally"
        else:
            installed = json.loads(metadata.read_text(encoding="utf-8"))
            if installed.get("name") != name or installed.get("version") != version:
                entry["status"] = "installed_version_mismatch"
            else:
                target = output / "npm" / (name + "@" + version)
                entry["files"] = copy_notices(base, target, output)
                if name == "qrcode":
                    entry["files"].append(source_notice(base, "lib/core/qrcode.js", rb"Kazuhiko Arase", target / "SOURCE-COPYRIGHT-qrcode.txt", output))
                entry["status"] = "collected" if entry["files"] else "missing_license_file"
        entries.append(entry)
    if args.goroot:
        go_version = (args.goroot / "VERSION").read_text(encoding="utf-8").splitlines()[0]
        entry = {"ecosystem": "go-toolchain", "name": "Go runtime and standard library", "version": go_version, "scope": "runtime", "license_summary": "BSD-3-Clause; PATENTS", "files": []}
        for name in ("LICENSE", "PATENTS"):
            source = args.goroot / name
            if source.is_file():
                data = source.read_bytes()
                destination = output / "go-toolchain" / go_version / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                entry["files"].append({"source": name, "file": destination.relative_to(output).as_posix(), "sha256": sha256(data), "bytes": len(data)})
        entry["status"] = "collected" if entry["files"] else "missing_license_file"
        entries.append(entry)
    required = [e for e in entries if e["ecosystem"] == "go" or (e["ecosystem"] == "npm" and e["scope"] == "runtime")]
    missing = [{"ecosystem": e["ecosystem"], "name": e["name"], "version": e["version"], "status": e["status"]} for e in entries if e["status"] != "collected"]
    manifest = {"schema_version": 1, "project_version": "0.2.2", "method": "Byte-for-byte copies from exact go.mod versions in the local Go module cache and exact package-lock versions in web/node_modules; no downloads or package execution.", "scope_note": "All go.mod requirements and the full non-dev npm lock graph are included conservatively; this is not a symbol-level or tree-shaken bundle inventory. Development packages are supplementary. Nested node_modules and testdata are not scanned as part of their parent packages. Embedded per-source notices may need separate review.", "inputs": {"go.mod": sha256(go_mod.read_bytes()), "web/package-lock.json": sha256(npm_lock.read_bytes())}, "summary": {"go_modules": sum(e["ecosystem"] == "go" for e in entries), "npm_runtime_packages": sum(e["ecosystem"] == "npm" and e["scope"] == "runtime" for e in entries), "npm_development_packages": sum(e["ecosystem"] == "npm" and e["scope"] == "development" for e in entries), "collected_components": sum(e["status"] == "collected" for e in entries), "copied_files": sum(len(e["files"]) for e in entries), "required_components_without_files": sum(e["status"] != "collected" for e in required)}, "uncovered_components": missing, "components": entries}
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest["summary"], ensure_ascii=False))
    print("Uncovered components:", len(missing), "(see licenses/manifest.json)")
    return 1 if manifest["summary"]["required_components_without_files"] else 0


if __name__ == "__main__":
    sys.exit(main())
