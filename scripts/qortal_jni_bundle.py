#!/usr/bin/env python3
"""Smoke-test and package the five desktop Qortal JNI libraries from one commit."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import tempfile
import tomllib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LIBRARIES = {
    "x86_64-unknown-linux-gnu": "librust-linux-x86_64.so",
    "aarch64-unknown-linux-gnu": "librust-linux-aarch64.so",
    "x86_64-pc-windows-msvc": "librust-windows-x86_64.dll",
    "x86_64-apple-darwin": "librust-macos-x86_64.dylib",
    "aarch64-apple-darwin": "librust-macos-aarch64.dylib",
}
SHARED = {
    "LiteWalletJni.java": "bindings/qortal-jni/src/main/java/com/rust/litewalletjni/LiteWalletJni.java",
    "qortal-handoff.md": "docs/qortal-handoff.md",
    "LICENSE-qortal-jni.txt": "LICENSE-MIT",
}
RECORD = "qortal-jni-build.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unique_file(directory: Path, name: str) -> Path:
    matches = list(directory.rglob(name))
    if len(matches) != 1 or not matches[0].is_file() or matches[0].is_symlink():
        raise ValueError(f"Expected exactly one regular {name} in {directory}")
    return matches[0]


def verify_architecture(path: Path, target: str) -> None:
    with path.open("rb") as stream:
        header = stream.read(64)
        if "linux" in target:
            machine = 183 if target.startswith("aarch64") else 62
            valid = (len(header) == 64 and header[:6] == b"\x7fELF\x02\x01"
                     and struct.unpack_from("<H", header, 18)[0] == machine)
        elif "apple" in target:
            cpu = 0x0100000C if target.startswith("aarch64") else 0x01000007
            valid = (len(header) == 64 and header[:4] == b"\xcf\xfa\xed\xfe"
                     and struct.unpack_from("<I", header, 4)[0] == cpu)
        else:
            valid = False
            if len(header) == 64 and header[:2] == b"MZ":
                stream.seek(struct.unpack_from("<I", header, 60)[0])
                pe = stream.read(26)
                valid = (len(pe) == 26 and pe[:4] == b"PE\x00\x00"
                         and struct.unpack_from("<H", pe, 4)[0] == 0x8664
                         and struct.unpack_from("<H", pe, 24)[0] == 0x20B)
    if not valid:
        raise ValueError(f"Native binary format/architecture does not match {target}: {path}")


def payload(directory: Path, target: str, root: Path) -> dict[str, Path]:
    library = LIBRARIES[target]
    for other in LIBRARIES.values():
        if other != library and list(directory.rglob(other)):
            raise ValueError(f"Unexpected native library {other} in {directory}")
    files = {name: unique_file(directory, name) for name in [library, *SHARED]}
    verify_architecture(files[library], target)
    for name, source in SHARED.items():
        if sha256(files[name]) != sha256(root / source):
            raise ValueError(f"Shared source file does not match this checkout: {name}")
    return files


def build_record(directory: Path, target: str, identity: dict, root: Path = ROOT) -> dict:
    files = payload(directory, target, root)
    return {"schema": 1, **identity, "target": target,
            "files": {name: {"sha256": sha256(path), "size": path.stat().st_size}
                      for name, path in sorted(files.items())}}


def write_record(directory: Path, target: str, identity: dict, root: Path = ROOT) -> None:
    record = build_record(directory, target, identity, root)
    (directory / RECORD).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


def create_bundle(artifacts: Path, output: Path, identity: dict, root: Path = ROOT) -> Path:
    records = []
    files: dict[str, Path] = {}
    for target in LIBRARIES:
        directory = artifacts / f"qortal-jni-native-{target}"
        expected = build_record(directory, target, identity, root)
        actual = json.loads(unique_file(directory, RECORD).read_text())
        if actual != expected:
            raise ValueError(f"Build provenance or checksums do not match: {target}")
        records.append(actual)
        files.update(payload(directory, target, root))

    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"stashi-qortal-jni-{identity['version']}-{identity['commit'][:12]}.zip"
    if archive.exists():
        raise ValueError(f"Refusing to overwrite an existing archive: {archive}")
    manifest = {"schema": 1, **identity, "platforms": records,
                "workflow_url": f"https://github.com/{identity['repository']}/actions/runs/{identity['run_id']}"}
    with tempfile.TemporaryDirectory(prefix="qortal-jni-manifest-") as temp:
        manifest_path = Path(temp) / "qortal-jni-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        files[manifest_path.name] = manifest_path
        checksums = Path(temp) / "SHA256SUMS"
        checksums.write_text("".join(f"{sha256(path)}  {name}\n" for name, path in sorted(files.items())))
        files[checksums.name] = checksums
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zipped:
            for name, path in sorted(files.items()):
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                with path.open("rb") as source, zipped.open(entry, "w") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
        shutil.copyfile(manifest_path, output / manifest_path.name)
    archive.with_suffix(".zip.sha256").write_text(f"{sha256(archive)}  {archive.name}\n")
    return archive


def smoke(directory: Path, target: str) -> None:
    library = unique_file(directory.resolve(), LIBRARIES[target])
    verify_architecture(library, target)
    with tempfile.TemporaryDirectory(prefix="qortal-jni-smoke-") as temp:
        base = Path(temp)
        classes = base / "classes"
        classes.mkdir()
        subprocess.run(["javac", "-d", str(classes), str(ROOT / SHARED["LiteWalletJni.java"]),
                        str(ROOT / "bindings/qortal-jni/src/test/java/com/rust/litewalletjni/QortalJniSmoke.java")],
                       check=True, timeout=120)
        subprocess.run(["java", f"-Dqortal.jni.library={library}",
                        f"-Dqortal.jni.storage={base / 'wallet'}", "-cp", str(classes),
                        "com.rust.litewalletjni.QortalJniSmoke"], check=True, timeout=180)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["smoke", "record", "bundle"])
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--target", choices=LIBRARIES)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--repository")
    parser.add_argument("--run-id")
    args = parser.parse_args()
    if args.command in ("smoke", "record") and not args.target:
        parser.error("--target is required")
    if args.command == "smoke":
        smoke(args.directory, args.target)
        return
    if not args.commit or not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("--commit must be a full Git commit SHA")
    if not args.repository or not re.fullmatch(r"[\w.-]+/[\w.-]+", args.repository):
        parser.error("--repository must identify the build repository")
    if not args.run_id or not args.run_id.isdecimal():
        parser.error("--run-id must be a GitHub Actions run ID")
    actual_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if args.commit != actual_commit:
        parser.error("--commit does not match the checked-out source")
    if subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT).returncode:
        parser.error("Build provenance requires an unchanged source checkout")
    version = tomllib.loads((ROOT / "release-artifacts.toml").read_text())["qortal_jni"]["version"]
    identity = {"commit": args.commit, "repository": args.repository,
                "run_id": args.run_id, "version": version}
    if args.command == "record":
        write_record(args.directory, args.target, identity)
    else:
        if not args.output:
            parser.error("--output is required")
        print(create_bundle(args.directory, args.output, identity))


if __name__ == "__main__":
    main()
