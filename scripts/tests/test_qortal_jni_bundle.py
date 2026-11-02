import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "qortal_jni_bundle", Path(__file__).parents[1] / "qortal_jni_bundle.py"
)
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)


def native_header(target):
    data = bytearray(128)
    if "linux" in target:
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 18, 183 if target.startswith("aarch64") else 62)
    elif "apple" in target:
        data[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", data, 4, 0x0100000C if target.startswith("aarch64") else 0x01000007)
    else:
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 64)
        data[64:68] = b"PE\x00\x00"
        struct.pack_into("<H", data, 68, 0x8664)
        struct.pack_into("<H", data, 88, 0x20B)
    return bytes(data)


class QortalJniBundleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        self.artifacts = self.base / "artifacts"
        self.identity = {"commit": "a" * 40, "repository": "owner/wallet",
                         "run_id": "123", "version": "0.3.9"}
        for name, source in BUNDLE.SHARED.items():
            path = self.root / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"shared source: {name}\n")
        for target, name in BUNDLE.LIBRARIES.items():
            directory = self.directory(target)
            directory.mkdir(parents=True)
            (directory / name).write_bytes(native_header(target))
            for shared, source in BUNDLE.SHARED.items():
                (directory / shared).write_bytes((self.root / source).read_bytes())
            BUNDLE.write_record(directory, target, self.identity, self.root)

    def directory(self, target):
        return self.artifacts / f"qortal-jni-native-{target}"

    def bundle(self, output="bundle"):
        return BUNDLE.create_bundle(self.artifacts, self.base / output, self.identity, self.root)

    def test_complete_bundle_contains_all_libraries_and_verified_checksums(self):
        archive = self.bundle()
        with zipfile.ZipFile(archive) as zipped:
            self.assertEqual(set(zipped.namelist()),
                             set(BUNDLE.LIBRARIES.values()) | set(BUNDLE.SHARED)
                             | {"SHA256SUMS", "qortal-jni-manifest.json"})
            self.assertIsNone(zipped.testzip())
            for line in zipped.read("SHA256SUMS").decode().splitlines():
                digest, name = line.split("  ", 1)
                import hashlib
                self.assertEqual(digest, hashlib.sha256(zipped.read(name)).hexdigest())
            manifest = json.loads(zipped.read("qortal-jni-manifest.json"))
            self.assertEqual(manifest["commit"], self.identity["commit"])
            self.assertEqual(len(manifest["platforms"]), 5)
        self.assertEqual(archive.with_suffix(".zip.sha256").read_text().split()[0],
                         BUNDLE.sha256(archive))

    def test_missing_platform_fails_instead_of_creating_partial_archive(self):
        target = next(iter(BUNDLE.LIBRARIES))
        (self.directory(target) / BUNDLE.LIBRARIES[target]).unlink()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.bundle()
        self.assertFalse((self.base / "bundle").exists())

    def test_modified_binary_is_rejected_even_when_architecture_is_valid(self):
        target = next(iter(BUNDLE.LIBRARIES))
        with (self.directory(target) / BUNDLE.LIBRARIES[target]).open("ab") as stream:
            stream.write(b"tampered")
        with self.assertRaisesRegex(ValueError, "provenance or checksums"):
            self.bundle()

    def test_different_commit_repository_or_run_is_rejected(self):
        target = next(iter(BUNDLE.LIBRARIES))
        path = self.directory(target) / BUNDLE.RECORD
        original = path.read_text()
        for field in ("commit", "repository", "run_id", "version"):
            with self.subTest(field=field):
                record = json.loads(original)
                record[field] = "different"
                path.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, "provenance or checksums"):
                    self.bundle()
        path.write_text(original)

    def test_wrong_architecture_is_rejected_before_recording(self):
        target = "aarch64-unknown-linux-gnu"
        (self.directory(target) / BUNDLE.LIBRARIES[target]).write_bytes(
            native_header("x86_64-unknown-linux-gnu"))
        with self.assertRaisesRegex(ValueError, "architecture"):
            BUNDLE.write_record(self.directory(target), target, self.identity, self.root)

    def test_duplicate_libraries_are_rejected(self):
        target = next(iter(BUNDLE.LIBRARIES))
        duplicate = self.directory(target) / "duplicate"
        duplicate.mkdir()
        (duplicate / BUNDLE.LIBRARIES[target]).write_bytes(native_header(target))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.bundle()

    def test_wrapper_must_match_checked_out_source(self):
        target = next(iter(BUNDLE.LIBRARIES))
        (self.directory(target) / "LiteWalletJni.java").write_text("stale wrapper")
        with self.assertRaisesRegex(ValueError, "Shared source file"):
            self.bundle()

    def test_same_inputs_produce_same_zip(self):
        self.assertEqual(BUNDLE.sha256(self.bundle("first")),
                         BUNDLE.sha256(self.bundle("second")))


if __name__ == "__main__":
    unittest.main()
