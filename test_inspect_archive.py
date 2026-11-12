import contextlib
import io
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
import warnings
import zipfile

from inspect_archive import MIB, inspect, main


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.file = Path(temp.name) / "fixture.zip"

    def inspect(self, **options):
        with zipfile.ZipFile(self.file) as archive:
            return inspect(archive, **options)

    def test_normal_archive_lists_and_verifies(self):
        with zipfile.ZipFile(self.file, "w") as archive:
            archive.writestr("folder/", b"")
            archive.writestr("folder/file.txt", b"hello")
        report = self.inspect(verify=True)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["verification"]["status"], "passed")
        self.assertEqual(report["uncompressed_bytes"], 5)

    def test_path_hazards_and_windows_name_collision(self):
        with zipfile.ZipFile(self.file, "w") as archive:
            for name in ["../escape.txt", "/absolute.txt", "C:relative.txt", "NUL.txt", "x.txt", "X.txt"]:
                archive.writestr(name, b"a")
        # Windows zipfile normalizes backslashes when creating an archive.
        self.file.write_bytes(self.file.read_bytes().replace(b"../escape.txt", b"..\\escape.txt"))
        findings = {(item["code"], item["name"]) for item in self.inspect()["findings"]}
        self.assertIn(("unsafe-path", "..\\escape.txt"), findings)
        self.assertIn(("unsafe-path", "/absolute.txt"), findings)
        self.assertIn(("unsafe-path", "C:relative.txt"), findings)
        self.assertIn(("windows-name", "NUL.txt"), findings)
        self.assertIn(("path-collision", "X.txt"), findings)

    def test_unix_symlink_and_file_parent_detected(self):
        link = zipfile.ZipInfo("outside")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.file, "w") as archive:
            archive.writestr(link, "../outside")
            archive.writestr("outside/file.txt", "payload")
        self.assertEqual({item["code"] for item in self.inspect()["findings"]}, {"symlink", "file-parent"})

    def test_verification_respects_limit_and_reports_high_ratio(self):
        with zipfile.ZipFile(self.file, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("zeros.bin", b"\0" * (2 * MIB))
        report = self.inspect(verify=True, max_bytes=MIB)
        self.assertEqual(report["findings"][0]["code"], "high-ratio")
        self.assertEqual(report["verification"]["status"], "skipped")

    def test_crc_mismatch_is_an_error(self):
        payload = b"recognizable data"
        with zipfile.ZipFile(self.file, "w") as archive:
            archive.writestr("file.txt", payload)
        original = self.file.read_bytes()
        self.assertIn(payload, original)
        self.file.write_bytes(original.replace(payload, b"X" * len(payload), 1))
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(main([str(self.file), "--verify"]), 2)
        self.assertIn("CRC", errors.getvalue())

    def test_crc_verifies_earlier_entry_when_names_repeat(self):
        with warnings.catch_warnings(), zipfile.ZipFile(self.file, "w") as archive:
            warnings.simplefilter("ignore", UserWarning)
            archive.writestr("file.txt", b"first payload")
            archive.writestr("file.txt", b"second payload")
        self.file.write_bytes(self.file.read_bytes().replace(b"first payload", b"other payload", 1))
        with self.assertRaises(zipfile.BadZipFile):
            self.inspect(verify=True)

    def test_non_zip_is_an_error(self):
        self.file.write_bytes(b"not a zip")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.file)]), 2)
