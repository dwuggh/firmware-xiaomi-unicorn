"""No device access: synthetic FAT metadata and optional local OEM input."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from firmware_extractor import cli
from firmware_extractor.fat import Fat16
from test_fat import Volume, long_entries, short_entry


class WorkflowTests(unittest.TestCase):
    def test_long_name_resolves_to_real_alias(self):
        volume = Volume()
        entry = short_entry("AMSS20~1.BIN", 2, 4)
        volume.put_root(*long_entries("amss20.bin", entry), entry)
        volume.set_fat(2, 0xffff)
        volume.put_cluster(2, b"test")
        reader = volume.reader()
        self.assertEqual(cli.resolve_fat_path(reader, "amss20.bin"), "AMSS20~1.BIN")
        self.assertEqual(reader.read_file("AMSS20~1.BIN"), b"test")

    def test_changed_firmware_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA256 differs"):
            cli.check_blob({"path": "test", "bytes": 4, "sha256": "0" * 64}, b"test")

    def test_vendor_symlink_cannot_escape_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vendor = root / "vendor"
            (vendor / "firmware").mkdir(parents=True)
            (root / "private").write_bytes(b"test")
            (vendor / "firmware/file").symlink_to(root / "private")
            with self.assertRaisesRegex(ValueError, "escapes"):
                cli.vendor_file(vendor, {"origin": "/vendor/firmware/file", "bytes": 4})

    def test_local_image_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "modem.img"
            path.write_bytes(b"0123456789")
            with contextlib.closing(cli.LocalImage(path)) as image:
                self.assertEqual(image.read_at(3, 4), b"3456")
                with self.assertRaisesRegex(ValueError, "outside"):
                    image.read_at(8, 4)

    def test_ssh_reads_selected_slot_without_device_writes(self):
        with patch("firmware_extractor.cli.subprocess.check_output",
                   side_effect=[b"100\n", b"test"]) as run:
            image = cli.PhoneImage("root@unicorn", "b")
            self.assertEqual(image.read_at(3, 4), b"test")
            commands = [call.args[0] for call in run.call_args_list]
            for command in commands:
                self.assertIn("root@unicorn", command)
                self.assertIn("modem_b", command[-1])
                self.assertIn("os.O_RDONLY", command[-1])
                self.assertNotIn("os.O_WRONLY", command[-1])
            self.assertIn("os.pread(fd,4,3)", commands[-1][-1])
            with self.assertRaisesRegex(ValueError, "outside"):
                image.read_at(99, 4)
            self.assertEqual(run.call_count, 2)

    @unittest.skipUnless(os.environ.get("UNICORN_TEST_INPUT") and shutil.which("zstd"),
                         "set UNICORN_TEST_INPUT to a private raw payload directory; zstd required")
    def test_extract_export_release_and_verify(self):
        """Extract from fresh FAT allocation, then validate reproducible zstd output."""
        from firmware_extractor.layout import read_payload
        original = Path(os.environ["UNICORN_TEST_INPUT"])
        raw, manifest, blobs = read_payload(original, cli.DEFAULT_MANIFEST)
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            modem, vendor = root / "modem.img", root / "vendor"
            build_modem(modem, manifest, blobs)
            for entry in manifest["files"]:
                if entry["origin"].startswith("/vendor/"):
                    path = vendor / entry["origin"].removeprefix("/vendor/")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(blobs[entry["path"]])
            payload = root / "payload"
            cli.main(["extract", "--modem-image", str(modem), "--vendor-dir", str(vendor),
                      "--source-id", "synthetic-layout-test", "--output", str(payload)])
            report = json.loads((payload / "extraction-report.json").read_text())
            self.assertEqual(len(report["files"]), 61)
            entry = next(e for e in manifest["files"] if "partition_extents" in e)
            extracted = next(e for e in report["files"] if e["path"] == entry["path"])
            self.assertNotEqual(entry["partition_extents"], extracted["partition_extents"])
            linux = root / "linux"
            cli.main(["export", "--input", str(payload), "--version", "snapshot-20261113",
                      "--output", str(linux)])
            self.assertTrue((linux / "lib/firmware/qcom/a730_sqe.fw").is_file())
            for line in (linux / "SHA256SUMS").read_text().splitlines():
                expected, name = line.split("  ", 1)
                self.assertEqual(cli.digest((linux / name).read_bytes()), expected)
            outputs = []
            for name in ["first.tar.zst", "second.tar.zst"]:
                archive = root / name
                cli.main(["release", "--input", str(payload), "--version", "snapshot-20261113",
                          "--output", str(archive)])
                outputs.append(archive.read_bytes())
            self.assertEqual(outputs[0], outputs[1])
            expected = json.loads((cli.ROOT / "archive.json").read_text())
            self.assertEqual(cli.digest(outputs[0]), expected["sha256"])
            verified = root / "verified"
            cli.main(["verify", "--archive", str(archive), "--output", str(verified)])
            for path in linux.rglob("*"):
                if path.is_file():
                    self.assertEqual(path.read_bytes(), (verified / path.relative_to(linux)).read_bytes())
            # Recomputed package checksums must not hide changed pinned firmware.
            bad_file = verified / "lib/firmware/qcom/a730_sqe.fw"
            data = bytearray(bad_file.read_bytes()); data[-1] ^= 1
            bad_file.write_bytes(data)
            sums = []
            for path in sorted(verified.rglob("*")):
                if path.is_file() and path.name != "SHA256SUMS":
                    sums.append(f"{cli.digest(path.read_bytes())}  {path.relative_to(verified)}\n")
            (verified / "SHA256SUMS").write_text("".join(sums))
            bad_tar = root / "bad.tar"
            with tarfile.open(bad_tar, "w") as stream:
                for path in sorted(verified.rglob("*")):
                    if path.is_file():
                        stream.add(path, arcname=str(path.relative_to(verified)), recursive=False)
            bad_archive = root / "bad.tar.zst"
            with bad_tar.open("rb") as source, bad_archive.open("wb") as destination:
                subprocess.run(["zstd", "-q", "-c"], stdin=source, stdout=destination, check=True)
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                cli.main(["verify", "--archive", str(bad_archive)])
            changed = payload / manifest["files"][0]["path"]
            changed.write_bytes(b"changed")
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                cli.main(["release", "--input", str(payload), "--version", "test",
                          "--output", str(root / "failed.tar.zst")])
            self.assertFalse((root / "failed.tar.zst").exists())


def build_modem(path, manifest, blobs):
    """FAT16 fixture uses fresh allocation and long-name aliases, not recorded offsets."""
    sector, cluster, count = 512, 16384, 4090
    fat_bytes, root_bytes = 8192, 16384
    root_offset = sector + 2 * fat_bytes
    data_offset = root_offset + root_bytes
    size = data_offset + count * cluster
    boot = bytearray(sector)
    struct.pack_into("<HBHBHHBHHHII", boot, 11,
                     sector, cluster // sector, 1, 2, 512, 0, 0xf8, fat_bytes // sector,
                     63, 255, 0, size // sector)
    boot[510:512] = b"\x55\xaa"
    fat = bytearray(fat_bytes)
    for n, value in [(0, 0xfff8), (1, 0xffff), (2, 0xffff), (3, 0xffff)]:
        struct.pack_into("<H", fat, n * 2, value)
    directories = {"image": bytearray(), "image/qca6490": bytearray()}
    directories["image"] += short_entry("QCA6490", 3, attr=0x10)
    next_cluster = 4
    with path.open("wb") as stream:
        stream.truncate(size)
        stream.write(boot)
        stream.seek(root_offset)
        stream.write(short_entry("IMAGE", 2, attr=0x10))
        for index, entry in enumerate(reversed(manifest["files"])):
            if not entry["origin"].startswith("modem_a:"):
                continue
            logical = Path(entry["origin"].split(":", 1)[1])
            data = blobs[entry["path"]]
            needed = (len(data) + cluster - 1) // cluster
            alias = f"F{index:07d}.DAT"
            record = short_entry(alias, next_cluster, len(data))
            directories[str(logical.parent)] += b"".join(long_entries(logical.name, record)) + record
            for n in range(next_cluster, next_cluster + needed):
                struct.pack_into("<H", fat, n * 2,
                                 0xffff if n == next_cluster + needed - 1 else n + 1)
            stream.seek(data_offset + (next_cluster - 2) * cluster)
            stream.write(data)
            next_cluster += needed
        for copy in range(2):
            stream.seek(sector + copy * fat_bytes)
            stream.write(fat)
        for n, contents in enumerate(directories.values(), 2):
            assert len(contents) < cluster
            stream.seek(data_offset + (n - 2) * cluster)
            stream.write(contents)


if __name__ == "__main__":
    unittest.main()
