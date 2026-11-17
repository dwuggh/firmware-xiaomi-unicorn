"""Check published firmware and packaging without requiring raw ROM inputs."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from firmware_extractor import cli
from firmware_extractor.runtime import read_directory


class RepositoryTests(unittest.TestCase):
    def copy_payload(self, destination):
        for name in ['lib', 'share']:
            shutil.copytree(cli.ROOT / name, destination / name)
        shutil.copy(cli.ROOT / 'SHA256SUMS', destination / 'SHA256SUMS')

    def test_launcher_works_outside_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [sys.executable, str(cli.ROOT / 'tools/firmware.py'), 'verify'],
                cwd=temporary, capture_output=True, text=True, check=True)
            self.assertIn('Verified repository firmware', result.stdout)

    @unittest.skipUnless(shutil.which('zstd'), 'zstd is required for packaging')
    def test_release_from_checkout_matches_existing_consumer_pin(self):
        expected = json.loads((cli.ROOT / 'archive.json').read_text())
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            archive = root / expected['file']
            cli.main(['release', '--version', expected['version'], '--output', str(archive)])
            self.assertEqual(archive.stat().st_size, expected['bytes'])
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), expected['sha256'])
            verified = root / 'verified'
            cli.main(['verify', '--archive', str(archive), '--output', str(verified)])
            self.assertFalse((verified / 'tools').exists())
            self.assertFalse((verified / '.git').exists())
            self.assertNotEqual((verified / 'README.md').read_bytes(),
                                (cli.ROOT / 'README.md').read_bytes())
            for name, data in read_directory(cli.ROOT, cli.DEFAULT_MANIFEST).items():
                self.assertEqual((verified / name).read_bytes(), data)

    def test_extra_runtime_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_payload(root)
            (root / 'lib/firmware/unreviewed.bin').write_bytes(b'unreviewed')
            with self.assertRaisesRegex(ValueError, 'file set differs'):
                read_directory(root, cli.DEFAULT_MANIFEST)

    def test_recomputed_checksums_cannot_hide_changed_firmware(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_payload(root)
            name = 'lib/firmware/qcom/a730_sqe.fw'
            path = root / name
            data = bytearray(path.read_bytes())
            data[-1] ^= 1
            path.write_bytes(data)
            lines = (root / 'SHA256SUMS').read_text().splitlines()
            lines = [(hashlib.sha256(data).hexdigest() + '  ' + name)
                     if line.split('  ', 1)[1] == name else line for line in lines]
            (root / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
            with self.assertRaisesRegex(ValueError, 'runtime bytes differ from pinned input'):
                read_directory(root, cli.DEFAULT_MANIFEST)

    def test_symlinked_runtime_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'lib').symlink_to(cli.ROOT / 'lib', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlinked runtime directory'):
                read_directory(root, cli.DEFAULT_MANIFEST)

    def test_repository_version_cannot_be_relabelled(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'release version differs'):
                cli.repository_tree(cli.ROOT, cli.DEFAULT_MANIFEST,
                                    Path(temporary) / 'payload', 'unknown-ROM')


if __name__ == '__main__':
    unittest.main()
