"""Extract a pinned Unicorn firmware set without mounting or writing devices."""

import argparse
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile

from .fat import Fat16
from .layout import assemble

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "share/unicorn-firmware/manifest.json"
MAX_INPUT = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_profile(path):
    raw = path.read_bytes()
    manifest = json.loads(raw)
    require(manifest.get("schema") == 1 and manifest.get("device") == "xiaomi,unicorn",
            "only the Unicorn schema-1 profile is supported")
    files = manifest["files"]
    require(len(files) == 61, "expected the pinned 61-file Unicorn set")
    names = set()
    for entry in files:
        name = entry["path"]
        p = PurePosixPath(name)
        require(not p.is_absolute() and ".." not in p.parts and str(p) == name,
                "unsafe or noncanonical manifest path")
        require(name not in names and name.startswith(("firmware/", "wlan/")),
                "duplicate or unexpected manifest path")
        require(type(entry["bytes"]) is int and 0 < entry["bytes"] <= MAX_INPUT,
                "invalid firmware size")
        require(re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), "invalid firmware hash")
        origin = entry["origin"]
        require(origin.startswith(("/vendor/firmware/", "modem_a:image/")),
                "unsupported firmware origin")
        source = PurePosixPath(origin.removeprefix("modem_a:") if origin.startswith("modem_a:")
                               else origin.removeprefix("/vendor/"))
        require(".." not in source.parts and not source.is_absolute(), "unsafe source path")
        names.add(name)
    return raw, manifest


def check_blob(entry, data):
    require(len(data) == entry["bytes"], f"{entry['path']}: size differs from pinned profile")
    require(digest(data) == entry["sha256"],
            f"{entry['path']}: SHA256 differs; this source needs a separately reviewed profile")


class LocalImage:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            st = os.fstat(self.fd)
            require(stat.S_ISREG(st.st_mode) or stat.S_ISBLK(st.st_mode),
                    "modem input must be a raw image or block device")
            self.size = (struct.unpack("Q", fcntl.ioctl(self.fd, 0x80081272, bytes(8)))[0]
                         if stat.S_ISBLK(st.st_mode) else st.st_size)
        except BaseException:
            os.close(self.fd)
            raise

    def read_at(self, offset, length):
        require(0 <= offset <= self.size and 0 <= length <= self.size - offset,
                "read outside modem input")
        data = os.pread(self.fd, length, offset)
        require(len(data) == length, "short read from modem input")
        return data

    def close(self):
        os.close(self.fd)


class PhoneImage:
    """Bounded reads over SSH. All remote device opens use O_RDONLY."""

    def __init__(self, host, slot):
        require(re.fullmatch(r"[A-Za-z0-9_.@-]+", host) and not host.startswith("-"),
                "invalid SSH hostname")
        self.host = host
        self.path = f"/dev/disk/by-partlabel/modem_{slot}"
        self.size = int(self._run(
            "import fcntl,os,struct; "
            f"fd=os.open({self.path!r},os.O_RDONLY); "
            "print(struct.unpack('Q',fcntl.ioctl(fd,0x80081272,bytes(8)))[0])"))

    def _run(self, program):
        return subprocess.check_output(
            ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", self.host,
             "python3 -c " + shlex.quote(program)], timeout=60)

    def read_at(self, offset, length):
        require(0 <= offset <= self.size and 0 <= length <= min(MAX_INPUT, self.size - offset),
                "read outside modem partition")
        data = self._run("import os,sys; "
                         f"fd=os.open({self.path!r},os.O_RDONLY); "
                         f"sys.stdout.buffer.write(os.pread(fd,{length},{offset}))")
        require(len(data) == length, "short SSH modem read")
        return data

    def close(self):
        pass


def resolve_fat_path(volume, logical):
    """Resolve validated VFAT display names to the actual short aliases."""
    current = ""
    for component in PurePosixPath(logical).parts:
        matches = [entry for entry in volume.list_dir(current)
                   if component.casefold() in
                   {entry["name"].casefold(), entry.get("long_name", "").casefold()}]
        require(len(matches) == 1, f"missing or ambiguous FAT component: {logical}")
        current = "/".join(filter(None, [current, matches[0]["name"]]))
    return current


def vendor_file(root, entry):
    root = root.resolve(strict=True)
    source = root / entry["origin"].removeprefix("/vendor/")
    resolved = source.resolve(strict=True)
    require(resolved.is_relative_to(root), "vendor file symlink escapes input directory")
    require(resolved.is_file(), "vendor source must be a regular file")
    with resolved.open("rb") as stream:
        return stream.read(entry["bytes"] + 1)


def extract(args):
    raw, manifest = read_profile(args.manifest)
    require(not args.output.exists(), "output exists; choose a new directory")
    image = (PhoneImage(args.phone, args.slot) if args.phone else LocalImage(args.modem_image))
    report = {"schema": 1, "source_id": args.source_id,
              "source_kind": "phone-ssh" if args.phone else "raw-modem-image",
              "profile_sha256": digest(raw), "files": []}
    if args.phone:
        report["partition"] = f"modem_{args.slot}"
    blobs = {}
    with contextlib.closing(image):
        volume = Fat16(image.read_at, image.size)
        report["modem_partition_bytes"] = image.size
        report["fat_geometry"] = volume.geometry
        for entry in manifest["files"]:
            record = {"path": entry["path"], "reference_origin": entry["origin"]}
            if entry["origin"].startswith("modem_a:"):
                logical = entry["origin"].split(":", 1)[1]
                record["origin"] = (f"modem_{args.slot}:" if args.phone else "modem-image:") + logical
                short = resolve_fat_path(volume, logical)
                data = volume.read_file(short)
                record.update(fat_path=short, partition_extents=volume.file_extents(short))
            else:
                record["origin"] = entry["origin"]
                data = vendor_file(args.vendor_dir, entry)
            check_blob(entry, data)
            blobs[entry["path"]] = data
            record.update(bytes=len(data), sha256=digest(data))
            report["files"].append(record)
    # Validate all inputs before writing output; never leave a partial final tree.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".extract-", dir=args.output.parent) as temporary:
        stage = Path(temporary) / "payload"
        stage.mkdir(mode=0o700)
        for name, data in blobs.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (stage / "manifest.json").write_bytes(raw)
        (stage / "extraction-report.json").write_text(json.dumps(report, indent=2) + "\n")
        stage.rename(args.output)
    print(f"Extracted and verified {len(blobs)} files into {args.output}")


def verify(args):
    from .runtime import verify_runtime, read_directory
    read_profile(args.manifest)
    if args.output:
        require(not args.output.exists(), "verification output already exists")
    if not args.archive:
        files = read_directory(args.tree, args.manifest)
        if args.output:
            version = json.loads(files["share/unicorn-firmware/source.json"])["version"]
            repository_tree(args.tree, args.manifest, args.output, version)
        print("Verified repository firmware, metadata and SHA256SUMS.")
        return
    with tempfile.TemporaryDirectory(prefix="firmware-verify-") as temporary:
        tree = Path(temporary) / "payload"
        verify_runtime(args.archive, args.manifest, tree)
        if args.output:
            shutil.copytree(tree, args.output)
    print("Verified zstd runtime archive and pinned firmware contents.")


def linux_tree(input_directory, manifest, output, version):
    """Generate a Linux runtime tree with a top-level checksum manifest."""
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", version),
            "version must be a simple snapshot or ROM version label")
    raw, _ = read_profile(manifest)
    assemble(input_directory, manifest, output)
    metadata = {"schema": 1, "device": "xiaomi,unicorn", "version": version,
                "profile_sha256": digest(raw), "redistribution_reviewed": False,
                "scope": "GPU, ADSP, SLPI, WLAN; no Bluetooth, factory identities or speaker calibration"}
    (output / "share/unicorn-firmware/source.json").write_text(
        json.dumps(metadata, indent=2) + "\n")
    finish_tree(output, version)


def finish_tree(output, version):
    (output / "README.md").write_text(
        "# Xiaomi 12S Pro (unicorn) runtime firmware\n\n"
        f"Snapshot label: {version}. This label is not proof of an official ROM build.\n\n"
        "The lib/firmware/ tree contains GPU, ADSP, SLPI and matching WLAN inputs.\n"
        "Bluetooth and Linux regulatory.db are supplied separately by the consumer.\n"
        "No factory identities, speaker calibration or partition flashing files are included.\n"
        "The original manifest and validation report are under share/unicorn-firmware/.\n"
        "Proprietary firmware retains its owners' rights; redistribution has not been reviewed.\n"
        "The MIT license of the extraction tools does not license these binaries.\n\n"
        "Verify all files from this directory: sha256sum -c SHA256SUMS\n")
    sums = []
    for path in sorted(output.rglob("*")):
        if path.is_file():
            sums.append(f"{digest(path.read_bytes())}  {path.relative_to(output).as_posix()}\n")
    (output / "SHA256SUMS").write_text("".join(sums))


def repository_tree(source, manifest, output, version):
    """Stage only validated runtime files; repository docs and tools stay out."""
    from .runtime import read_directory
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", version),
            "version must be a simple snapshot or ROM version label")
    files = read_directory(source, manifest)
    metadata = json.loads(files["share/unicorn-firmware/source.json"])
    require(metadata["version"] == version, "release version differs from repository source metadata")
    output.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    finish_tree(output, version)


def export(args):
    require(not args.output.exists(), "Linux tree output already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".export-", dir=args.output.parent) as temporary:
        stage = Path(temporary) / "payload"
        linux_tree(args.input, args.manifest, stage, args.version)
        stage.rename(args.output)
    print(f"Linux runtime payload and SHA256SUMS: {args.output}")


def release(args):
    require(not args.output.exists(), "release archive already exists")
    require(args.output.name.endswith(".tar.zst"), "release output must end in .tar.zst")
    require(shutil.which("zstd") is not None, "release packaging requires the zstd executable")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".release-", dir=args.output.parent) as temporary:
        temporary = Path(temporary)
        tree = temporary / "payload"
        if args.input:
            linux_tree(args.input, args.manifest, tree, args.version)
        else:
            repository_tree(args.tree, args.manifest, tree, args.version)
        tar = temporary / "payload.tar"
        with tarfile.open(tar, "w", format=tarfile.USTAR_FORMAT) as stream:
            for path in sorted(tree.rglob("*")):
                if path.is_file():
                    data = path.read_bytes()
                    info = tarfile.TarInfo(path.relative_to(tree).as_posix())
                    info.mode, info.mtime, info.size = 0o644, 0, len(data)
                    stream.addfile(info, io.BytesIO(data))
        compressed = temporary / "payload.tar.zst"
        with tar.open("rb") as source, compressed.open("xb") as destination:
            subprocess.run(["zstd", "-q", "-T1", "-10", "-c"],
                           stdin=source, stdout=destination, check=True)
        metadata = {"file": args.output.name, "version": args.version,
                    "bytes": compressed.stat().st_size,
                    "sha256": digest(compressed.read_bytes()), "redistribution_reviewed": False}
        compressed.rename(args.output)
    print(json.dumps(metadata, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("extract", help="extract pinned files from FAT16 modem and vendor tree")
    source = command.add_mutually_exclusive_group(required=True)
    source.add_argument("--modem-image", type=Path, help="raw modem image or read-only block input")
    source.add_argument("--phone", help="SSH alias for a phone with root access and Python 3")
    command.add_argument("--slot", choices=["a", "b"], default="a", help="phone modem slot (default: a)")
    command.add_argument("--vendor-dir", required=True, type=Path,
                         help="extracted vendor root containing firmware/ (not a vendor image)")
    command.add_argument("--source-id", required=True,
                         help="operator-supplied ROM build/version or phone firmware provenance")
    command.add_argument("--output", required=True, type=Path)
    command.set_defaults(func=extract)
    command = sub.add_parser("verify", help="validate repository firmware or a zstd runtime archive")
    source = command.add_mutually_exclusive_group()
    source.add_argument("--archive", type=Path, help="zstd runtime archive")
    source.add_argument("--tree", type=Path, default=ROOT, help="runtime repository (default: this checkout)")
    command.add_argument("--output", type=Path, help="optional new verified runtime directory")
    command.set_defaults(func=verify)
    command = sub.add_parser("export", help="generate a Linux lib/firmware tree and SHA256SUMS")
    command.add_argument("--input", required=True, type=Path, help="verified raw payload directory")
    command.add_argument("--version", required=True, help="explicit ROM or historical snapshot label")
    command.add_argument("--output", required=True, type=Path, help="new payload directory")
    command.set_defaults(func=export)
    command = sub.add_parser("release", help="package repository firmware as tar.zst; does not upload")
    source = command.add_mutually_exclusive_group()
    source.add_argument("--input", type=Path, help="optional raw payload directory instead of repository firmware")
    source.add_argument("--tree", type=Path, default=ROOT, help="runtime repository (default: this checkout)")
    command.add_argument("--version", required=True)
    command.add_argument("--output", required=True, type=Path)
    command.set_defaults(func=release)
    for command in sub.choices.values():
        command.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        args.func(args)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, f"error: {error}\n")
    return 0
