"""Verify the zstd runtime package against both checksums and OEM input hashes."""

import hashlib
import json
from pathlib import PurePosixPath
import struct
import subprocess
import tarfile
import tempfile

from .layout import element, require, validate_mdt

WLAN = "lib/firmware/ath11k/WCN6855/hw2.1/"


def records(data):
    result = []
    offset = 0
    while offset < len(data):
        require(offset + 8 <= len(data), "truncated board record")
        tag, length = struct.unpack_from("<II", data, offset)
        start = offset + 8
        end = start + length
        padded = end + (-length % 4)
        require(padded <= len(data) and not any(data[end:padded]), "invalid board record length/padding")
        result.append((tag, data[start:end]))
        offset = padded
    return result


def check_contents(files, manifest_bytes):
    manifest = json.loads(manifest_bytes)
    require(files["share/unicorn-firmware/manifest.json"] == manifest_bytes,
            "runtime manifest differs from pinned manifest")
    board = files[WLAN + "board-2.bin"]
    magic = b"QCA-ATH11K-BOARD\0"
    header = magic + b"\0" * (-len(magic) % 4)
    require(board.startswith(header), "invalid board file magic/padding")
    outer = records(board[len(header):])
    require([tag for tag, _ in outer] == [0, 1], "unexpected board records")
    payloads = []
    key = manifest["wlan"]["board_key"].encode("ascii")
    for _, data in outer:
        inner = records(data)
        require([tag for tag, _ in inner] == [0, 1] and inner[0][1] == key,
                "board key differs from pinned manifest")
        payloads.append(inner[1][1])
    canonical = header + b"".join(element(tag, element(0, key) + element(1, data))
                                  for tag, data in enumerate(payloads))
    require(board == canonical, "noncanonical board file")
    require(payloads[1] == files[WLAN + "regdb.bin"], "board and standalone REGDB differ")
    raw = {}
    for entry in manifest["files"]:
        name = entry["path"]
        if name.startswith("firmware/"):
            data = files["lib/" + name]
        elif name == "wlan/bd_l2sgf.elf":
            data = payloads[0]
        else:
            target = {"wlan/amss20.bin": "amss.bin", "wlan/m3.bin": "m3.bin",
                      "wlan/regdb_xiaomi.bin": "regdb.bin"}[name]
            data = files[WLAN + target]
        require(len(data) == entry["bytes"] and hashlib.sha256(data).hexdigest() == entry["sha256"],
                f"{name}: runtime bytes differ from pinned input")
        raw[name] = data
    for name in sorted(raw):
        if name.endswith(".mdt"):
            validate_mdt(name, raw)


def payload_paths(manifest):
    expected = {"lib/" + entry["path"] for entry in manifest["files"]
                if entry["path"].startswith("firmware/")}
    expected |= {WLAN + name for name in ["amss.bin", "m3.bin", "regdb.bin", "board-2.bin"]}
    expected |= {"share/unicorn-firmware/manifest.json",
                 "share/unicorn-firmware/validation.json", "share/unicorn-firmware/source.json"}
    return expected


def read_directory(directory, manifest_path):
    """Validate the committed runtime tree, including its exact file set."""
    root = directory.resolve(strict=True)
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    expected = payload_paths(manifest)
    actual = set()
    for subdirectory in ["lib/firmware", "share/unicorn-firmware"]:
        base = root / subdirectory
        current = root
        for component in PurePosixPath(subdirectory).parts:
            current = current / component
            require(current.is_dir() and not current.is_symlink(),
                    "missing or symlinked runtime directory")
        for path in base.rglob("*"):
            require(not path.is_symlink(), "symlinks are not allowed in the runtime tree")
            if path.is_file():
                actual.add(path.relative_to(root).as_posix())
            else:
                require(path.is_dir(), "nonregular runtime entry")
    require(actual == expected, "runtime directory file set differs from expected layout")
    files = {}
    for name in sorted(expected):
        path = root / name
        require(path.resolve(strict=True).is_relative_to(root), "runtime file escapes repository")
        require(path.stat().st_size <= 64 * 1024 * 1024, "runtime file exceeds size limit")
        files[name] = path.read_bytes()
    checksum_path = root / "SHA256SUMS"
    require(checksum_path.is_file() and not checksum_path.is_symlink(), "missing or symlinked SHA256SUMS")
    checksums = {}
    for line in checksum_path.read_text().splitlines():
        checksum, name = line.split("  ", 1)
        require(name not in checksums, "duplicate checksum path")
        checksums[name] = checksum
    require(set(checksums) == expected, "checksum file set differs")
    for name, checksum in checksums.items():
        require(hashlib.sha256(files[name]).hexdigest() == checksum, f"{name}: checksum mismatch")
    check_contents(files, manifest_bytes)
    source = json.loads(files["share/unicorn-firmware/source.json"])
    require(source["device"] == "xiaomi,unicorn"
            and source["profile_sha256"] == hashlib.sha256(manifest_bytes).hexdigest(),
            "source metadata differs from pinned profile")
    return files


def verify_runtime(archive, manifest_path, output):
    require(archive.name.endswith(".tar.zst"), "only .tar.zst runtime archives are supported")
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    expected = payload_paths(manifest) | {"README.md", "SHA256SUMS"}
    with tempfile.TemporaryFile() as uncompressed:
        subprocess.run(["zstd", "-q", "-d", "-c", "--", str(archive)],
                       stdout=uncompressed, check=True)
        uncompressed.seek(0)
        with tarfile.open(fileobj=uncompressed, mode="r:") as stream:
            members = stream.getmembers()
            names = [member.name for member in members]
            require(len(names) == len(set(names)) and set(names) == expected,
                    "runtime archive file set differs from expected layout")
            files = {}
            for member in members:
                path = PurePosixPath(member.name)
                require(member.isfile() and not path.is_absolute() and ".." not in path.parts,
                        "runtime archive contains unsafe entries")
                require(member.size <= 64 * 1024 * 1024, "runtime member exceeds size limit")
                files[member.name] = stream.extractfile(member).read()
    checksums = {}
    for line in files["SHA256SUMS"].decode("ascii").splitlines():
        checksum, name = line.split("  ", 1)
        require(name not in checksums, "duplicate checksum path")
        checksums[name] = checksum
    require(set(checksums) == set(files) - {"SHA256SUMS"}, "checksum file set differs")
    for name, checksum in checksums.items():
        require(hashlib.sha256(files[name]).hexdigest() == checksum, f"{name}: checksum mismatch")
    check_contents(files, manifest_bytes)
    output.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
