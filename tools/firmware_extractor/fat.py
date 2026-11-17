"""Bounded, read-only FAT16 access through a caller-supplied byte reader.

API: Fat16(read_at, size), list_dir(path=""), read_file(path), file_extents(path).
read_at(offset, length) must return exactly those bytes, relative to the start
of the FAT volume. It must provide a stable view for this instance. This module
does not open devices/files, invoke programs, mount, extract, or write anything.

Format reference: Linux 067c5c24cef23d913b67eaaf71ae67e7169a6620,
include/uapi/linux/msdos_fs.h (BPB/directory layouts, attributes, limits) and
fs/fat/{inode,fatent,dir,cache,file,namei_vfat}.c and fat.h (geometry,
cluster traversal, preallocation, VFAT slots and short-alias checksum).

Only ASCII 8.3 paths are supported, with case-insensitive lookup and NT lowercase
flags for display. Validated VFAT names are optional long_name metadata; name
always remains the real short alias used for traversal. Invalid LFN sequences
are ignored, without associating their text with another entry. FAT12/FAT32,
long-name lookup, code-page short aliases and absolute/dot paths are rejected.
This intentionally strict reader rejects differing FAT copies, excess nonempty
file allocation, ambiguous names and malformed unrelated directory entries.
Allocated empty files are supported; their bounded chain is checked on read.
Unlike Linux's compatibility-oriented mount path, bad-cluster markers and a
truncated FAT are rejected rather than treated as EOF or a smaller volume.
Limits: files 64 MiB, directories 2 MiB, metadata FAT 128 KiB per copy, individual
callback reads 1 MiB. It is not a filesystem repair or authenticity checker.
"""

from __future__ import annotations

import struct
from typing import Callable


MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_DIR_BYTES = 65536 * 32  # FAT_MAX_DIR_SIZE in the pinned Linux UAPI.
MAX_FAT_BYTES = 65536 * 2
MAX_READ_BYTES = 1024 * 1024
MAX_LFN_SLOTS = 20  # MSDOS_SLOTS - one short entry, in the pinned Linux UAPI.
MAX_LFN_UNITS = 255  # FAT_LFN_LEN counts UTF-16 code units, not Python characters.
SHORT_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%'-_@~`!(){}^#&")


class FatError(ValueError):
    """Unsupported or inconsistent FAT16 data, path, or read callback result."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FatError(message)


class Fat16:
    def __init__(self, read_at: Callable[[int, int], bytes], size: int):
        require(callable(read_at), "read_at must be callable")
        require(type(size) is int and size >= 512, "volume size must be an integer >= 512")
        self._read_at, self.size = read_at, size
        self._limit = size
        self._directories = {}
        boot = self._read(0, 512)
        require(boot[510:512] == b"\x55\xaa", "missing FAT boot-sector signature")
        self.sector_size = struct.unpack_from("<H", boot, 11)[0]
        self.sectors_per_cluster = boot[13]
        reserved = struct.unpack_from("<H", boot, 14)[0]
        copies = boot[16]
        self.root_entries = struct.unpack_from("<H", boot, 17)[0]
        sectors16 = struct.unpack_from("<H", boot, 19)[0]
        media = boot[21]
        fat_sectors = struct.unpack_from("<H", boot, 22)[0]
        sectors32 = struct.unpack_from("<I", boot, 32)[0]
        require(self.sector_size in (512, 1024, 2048, 4096), "invalid sector size")
        require(self.sectors_per_cluster in (1, 2, 4, 8, 16, 32, 64, 128),
                "invalid sectors per cluster")
        require(reserved > 0 and copies > 0, "missing reserved sector or FAT copy")
        require(fat_sectors > 0 and self.root_entries > 0, "FAT32/zero-root volumes are unsupported")
        require(media == 0xf0 or media >= 0xf8, "invalid FAT media descriptor")
        require(not sectors16 or sectors32 in (0, sectors16), "conflicting BPB sector counts")
        self.total_sectors = sectors16 or sectors32
        self.volume_bytes = self.total_sectors * self.sector_size
        require(0 < self.volume_bytes <= size, "BPB volume exceeds supplied partition size")
        self._limit = self.volume_bytes
        self.cluster_size = self.sector_size * self.sectors_per_cluster
        root_bytes = self.root_entries * 32
        require(root_bytes <= MAX_DIR_BYTES and root_bytes % self.sector_size == 0,
                "root directory size is too large or not sector aligned")
        fat_bytes = fat_sectors * self.sector_size
        require(fat_bytes <= MAX_FAT_BYTES, "FAT16 table exceeds 128 KiB")
        self.fat_offset = reserved * self.sector_size
        self.root_offset = self.fat_offset + copies * fat_bytes
        self.data_offset = self.root_offset + root_bytes
        require(self.data_offset < self.volume_bytes, "metadata consumes/exceeds volume")
        self.cluster_count = (self.volume_bytes - self.data_offset) // self.cluster_size
        require(4085 <= self.cluster_count < 65525, "cluster count is not FAT16 (FAT12/FAT32 unsupported)")
        require((self.cluster_count + 2) * 2 <= fat_bytes, "FAT table is too short for data region")
        self._fat = self._read(self.fat_offset, fat_bytes)
        for copy in range(1, copies):
            require(self._read(self.fat_offset + copy * fat_bytes, fat_bytes) == self._fat,
                    "FAT copies disagree; refusing to choose one")
        first, second = struct.unpack_from("<HH", self._fat)
        require(first == (0xff00 | media), "FAT reserved entry/media descriptor mismatch")
        # FAT16 entry 1's upper two bits are clean-shutdown/hard-error flags.
        require((second & 0x3fff) == 0x3fff, "invalid FAT reserved entry 1")
        self.geometry = {
            "sector_size": self.sector_size, "sectors_per_cluster": self.sectors_per_cluster,
            "cluster_size": self.cluster_size, "reserved_sectors": reserved,
            "fat_copies": copies, "fat_sectors": fat_sectors, "root_entries": self.root_entries,
            "total_sectors": self.total_sectors, "cluster_count": self.cluster_count,
            "fat_offset": self.fat_offset, "root_offset": self.root_offset,
            "data_offset": self.data_offset, "volume_bytes": self.volume_bytes,
        }

    def _read(self, offset: int, length: int) -> bytes:
        require(type(offset) is int and type(length) is int and
                0 <= offset <= self._limit and 0 <= length <= self._limit - offset,
                "read exceeds volume bounds")
        pieces = []
        while length:
            amount = min(length, MAX_READ_BYTES)
            data = self._read_at(offset, amount)
            require(isinstance(data, bytes) and len(data) == amount,
                    "read_at must return exactly the requested bytes")
            pieces.append(data)
            offset += amount
            length -= amount
        return b"".join(pieces)

    def _cluster_offset(self, cluster: int) -> int:
        require(2 <= cluster < min(self.cluster_count + 2, 0xfff0),
                f"invalid/reserved data cluster {cluster:#x}")
        offset = self.data_offset + (cluster - 2) * self.cluster_size
        require(offset + self.cluster_size <= self.volume_bytes, "cluster exceeds volume")
        return offset

    def _chain(self, first: int, max_clusters: int) -> list[int]:
        chain, seen = [], set()
        cluster = first
        while True:
            self._cluster_offset(cluster)
            require(cluster not in seen, "cluster chain contains a loop")
            require(len(chain) < max_clusters, "cluster chain exceeds allowed length")
            seen.add(cluster)
            chain.append(cluster)
            next_cluster = struct.unpack_from("<H", self._fat, cluster * 2)[0]
            if next_cluster >= 0xfff8:
                return chain
            require(next_cluster != 0xfff7, "cluster chain contains a bad-cluster marker")
            require(next_cluster not in (0, 1) and not 0xfff0 <= next_cluster <= 0xfff6,
                    "cluster chain points to a free/reserved cluster")
            cluster = next_cluster

    @staticmethod
    def _valid_component(component: str) -> bool:
        parts = component.split(".")
        return (len(parts) in (1, 2) and 1 <= len(parts[0]) <= 8 and
                (len(parts) == 1 or 1 <= len(parts[1]) <= 3) and
                all(character in SHORT_CHARACTERS for part in parts for character in part.upper()) and
                component.isascii())

    @classmethod
    def _path(cls, path: str, allow_root: bool) -> list[str]:
        require(isinstance(path, str), "path must be a string")
        if not path:
            require(allow_root, "a file path is required")
            return []
        parts = path.split("/")
        require(len(parts) <= 64 and len(path) <= 1024, "path is too deep or long")
        require(all(cls._valid_component(part) for part in parts),
                "path requires relative ASCII 8.3 names without empty/dot/traversal components")
        return [part.upper() for part in parts]

    @staticmethod
    def _long_name(slots: list[bytes] | None, alias: bytes) -> str | None:
        """Decode only a complete consecutive LFN run bound to this raw alias.

        Linux fat_parse_long validates order/checksum; vfat_build_slots and
        xlate_to_uni define zero type/start, UTF-16 layout and NUL/FFFF padding.
        Bad metadata falls back to the short alias; it never changes lookup.
        """
        if not slots:
            return None
        checksum = 0
        for byte in alias:
            checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 0xff
        count = len(slots)
        for index, slot in enumerate(slots):
            expected = (count - index) | (0x40 if index == 0 else 0)
            if (slot[0] != expected or slot[11] != 0x0f or slot[12] != 0 or
                    slot[13] != checksum or slot[26:28] != b"\0\0"):
                return None
        raw = b"".join(slot[1:11] + slot[14:26] + slot[28:32] for slot in reversed(slots))
        units = struct.unpack("<" + "H" * (len(raw) // 2), raw)
        try:
            end = units.index(0)
        except ValueError:
            end = len(units)  # Names exactly filling their slots need no NUL.
        else:
            if any(unit != 0xffff for unit in units[end + 1:]):
                return None
        if not 1 <= end <= MAX_LFN_UNITS or 0xffff in units[:end]:
            return None
        try:
            name = raw[:end * 2].decode("utf-16le", errors="strict")
        except UnicodeDecodeError:
            return None
        if (name in (".", "..") or name.endswith((" ", ".")) or
                any(ord(char) < 32 or char in '*?<>|":/\\' for char in name)):
            return None
        return name

    def _entries(self, data: bytes) -> list[dict]:
        result, names, labels = [], set(), set()
        pending = []
        for offset in range(0, len(data), 32):
            entry = data[offset:offset + 32]
            if entry[0] == 0:
                break
            if entry[0] == 0xe5:
                pending = []
                continue
            if entry[11] == 0x0f:
                if pending is not None:
                    if len(pending) < MAX_LFN_SLOTS:
                        pending.append(entry)
                    else:
                        pending = None  # Oversized runs cannot attach to a file.
                continue
            slots, pending = pending, []
            attr = entry[11]
            require(not (attr & 0xc0) and (attr & 0x18) != 0x18, "invalid directory attributes")
            if attr & 0x08:
                continue  # Volume label.
            if entry[:11] in (b".          ", b"..         "):
                continue  # Never follow an on-disk parent pointer.
            require(all(byte < 128 for byte in entry[:11]), "non-ASCII short names are unsupported")
            base = entry[:8].decode("ascii").rstrip(" ")
            extension = entry[8:11].decode("ascii").rstrip(" ")
            name = base + ("." + extension if extension else "")
            require(self._valid_component(name), "malformed ASCII 8.3 directory name")
            require(name.upper() not in names, "duplicate/ambiguous short directory name")
            names.add(name.upper())
            if entry[12] & 0x08:
                base = base.lower()
            if entry[12] & 0x10:
                extension = extension.lower()
            name = base + ("." + extension if extension else "")
            long_name = self._long_name(slots, entry[:11])
            entry_labels = {name.casefold()}
            if long_name is not None:
                entry_labels.add(long_name.casefold())
            require(not labels.intersection(entry_labels), "ambiguous long name or short alias")
            labels.update(entry_labels)
            high = struct.unpack_from("<H", entry, 20)[0]
            cluster, size = struct.unpack_from("<HI", entry, 26)
            require(high == 0, "nonzero FAT32 high cluster field in FAT16 entry")
            is_dir = bool(attr & 0x10)
            if is_dir:
                require(size == 0, "FAT16 directory size field must be zero")
                self._cluster_offset(cluster)
            elif size or cluster:
                self._cluster_offset(cluster)
            record = {"name": name, "size": size, "cluster": cluster, "is_dir": is_dir}
            if long_name is not None:
                record["long_name"] = long_name
            result.append(record)
        return result

    def _directory(self, cluster: int) -> tuple[list[dict], tuple[int, ...]]:
        if cluster not in self._directories:
            if cluster == 0:
                chain = []
                data = self._read(self.root_offset, self.root_entries * 32)
            else:
                chain = self._chain(cluster, MAX_DIR_BYTES // self.cluster_size)
                data = b"".join(self._read(self._cluster_offset(item), self.cluster_size) for item in chain)
            self._directories[cluster] = self._entries(data), tuple(chain)
        return self._directories[cluster]

    def _walk(self, parts: list[str], want_directory: bool) -> tuple[object, set[int]]:
        cluster, ancestors = 0, set()
        for index in range(len(parts) + 1):
            entries, chain = self._directory(cluster)
            require(not ancestors.intersection(chain), "directory path has a cycle/cross-link")
            ancestors.update(chain)
            if index == len(parts):
                require(want_directory, "file path resolves to a directory")
                return entries, ancestors
            found = next((entry for entry in entries if entry["name"].upper() == parts[index]), None)
            if found is None:
                raise FileNotFoundError("FAT16 short name not found: " + "/".join(parts[:index + 1]))
            if index == len(parts) - 1 and not want_directory:
                require(not found["is_dir"], "requested file is a directory")
                return found, ancestors
            require(found["is_dir"], "path component is not a directory")
            cluster = found["cluster"]
        raise AssertionError("unreachable FAT path traversal")

    def list_dir(self, path: str = "") -> list[dict]:
        """List short aliases with optional validated long_name display metadata.

        Traverse only with name, never long_name. Returned records cannot mutate
        the cache. Different entries cannot share a casefolded alias/long name.
        """
        entries, _ = self._walk(self._path(path, allow_root=True), want_directory=True)
        return [dict(entry) for entry in entries]

    def file_extents(self, path: str) -> list[dict]:
        """Return ordered, coalesced byte extents relative to the FAT volume.

        Each record has offset, length and file_offset. The final length excludes
        cluster slack. The complete allocation chain is validated before return.
        """
        entry, ancestors = self._walk(self._path(path, allow_root=False), want_directory=False)
        size = entry["size"]
        require(size <= MAX_FILE_BYTES, "file exceeds 64 MiB limit")
        if not size:
            if entry["cluster"]:
                # FAT fallocate(KEEP_SIZE) permits allocated empty files. Check
                # the chain without exposing its allocation as logical content.
                chain = self._chain(entry["cluster"], MAX_FILE_BYTES // self.cluster_size)
                require(not ancestors.intersection(chain), "file allocation overlaps an ancestor directory")
            return []
        expected = (size + self.cluster_size - 1) // self.cluster_size
        chain = self._chain(entry["cluster"], expected)
        require(len(chain) == expected, "cluster chain is shorter than file length")
        require(not ancestors.intersection(chain), "file allocation overlaps an ancestor directory")
        extents, consumed = [], 0
        for cluster in chain:
            offset = self._cluster_offset(cluster)
            length = min(self.cluster_size, size - consumed)
            if extents and extents[-1]["offset"] + extents[-1]["length"] == offset:
                extents[-1]["length"] += length
            else:
                extents.append({"offset": offset, "length": length, "file_offset": consumed})
            consumed += length
        return extents

    def read_file(self, path: str) -> bytes:
        """Read one validated file; never return allocation slack or over 64 MiB."""
        return b"".join(self._read(entry["offset"], entry["length"]) for entry in self.file_extents(path))
