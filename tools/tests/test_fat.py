"""Exercise the actual reader against generated FAT16 bytes, without devices."""

from pathlib import Path
import struct
import unittest
from unittest.mock import patch


from firmware_extractor import fat


def short_entry(name, cluster=0, size=0, attr=0x20, lowercase=0):
    """Encode fixture metadata, independently of the reader's parsing code."""
    base, _, extension = name.partition(".")
    result = bytearray(32)
    result[:11] = (base.ljust(8) + extension.ljust(3)).encode("ascii")
    result[11] = attr
    result[12] = lowercase
    struct.pack_into("<HI", result, 26, cluster, size)
    return bytes(result)


def long_entries(name, alias_entry):
    """Build VFAT records in disk order, retaining an unrelated real alias."""
    raw = name.encode("utf-16le")
    units = list(struct.unpack("<" + "H" * (len(raw) // 2), raw))
    if len(units) % 13:
        units.append(0)
        units.extend([0xffff] * ((-len(units)) % 13))
    checksum = 0
    for byte in alias_entry[:11]:
        checksum = ((checksum >> 1) | ((checksum & 1) << 7)) + byte
        checksum &= 255
    result = []
    count = len(units) // 13
    for number in range(count, 0, -1):
        entry = bytearray(32)
        entry[0] = number | (0x40 if number == count else 0)
        entry[11] = 15
        entry[13] = checksum
        text = struct.pack("<13H", *units[(number - 1) * 13:number * 13])
        entry[1:11], entry[14:26], entry[28:32] = text[:10], text[10:22], text[22:]
        result.append(bytes(entry))
    return result


class Volume:
    # Smallest convenient real FAT16 geometry, not a FAT12 masquerading fixture.
    sector_size = 512
    cluster_size = 512
    cluster_count = 4090
    fat_offset = 512
    fat_bytes = 8192
    root_offset = 512 + 2 * 8192
    root_bytes = 512 * 32
    data_offset = root_offset + root_bytes
    size = data_offset + cluster_count * cluster_size

    def __init__(self):
        self.data = bytearray(self.size)
        self.calls = []
        self.data[:3] = b"\xeb\x3c\x90"
        self.data[3:11] = b"TESTFAT "
        struct.pack_into("<HBHBHHBHHHII", self.data, 11,
                         512, 1, 1, 2, 512, self.size // 512, 0xf8, 16,
                         63, 255, 0, 0)
        self.data[510:512] = b"\x55\xaa"
        self.set_fat(0, 0xfff8)
        self.set_fat(1, 0xffff)

    def set_fat(self, cluster, value):
        for copy in range(2):
            struct.pack_into("<H", self.data,
                             self.fat_offset + copy * self.fat_bytes + cluster * 2, value)

    def offset(self, cluster):
        return self.data_offset + (cluster - 2) * self.cluster_size

    def put_cluster(self, cluster, content):
        assert len(content) <= self.cluster_size
        start = self.offset(cluster)
        self.data[start:start + len(content)] = content

    def put_root(self, *entries):
        content = b"".join(entries)
        assert len(content) <= self.root_bytes
        self.data[self.root_offset:self.root_offset + len(content)] = content

    def read_at(self, offset, length):
        self.calls.append((offset, length))
        if offset < 0 or length < 0 or offset + length > self.size:
            raise AssertionError("reader attempted an out-of-bounds callback")
        return bytes(self.data[offset:offset + length])

    def reader(self):
        return fat.Fat16(self.read_at, self.size)


def populated_volume():
    volume = Volume()
    # File order differs from physical order, and the last cluster has slack.
    fragmented = b"A" * 512 + b"B" * 512 + bytes(range(129))
    for cluster, successor, payload in ((2, 8, b"A" * 512), (8, 3, b"B" * 512),
                                        (3, 0xffff, bytes(range(129)) + b"X" * 383)):
        volume.set_fat(cluster, successor)
        volume.put_cluster(cluster, payload)
    volume.set_fat(4, 9)
    volume.set_fat(9, 0xfff8)
    # Fill the first directory cluster: deleted records must not end traversal.
    deleted = b"\xe5" + b"\0" * 31
    volume.put_cluster(4, deleted * 16)
    board = b"Q" * 512 + b"R" * 17
    volume.set_fat(5, 6)
    volume.set_fat(6, 0xffff)
    volume.put_cluster(5, board[:512])
    volume.put_cluster(6, board[512:] + b"S" * 495)
    dot = bytearray(short_entry("DOT", 4, attr=0x10))
    dot[:11] = b".          "
    dotdot = bytearray(short_entry("DOTDOT", 0, attr=0x10))
    dotdot[:11] = b"..         "
    volume.put_cluster(9, bytes(dot) + bytes(dotdot) +
                       short_entry("BOARD.BIN", 5, len(board), lowercase=0x18))
    # LFN data deliberately resembles a valid alias; it must never be exposed.
    lfn = bytearray(short_entry("DECOY.BIN", 2, len(fragmented)))
    lfn[11] = 0x0f
    volume.put_root(short_entry("ADSP.MDT", 2, len(fragmented)),
                    short_entry("QCA6490", 4, attr=0x10),
                    short_entry("EMPTY.JSN"), bytes(lfn),
                    short_entry("SERVIC~1.JSN"), deleted,
                    short_entry("FIRMWARE", attr=0x08))
    return volume, fragmented, board


class Fat16ReadTests(unittest.TestCase):
    def test_fragmented_file_preserves_chain_order_and_excludes_slack(self):
        volume, expected, _ = populated_volume()
        reader = volume.reader()
        self.assertEqual(reader.read_file("adsp.mdt"), expected)
        self.assertEqual(reader.file_extents("ADSP.MDT"), [
            {"offset": volume.offset(2), "length": 512, "file_offset": 0},
            {"offset": volume.offset(8), "length": 512, "file_offset": 512},
            {"offset": volume.offset(3), "length": 129, "file_offset": 1024},
        ])
        self.assertTrue(all(0 < length <= fat.MAX_READ_BYTES for _, length in volume.calls))
        self.assertLess(sum(length for _, length in volume.calls), volume.size // 10)

    def test_fragmented_subdirectory_and_contiguous_file_extents(self):
        volume, _, expected = populated_volume()
        reader = volume.reader()
        self.assertEqual(reader.list_dir("qca6490"), [
            {"name": "board.bin", "size": 529, "cluster": 5, "is_dir": False},
        ])
        self.assertEqual(reader.read_file("QCA6490/BoArD.BiN"), expected)
        self.assertEqual(reader.file_extents("QCA6490/BOARD.BIN"), [
            {"offset": volume.offset(5), "length": 529, "file_offset": 0},
        ])

    def test_root_metadata_skips_lfn_deleted_and_labels(self):
        volume, _, _ = populated_volume()
        reader = volume.reader()
        result = reader.list_dir()
        self.assertEqual([entry["name"] for entry in result],
                         ["ADSP.MDT", "QCA6490", "EMPTY.JSN", "SERVIC~1.JSN"])
        self.assertEqual(result[1], {"name": "QCA6490", "cluster": 4, "size": 0, "is_dir": True})
        self.assertEqual(reader.read_file("servic~1.jsn"), b"")
        self.assertEqual(reader.file_extents("EMPTY.JSN"), [])
        with self.assertRaises(FileNotFoundError):
            reader.read_file("DECOY.BIN")
        result[0]["name"] = "MUTATED"
        self.assertEqual(reader.list_dir()[0]["name"], "ADSP.MDT")

    def test_directory_end_marker_ignores_following_unallocated_bytes(self):
        volume = Volume()
        volume.put_root(b"\0" * 32, b"\xff" * 32)
        self.assertEqual(volume.reader().list_dir(), [])

    def test_dirty_volume_flags_are_not_mistaken_for_invalid_reserved_entry(self):
        for flags in (0x3fff, 0x7fff, 0xbfff, 0xffff):
            with self.subTest(flags=flags):
                volume = Volume()
                volume.set_fat(1, flags)
                self.assertEqual(volume.reader().list_dir(), [])

    def test_callback_chunks_are_bounded(self):
        volume, expected, _ = populated_volume()
        with patch.object(fat, "MAX_READ_BYTES", 127):
            self.assertEqual(volume.reader().read_file("ADSP.MDT"), expected)
        self.assertTrue(all(length <= 127 for _, length in volume.calls))

    def test_actual_4096_sector_geometry_with_sparse_memory_source(self):
        # Geometry reported by the parent; no phone/image access here. Sparse
        # segments let this represent 380 MiB without allocating/dumping it.
        size, sector, cluster_size = 398458880, 4096, 16384
        boot = bytearray(512)
        struct.pack_into("<HBHBHHBHHHII", boot, 11,
                         sector, 4, 1, 2, 512, 0, 0xf8, 12, 63, 255, 0, 97280)
        boot[510:512] = b"\x55\xaa"
        table = bytearray(12 * sector)
        for cluster, successor in ((0, 0xfff8), (1, 0xffff), (2, 7), (7, 0xffff)):
            struct.pack_into("<H", table, cluster * 2, successor)
        root_offset, data_offset = 25 * sector, 29 * sector
        payload = b"F" * cluster_size + b"TAIL"
        segments = [(0, boot), (sector, table), (13 * sector, table),
                    (root_offset, short_entry("SLPI.MDT", 2, len(payload))),
                    (data_offset, payload[:cluster_size]),
                    (data_offset + 5 * cluster_size, payload[cluster_size:])]
        calls = []

        def read_at(offset, length):
            self.assertGreaterEqual(offset, 0)
            self.assertLessEqual(offset + length, size)
            calls.append((offset, length))
            result = bytearray(length)
            for start, content in segments:
                low, high = max(offset, start), min(offset + length, start + len(content))
                if low < high:
                    result[low - offset:high - offset] = content[low - start:high - start]
            return bytes(result)

        reader = fat.Fat16(read_at, size)
        self.assertEqual(reader.cluster_count, 24312)
        self.assertEqual(reader.geometry["root_offset"], root_offset)
        self.assertEqual(reader.geometry["data_offset"], data_offset)
        self.assertEqual(reader.read_file("SLPI.MDT"), payload)
        self.assertLess(sum(length for _, length in calls), 200000)

    def test_missing_or_wrong_object_types(self):
        volume, _, _ = populated_volume()
        reader = volume.reader()
        with self.assertRaises(FileNotFoundError):
            reader.read_file("MISSING.MDT")
        for operation, path in ((reader.read_file, "QCA6490"),
                                (reader.list_dir, "ADSP.MDT"),
                                (reader.read_file, "ADSP.MDT/FILE.BIN")):
            with self.subTest(path=path), self.assertRaises(fat.FatError):
                operation(path)

    def test_rejects_absolute_traversal_lfn_unicode_and_malformed_paths(self):
        reader = Volume().reader()
        paths = ("/ADSP.MDT", "../ADSP.MDT", "./ADSP.MDT", "QCA6490/../ADSP.MDT",
                 "QCA6490//BOARD.BIN", "QCA6490/", "ADSP\\MDT", "ADSP.MDT/.",
                 "NAME.JSON", "TOOLONGNAME.BIN", "ADSP.", "ADSP..MDT", "A B.MDT",
                 "ＡDSP.MDT", "ADSP.MDＴ", "A\x00.MDT", "/".join(["A"] * 65))
        for path in paths:
            with self.subTest(path=path), self.assertRaises(fat.FatError):
                reader.list_dir(path)
        for path in ("", None, b"ADSP.MDT", 1):
            with self.subTest(file_path=path), self.assertRaises(fat.FatError):
                reader.read_file(path)


class Fat16CorruptionTests(unittest.TestCase):
    def test_invalid_bpb_fields(self):
        cases = (("sector size", 11, "H", 256),
                 ("cluster zero", 13, "B", 0), ("cluster not power of two", 13, "B", 3),
                 ("reserved zero", 14, "H", 0), ("no FAT", 16, "B", 0),
                 ("FAT32 zero root", 17, "H", 0), ("unaligned root", 17, "H", 511),
                 ("invalid media", 21, "B", 0xf1), ("FAT32 length", 22, "H", 0),
                 ("too short FAT", 22, "H", 1), ("too large FAT", 22, "H", 257),
                 ("FAT12 count", 19, "H", 4000), ("metadata only", 19, "H", 2),
                 ("oversize volume", 19, "H", 5000), ("zero volume", 19, "H", 0),
                 ("conflicting sector counts", 32, "I", 4000))
        for label, offset, fmt, value in cases:
            with self.subTest(label=label):
                volume = Volume()
                struct.pack_into("<" + fmt, volume.data, offset, value)
                with self.assertRaises(fat.FatError):
                    volume.reader()

    def test_rejects_fat32_cluster_count_even_with_legacy_bpb(self):
        volume = Volume()
        struct.pack_into("<H", volume.data, 19, 0)
        struct.pack_into("<I", volume.data, 32, 70000)
        # Geometry must fail before a callback outside the small fixture.
        with self.assertRaisesRegex(fat.FatError, "cluster count is not FAT16"):
            fat.Fat16(volume.read_at, 70000 * 512)

    def test_signature_reserved_entries_and_fat_copies(self):
        for corruption in ("signature", "media", "entry1", "copy"):
            with self.subTest(corruption=corruption):
                volume = Volume()
                if corruption == "signature":
                    volume.data[510] = 0
                elif corruption == "media":
                    volume.set_fat(0, 0xfff0)
                elif corruption == "entry1":
                    volume.set_fat(1, 0)
                else:
                    volume.data[volume.fat_offset + volume.fat_bytes + 4] ^= 1
                with self.assertRaises(fat.FatError):
                    volume.reader()

    def test_invalid_callback_contract_and_io_errors(self):
        for callback in (None, lambda offset, length: b"", lambda offset, length: bytearray(length),
                         lambda offset, length: b"\0" * (length + 1)):
            with self.subTest(callback=callback), self.assertRaises(fat.FatError):
                fat.Fat16(callback, Volume.size)
        for size in (-1, 0, 511, True, 512.0):
            with self.subTest(size=size), self.assertRaises(fat.FatError):
                fat.Fat16(lambda offset, length: b"\0" * length, size)

        def io_error(offset, length):
            raise OSError("source unavailable")

        with self.assertRaisesRegex(OSError, "source unavailable"):
            fat.Fat16(io_error, Volume.size)

    def test_short_read_in_a_later_payload_extent_never_returns_partial_file(self):
        volume, _, _ = populated_volume()

        def read_at(offset, length):
            result = volume.read_at(offset, length)
            return result[:-1] if offset == volume.offset(8) else result

        reader = fat.Fat16(read_at, volume.size)
        with self.assertRaisesRegex(fat.FatError, "exactly the requested bytes"):
            reader.read_file("ADSP.MDT")

    def test_file_chain_corruption_is_checked_before_payload_reads(self):
        cases = ((0, "free/reserved"), (1, "free/reserved"), (0xfff0, "free/reserved"),
                 (0xfff6, "free/reserved"), (0xfff7, "bad-cluster"),
                 (4092, "invalid/reserved"), (2, "loop"), (0xffff, "shorter"))
        for successor, message in cases:
            with self.subTest(successor=successor):
                volume, _, _ = populated_volume()
                volume.set_fat(2, successor)
                reader = volume.reader()
                reader.list_dir()
                volume.calls.clear()
                with self.assertRaisesRegex(fat.FatError, message):
                    reader.read_file("ADSP.MDT")
                self.assertEqual(volume.calls, [])

    def test_excess_allocation_is_rejected(self):
        volume, _, _ = populated_volume()
        volume.set_fat(3, 10)
        volume.set_fat(10, 0xffff)
        with self.assertRaisesRegex(fat.FatError, "exceeds allowed length"):
            volume.reader().read_file("ADSP.MDT")

    def test_file_limit_is_checked_without_reading_its_allocation(self):
        volume = Volume()
        volume.put_root(short_entry("HUGE.BIN", 2, fat.MAX_FILE_BYTES + 1))
        reader = volume.reader()
        reader.list_dir()
        volume.calls.clear()
        with self.assertRaisesRegex(fat.FatError, "64 MiB"):
            reader.read_file("HUGE.BIN")
        self.assertEqual(volume.calls, [])

    def test_directory_chain_loop_and_size_limit(self):
        volume, _, _ = populated_volume()
        volume.set_fat(9, 4)
        with self.assertRaisesRegex(fat.FatError, "loop"):
            volume.reader().list_dir("QCA6490")
        volume.set_fat(9, 0xffff)
        reader = volume.reader()
        with patch.object(fat, "MAX_DIR_BYTES", volume.cluster_size):
            with self.assertRaisesRegex(fat.FatError, "exceeds allowed length"):
                reader.list_dir("QCA6490")

    def test_directory_path_cycle_and_file_directory_crosslink(self):
        volume, _, _ = populated_volume()
        volume.put_cluster(9, short_entry("LOOP", 4, attr=0x10) +
                           short_entry("OVERLAP.BIN", 4, 1024) + b"\0" * 32)
        reader = volume.reader()
        with self.assertRaisesRegex(fat.FatError, "cycle/cross-link"):
            reader.list_dir("QCA6490/LOOP")
        with self.assertRaisesRegex(fat.FatError, "overlaps an ancestor"):
            reader.read_file("QCA6490/OVERLAP.BIN")

    def test_invalid_directory_entry_fields(self):
        cases = (("FAT32 high cluster", 20, "H", 1),
                 ("invalid attributes", 11, "B", 0xc0),
                 ("directory plus label", 11, "B", 0x18),
                 ("invalid cluster", 26, "H", 4092),
                 ("reserved cluster", 26, "H", 0xfff0),
                 ("zero file cluster", 26, "H", 0))
        for label, offset, fmt, value in cases:
            with self.subTest(label=label):
                volume = Volume()
                entry = bytearray(short_entry("FILE.BIN", 2, 1))
                struct.pack_into("<" + fmt, entry, offset, value)
                volume.put_root(entry)
                with self.assertRaises(fat.FatError):
                    volume.reader().list_dir()
        for entry in (short_entry("DIRECTRY", 2, 1, attr=0x10),
                      short_entry("DIRECTRY", 0, 0, attr=0x10)):
            volume = Volume()
            volume.put_root(entry)
            with self.assertRaises(fat.FatError):
                volume.reader().list_dir()

    def test_duplicate_and_non_ascii_or_malformed_short_names(self):
        volume = Volume()
        volume.put_root(short_entry("FILE.BIN"), short_entry("file.bin"))
        with self.assertRaisesRegex(fat.FatError, "duplicate/ambiguous"):
            volume.reader().list_dir()
        for name in (b"\xffILE    BIN", b"BAD NAMEBIN", b"BAD\0    BIN", b"        BIN"):
            with self.subTest(name=name):
                volume = Volume()
                entry = bytearray(short_entry("FILE.BIN"))
                entry[:11] = name
                volume.put_root(entry)
                with self.assertRaises(fat.FatError):
                    volume.reader().list_dir()


class Fat16LongNameTests(unittest.TestCase):
    def test_random_aliases_expose_logical_names_without_changing_read_paths(self):
        volume = Volume()
        payload = b"metadata"
        alias = short_entry("Q7M2XY~2.MDT", 2, len(payload), lowercase=0x18)
        directory = short_entry("R8K3VZ~2", 3, attr=0x10, lowercase=0x08)
        volume.set_fat(2, 0xffff)
        volume.set_fat(3, 0xffff)
        volume.put_cluster(2, payload)
        volume.put_root(*long_entries("adsp.mdt", alias), alias,
                        *long_entries("qca6490", directory), directory)
        reader = volume.reader()
        self.assertEqual(reader.list_dir(), [
            {"name": "q7m2xy~2.mdt", "long_name": "adsp.mdt", "size": len(payload),
             "cluster": 2, "is_dir": False},
            {"name": "r8k3vz~2", "long_name": "qca6490", "size": 0,
             "cluster": 3, "is_dir": True},
        ])
        self.assertEqual(reader.read_file("Q7M2XY~2.MDT"), payload)
        self.assertEqual(reader.list_dir("R8K3VZ~2"), [])
        with self.assertRaises(FileNotFoundError):
            reader.read_file("adsp.mdt")
        with self.assertRaises(FileNotFoundError):
            reader.list_dir("qca6490")

    def test_multi_slot_unicode_surrogate_boundaries_and_exact_slot_lengths(self):
        alias = short_entry("RANDOM~2.BIN")
        for name in ("oem_hw_null.txt", "固件配置.json", "A" * 12 + "😀.bin",
                     "A" * 13, "B" * 26, "C" * 255):
            with self.subTest(name=name):
                volume = Volume()
                volume.put_root(*long_entries(name, alias), alias)
                entry = volume.reader().list_dir()[0]
                self.assertEqual(entry["long_name"], name)
                self.assertEqual(entry["name"], "RANDOM~2.BIN")

    def test_lfn_can_cross_a_directory_cluster_boundary(self):
        volume = Volume()
        volume.set_fat(2, 3)
        volume.set_fat(3, 0xffff)
        volume.put_root(short_entry("SUBDIR", 2, attr=0x10))
        alias = short_entry("RANDOM~2.TXT")
        first, second = long_entries("oem_hw_null.txt", alias)
        volume.put_cluster(2, (b"\xe5" + b"\0" * 31) * 15 + first)
        volume.put_cluster(3, second + alias)
        self.assertEqual(volume.reader().list_dir("SUBDIR")[0]["long_name"], "oem_hw_null.txt")

    def test_invalid_order_checksum_or_slot_fields_fall_back_to_real_alias(self):
        alias = short_entry("RANDOM~2.TXT")
        original = long_entries("oem_hw_null.txt", alias)
        cases = []
        cases.append(("reverse order", original[::-1]))
        cases.append(("missing last slot", original[1:]))
        cases.append(("missing first slot", original[:1]))
        for label, slot, offset, value in (
                ("missing LAST flag", 0, 0, 2), ("invalid ordinal", 1, 0, 2),
                ("extra LAST flag", 1, 0, 0x41), ("reserved ordinal bit", 0, 0, 0xc2),
                ("checksum", 1, 13, original[1][13] ^ 1), ("nonzero type", 0, 12, 1),
                ("nonzero cluster", 0, 26, 1)):
            modified = list(original)
            entry = bytearray(modified[slot])
            entry[offset] = value
            modified[slot] = bytes(entry)
            cases.append((label, modified))
        other_alias = short_entry("OTHER~2.TXT")
        cases.append(("another alias checksum", long_entries("oem_hw_null.txt", other_alias)))
        cases.append(("more than 20 slots", long_entries("A" * 273, alias)))
        for label, slots in cases:
            with self.subTest(label=label):
                volume = Volume()
                volume.put_root(*slots, alias)
                self.assertEqual(volume.reader().list_dir(), [
                    {"name": "RANDOM~2.TXT", "size": 0, "cluster": 0, "is_dir": False},
                ])

    def test_invalid_terminators_padding_utf16_and_pathlike_names_are_ignored(self):
        alias = short_entry("RANDOM~2.BIN")
        original = long_entries("abc.bin", alias)[0]
        cases = []
        # UTF-16 character 7 is the NUL in the name5_10 field; character 8
        # starts padding. Corrupt those bytes without changing the alias hash.
        for label, offset, value in (("missing terminator", 18, 0xffff),
                                     ("text after terminator", 20, ord("Z")),
                                     ("zero padding", 20, 0),
                                     ("lone high surrogate", 1, 0xd800),
                                     ("lone low surrogate", 1, 0xdc00),
                                     ("empty name", 1, 0)):
            slot = bytearray(original)
            struct.pack_into("<H", slot, offset, value)
            cases.append((label, [bytes(slot)]))
        for name in ("A" * 256, ".", "..", "../escape", "bad\\name", "bad:name",
                     "bad?name", "bad\x01name", "trailing ", "trailing."):
            cases.append((name, long_entries(name, alias)))
        for label, slots in cases:
            with self.subTest(label=label):
                volume = Volume()
                volume.put_root(*slots, alias)
                self.assertNotIn("long_name", volume.reader().list_dir()[0])

    def test_lfn_run_never_leaks_across_deleted_volume_or_regular_entries(self):
        alias = short_entry("RANDOM~2.BIN")
        deleted = b"\xe5" + b"\0" * 31
        for separator in (deleted, short_entry("VOLUME", attr=0x08), short_entry("OTHER.BIN")):
            with self.subTest(separator=separator[:11]):
                volume = Volume()
                volume.put_root(*long_entries("adsp.mdt", alias), separator, alias)
                entry = volume.reader().list_dir()[-1]
                self.assertEqual(entry["name"], "RANDOM~2.BIN")
                self.assertNotIn("long_name", entry)

    def test_casefolded_long_name_and_short_alias_collisions_are_rejected(self):
        first, second = short_entry("FIRST~2.BIN"), short_entry("OTHER~2.BIN")
        for first_name, second_name in (("ADSP.MDT", "adsp.mdt"), ("straße", "STRASSE"),
                                        ("OTHER~2.BIN", "different.bin"),
                                        ("different.bin", "first~2.bin")):
            with self.subTest(names=(first_name, second_name)):
                volume = Volume()
                volume.put_root(*long_entries(first_name, first), first,
                                *long_entries(second_name, second), second)
                with self.assertRaisesRegex(fat.FatError, "ambiguous long name or short alias"):
                    volume.reader().list_dir()
        volume = Volume()
        volume.put_root(*long_entries("first~2.bin", first), first)
        self.assertEqual(volume.reader().list_dir()[0]["long_name"], "first~2.bin")


class Fat16AllocatedEmptyTests(unittest.TestCase):
    def test_allocated_empty_file_is_listed_and_read_without_exposing_slack(self):
        volume = Volume()
        volume.put_root(short_entry("EMPTY.TXT", 2))
        volume.set_fat(2, 8)
        volume.set_fat(8, 0xffff)
        volume.put_cluster(2, b"uninitialized allocation must not be returned")
        reader = volume.reader()
        self.assertEqual(reader.list_dir()[0]["cluster"], 2)
        volume.calls.clear()
        self.assertEqual(reader.read_file("EMPTY.TXT"), b"")
        self.assertEqual(reader.file_extents("EMPTY.TXT"), [])
        self.assertEqual(volume.calls, [])

    def test_allocated_empty_file_chain_is_checked_and_bounded_on_read(self):
        for successor in (0, 1, 0xfff0, 0xfff7, 2, 4092):
            with self.subTest(successor=successor):
                volume = Volume()
                volume.put_root(short_entry("EMPTY.TXT", 2))
                volume.set_fat(2, successor)
                reader = volume.reader()
                self.assertEqual(len(reader.list_dir()), 1)
                with self.assertRaises(fat.FatError):
                    reader.read_file("EMPTY.TXT")
        volume.set_fat(2, 3)
        volume.set_fat(3, 0xffff)
        reader = volume.reader()
        with patch.object(fat, "MAX_FILE_BYTES", 512):
            with self.assertRaisesRegex(fat.FatError, "exceeds allowed length"):
                reader.read_file("EMPTY.TXT")

    def test_empty_file_cannot_reference_its_parent_directory_allocation(self):
        volume = Volume()
        volume.put_root(short_entry("SUBDIR", 2, attr=0x10))
        volume.set_fat(2, 0xffff)
        volume.put_cluster(2, short_entry("EMPTY.TXT", 2))
        with self.assertRaisesRegex(fat.FatError, "overlaps an ancestor"):
            volume.reader().read_file("SUBDIR/EMPTY.TXT")


if __name__ == "__main__":
    unittest.main()
