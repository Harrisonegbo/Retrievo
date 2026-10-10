from __future__ import annotations

import struct
import tempfile
import unittest
import uuid
import zlib
from pathlib import Path

from retrievo.forensics import analyze_partitions, recover_deleted_fat32

SECTOR_SIZE = 512


def _make_fat32_image(path: Path) -> bytes:
    image = bytearray(101 * SECTOR_SIZE)
    image[510:512] = b"\x55\xaa"
    struct.pack_into("<B3sB3sII", image, 446, 0, b"\x00" * 3, 0x0C, b"\x00" * 3, 1, 100)

    partition_offset = SECTOR_SIZE
    boot = memoryview(image)[partition_offset : partition_offset + SECTOR_SIZE]
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", boot, 11, SECTOR_SIZE)
    boot[13] = 1
    struct.pack_into("<H", boot, 14, 1)
    boot[16] = 1
    struct.pack_into("<I", boot, 32, 100)
    struct.pack_into("<I", boot, 36, 1)
    struct.pack_into("<I", boot, 44, 2)
    boot[71:82] = b"TEST VOLUME"
    boot[82:90] = b"FAT32   "
    boot[510:512] = b"\x55\xaa"

    fat_offset = partition_offset + SECTOR_SIZE
    struct.pack_into("<I", image, fat_offset + 2 * 4, 0x0FFFFFFF)
    struct.pack_into("<I", image, fat_offset + 3 * 4, 0)
    root_offset = partition_offset + 2 * SECTOR_SIZE
    image[root_offset : root_offset + 11] = b"\xe5ILE    TXT"
    image[root_offset + 11] = 0x20
    struct.pack_into("<H", image, root_offset + 26, 3)
    struct.pack_into("<I", image, root_offset + 28, 5)
    image[root_offset + 32] = 0
    file_offset = partition_offset + 3 * SECTOR_SIZE
    image[file_offset : file_offset + 5] = b"hello"
    path.write_bytes(image)
    return bytes(image)


class ForensicAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.image = self.root / "evidence.img"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_analyzes_mbr_partition_and_identifies_fat32(self) -> None:
        _make_fat32_image(self.image)

        report = analyze_partitions(self.image)

        self.assertEqual(report.scheme, "MBR")
        self.assertEqual(len(report.partitions), 1)
        self.assertEqual(report.partitions[0].filesystem, "FAT32")
        self.assertEqual(report.partitions[0].byte_offset, SECTOR_SIZE)
        self.assertEqual(report.warnings, ())

    def test_enumerates_mbr_logical_partitions_through_ebr(self) -> None:
        image = bytearray(100 * SECTOR_SIZE)
        image[510:512] = b"\x55\xaa"
        struct.pack_into("<B3sB3sII", image, 446, 0, b"\x00" * 3, 0x0F, b"\x00" * 3, 1, 99)
        ebr_offset = SECTOR_SIZE
        image[ebr_offset + 510 : ebr_offset + 512] = b"\x55\xaa"
        struct.pack_into(
            "<B3sB3sII",
            image,
            ebr_offset + 446,
            0,
            b"\x00" * 3,
            0x0C,
            b"\x00" * 3,
            1,
            98,
        )
        self.image.write_bytes(image)

        report = analyze_partitions(self.image)

        self.assertEqual([partition.number for partition in report.partitions], [1, 5])
        self.assertEqual(report.partitions[1].start_lba, 2)
        self.assertEqual(report.partitions[1].partition_type, "0x0C")
        self.assertEqual(report.warnings, ())

    def test_recovers_deleted_contiguous_fat32_file_without_modifying_source(self) -> None:
        original = _make_fat32_image(self.image)
        partition = analyze_partitions(self.image).partitions[0]

        results = recover_deleted_fat32(
            self.image, self.root / "recovered", partition
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].kind, "Deleted FAT32 file")
        self.assertEqual(results[0].size, 5)
        self.assertEqual(results[0].path.suffix, ".txt")
        self.assertEqual(results[0].path.read_bytes(), b"hello")
        self.assertEqual(self.image.read_bytes(), original)

    def test_rejects_non_fat32_recovery_request(self) -> None:
        _make_fat32_image(self.image)
        partition = analyze_partitions(self.image).partitions[0]
        partition = partition.__class__(
            partition.number,
            partition.scheme,
            partition.start_lba,
            partition.sectors,
            partition.partition_type,
            "NTFS",
        )

        with self.assertRaises(ValueError):
            recover_deleted_fat32(self.image, self.root / "recovered", partition)

    def test_analyzes_gpt_and_checks_partition_table_crc(self) -> None:
        image = bytearray(100 * SECTOR_SIZE)
        image[510:512] = b"\x55\xaa"
        struct.pack_into("<B3sB3sII", image, 446, 0, b"\x00" * 3, 0xEE, b"\x00" * 3, 1, 99)
        basic_data_guid = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
        entry = bytearray(128)
        entry[:16] = basic_data_guid.bytes_le
        entry[16:32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQQ", entry, 32, 34, 49, 0)
        entry[56:72] = "Evidence".encode("utf-16le")
        table_crc = zlib.crc32(entry) & 0xFFFFFFFF
        image[2 * SECTOR_SIZE : 2 * SECTOR_SIZE + len(entry)] = entry
        header = bytearray(
            struct.pack(
                "<8sIIIIQQQQ16sQIII",
                b"EFI PART",
                0x00010000,
                92,
                0,
                0,
                1,
                99,
                34,
                90,
                uuid.uuid4().bytes_le,
                2,
                1,
                128,
                table_crc,
            )
        )
        struct.pack_into("<I", header, 16, zlib.crc32(header) & 0xFFFFFFFF)
        image[SECTOR_SIZE : SECTOR_SIZE + len(header)] = header
        self.image.write_bytes(image)

        report = analyze_partitions(self.image)

        self.assertEqual(report.scheme, "GPT")
        self.assertEqual(len(report.partitions), 1)
        self.assertEqual(report.partitions[0].start_lba, 34)
        self.assertEqual(report.partitions[0].label, "Evidence")
        self.assertEqual(report.warnings, ())

    def test_reports_corrupt_gpt_header_crc(self) -> None:
        image = bytearray(100 * SECTOR_SIZE)
        image[510:512] = b"\x55\xaa"
        struct.pack_into("<B3sB3sII", image, 446, 0, b"\x00" * 3, 0xEE, b"\x00" * 3, 1, 99)
        entries = bytes(128)
        image[2 * SECTOR_SIZE : 2 * SECTOR_SIZE + len(entries)] = entries
        header = bytearray(
            struct.pack(
                "<8sIIIIQQQQ16sQIII",
                b"EFI PART",
                0x00010000,
                92,
                0,
                0,
                1,
                99,
                34,
                90,
                uuid.uuid4().bytes_le,
                2,
                1,
                128,
                zlib.crc32(entries) & 0xFFFFFFFF,
            )
        )
        struct.pack_into("<I", header, 16, zlib.crc32(header) & 0xFFFFFFFF)
        header[8] ^= 1
        image[SECTOR_SIZE : SECTOR_SIZE + len(header)] = header
        self.image.write_bytes(image)

        report = analyze_partitions(self.image)

        self.assertTrue(any("header CRC mismatch" in warning for warning in report.warnings))


if __name__ == "__main__":
    unittest.main()
