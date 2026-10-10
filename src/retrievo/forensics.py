"""Read-only MBR/GPT analysis and limited FAT32 deleted-entry recovery."""

from __future__ import annotations

import os
import re
import struct
import threading
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from retrievo.recovery import RecoveredFile, ScanCancelled

SECTOR_SIZE = 512
GPT_SIGNATURE = b"EFI PART"
GPT_HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
GPT_ENTRY_MIN_SIZE = 128
GPT_MAX_ENTRIES = 1_000_000
GPT_MAX_TABLE_BYTES = 64 * 1024 * 1024
FAT32_MAX_FILE_SIZE = 512 * 1024 * 1024
FAT32_EOC = 0x0FFFFFF8
FAT32_BAD_CLUSTER = 0x0FFFFFF7
FAT32_RESERVED = 0x0FFFFFF0


@dataclass(frozen=True)
class Partition:
    number: int
    scheme: str
    start_lba: int
    sectors: int
    partition_type: str
    filesystem: str
    sector_size: int = SECTOR_SIZE
    label: str = ""

    @property
    def byte_offset(self) -> int:
        return self.start_lba * self.sector_size

    @property
    def byte_size(self) -> int:
        return self.sectors * self.sector_size


@dataclass(frozen=True)
class PartitionReport:
    scheme: str
    sector_size: int
    partitions: tuple[Partition, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class _Fat32Volume:
    partition: Partition
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    fat_count: int
    sectors_per_fat: int
    root_cluster: int
    data_start: int
    cluster_size: int
    cluster_count: int


def analyze_partitions(
    source: str | os.PathLike[str], *, sector_size: int = SECTOR_SIZE
) -> PartitionReport:
    """Read the MBR and, when present, validate and enumerate a GPT."""
    if sector_size < 512 or sector_size & (sector_size - 1):
        raise ValueError("sector_size must be a power of two of at least 512 bytes")

    source_path = os.fspath(source)
    try:
        source_size: int | None = os.path.getsize(source_path)
    except OSError:
        source_size = None
    if source_size == 0:
        source_size = None
    warnings: list[str] = []
    with open(source_path, "rb", buffering=0) as stream:
        mbr = _read_at(stream, 0, SECTOR_SIZE)
        if len(mbr) < SECTOR_SIZE or mbr[510:512] != b"\x55\xaa":
            return PartitionReport(
                "Unknown", sector_size, (), ("No valid MBR signature was found.",)
            )

        entries = [
            struct.unpack_from("<B3sB3sII", mbr, 446 + index * 16)
            for index in range(4)
        ]
        is_gpt = any(entry[2] == 0xEE for entry in entries)
        if is_gpt:
            gpt_partitions, gpt_warnings = _read_gpt(
                stream, source_size, sector_size
            )
            return PartitionReport("GPT", sector_size, tuple(gpt_partitions), tuple(gpt_warnings))

        partitions: list[Partition] = []
        for index, entry in enumerate(entries, start=1):
            _boot, _first_chs, partition_id, _last_chs, start_lba, sectors = entry
            if partition_id == 0 or sectors == 0:
                continue
            if (
                source_size is not None
                and start_lba * sector_size + sectors * sector_size > source_size
            ):
                warnings.append(f"MBR partition {index} extends beyond the source image.")
                continue
            filesystem, label = _probe_filesystem(
                stream, start_lba * sector_size, sector_size
            )
            partitions.append(
                Partition(
                    index,
                    "MBR",
                    start_lba,
                    sectors,
                    f"0x{partition_id:02X}",
                    filesystem,
                    sector_size,
                    label,
                )
            )
            if partition_id in (0x05, 0x0F, 0x85):
                partitions.extend(
                    _read_ebr_partitions(
                        stream,
                        source_size,
                        sector_size,
                        start_lba,
                        sectors,
                        warnings,
                    )
                )
        return PartitionReport("MBR", sector_size, tuple(partitions), tuple(warnings))


def _read_ebr_partitions(
    stream: BinaryIO,
    source_size: int | None,
    sector_size: int,
    extended_start: int,
    extended_sectors: int,
    warnings: list[str],
) -> list[Partition]:
    partitions: list[Partition] = []
    extended_end = extended_start + extended_sectors
    current_ebr = extended_start
    visited: set[int] = set()
    logical_number = 5
    while current_ebr not in visited:
        if not extended_start <= current_ebr < extended_end:
            warnings.append("An extended-partition link points outside its container.")
            break
        visited.add(current_ebr)
        ebr = _read_at(stream, current_ebr * sector_size, SECTOR_SIZE)
        if len(ebr) < SECTOR_SIZE or ebr[510:512] != b"\x55\xaa":
            warnings.append(f"Extended partition table at LBA {current_ebr} is invalid.")
            break
        first = struct.unpack_from("<B3sB3sII", ebr, 446)
        _boot, _first_chs, partition_id, _last_chs, relative_start, sectors = first
        if partition_id and sectors:
            start_lba = current_ebr + relative_start
            if (
                start_lba < extended_start
                or start_lba + sectors > extended_end
                or (
                    source_size is not None
                    and (start_lba + sectors) * sector_size > source_size
                )
            ):
                warnings.append(f"Logical MBR partition {logical_number} has invalid bounds.")
            else:
                filesystem, label = _probe_filesystem(
                    stream, start_lba * sector_size, sector_size
                )
                partitions.append(
                    Partition(
                        logical_number,
                        "MBR",
                        start_lba,
                        sectors,
                        f"0x{partition_id:02X}",
                        filesystem,
                        sector_size,
                        label,
                    )
                )
                logical_number += 1
        link = struct.unpack_from("<B3sB3sII", ebr, 462)
        link_type, next_relative, next_sectors = link[2], link[4], link[5]
        if link_type not in (0x05, 0x0F, 0x85) or next_sectors == 0:
            break
        current_ebr = extended_start + next_relative
    else:
        warnings.append("Extended partition table contains a cycle.")
    return partitions


def _read_gpt(
    stream: BinaryIO, source_size: int | None, sector_size: int
) -> tuple[list[Partition], list[str]]:
    warnings: list[str] = []
    header_data = _read_at(stream, sector_size, sector_size)
    if len(header_data) < GPT_HEADER.size:
        return [], ["GPT header is truncated."]
    fields = GPT_HEADER.unpack_from(header_data)
    (
        signature,
        revision,
        header_size,
        header_crc,
        _reserved,
        current_lba,
        backup_lba,
        first_usable,
        last_usable,
        _disk_guid,
        entries_lba,
        entry_count,
        entry_size,
        entries_crc,
    ) = fields
    if signature != GPT_SIGNATURE:
        return [], ["Protective MBR found, but GPT header signature is missing."]
    if header_size < GPT_HEADER.size or header_size > sector_size:
        return [], ["GPT header size is invalid."]
    header_copy = bytearray(header_data[:header_size])
    struct.pack_into("<I", header_copy, 16, 0)
    if zlib.crc32(header_copy) & 0xFFFFFFFF != header_crc:
        warnings.append("GPT header CRC mismatch; parsed data may be unreliable.")
    if current_lba != 1 or (
        source_size is not None and backup_lba * sector_size >= source_size
    ):
        warnings.append("GPT header has out-of-range or unexpected LBA values.")
    if (
        entry_count > GPT_MAX_ENTRIES
        or entry_size < GPT_ENTRY_MIN_SIZE
        or entry_size > 4096
        or entry_count * entry_size > GPT_MAX_TABLE_BYTES
        or (
            source_size is not None
            and entry_count * entry_size > source_size
        )
    ):
        return [], warnings + ["GPT partition-entry dimensions are invalid."]

    table_offset = entries_lba * sector_size
    table_size = entry_count * entry_size
    if source_size is not None and table_offset + table_size > source_size:
        return [], warnings + ["GPT partition-entry table is truncated."]
    table = _read_at(stream, table_offset, table_size)
    if len(table) != table_size:
        return [], warnings + ["GPT partition-entry table is truncated."]
    if zlib.crc32(table) & 0xFFFFFFFF != entries_crc:
        warnings.append("GPT partition-entry table CRC mismatch.")

    partitions: list[Partition] = []
    for index in range(entry_count):
        entry = table[index * entry_size : (index + 1) * entry_size]
        type_guid_bytes = entry[:16]
        if type_guid_bytes == b"\x00" * 16:
            continue
        type_guid = str(uuid.UUID(bytes_le=type_guid_bytes))
        _unique_guid = entry[16:32]
        first_lba, last_lba, _attributes = struct.unpack_from("<QQQ", entry, 32)
        name_data = entry[56 : min(entry_size, 128)]
        label = name_data.decode("utf-16le", errors="replace").rstrip("\x00")
        if (
            first_lba < first_usable
            or last_lba < first_lba
            or last_lba > last_usable
        ):
            warnings.append(f"GPT partition {index + 1} has invalid LBA bounds.")
            continue
        sectors = last_lba - first_lba + 1
        if (
            source_size is not None
            and (first_lba + sectors) * sector_size > source_size
        ):
            warnings.append(f"GPT partition {index + 1} extends beyond the source image.")
            continue
        filesystem, boot_label = _probe_filesystem(
            stream, first_lba * sector_size, sector_size
        )
        partitions.append(
            Partition(
                index + 1,
                "GPT",
                first_lba,
                sectors,
                type_guid,
                filesystem,
                sector_size,
                label or boot_label,
            )
        )
    return partitions, warnings


def _probe_filesystem(
    stream: BinaryIO, offset: int, sector_size: int
) -> tuple[str, str]:
    boot = _read_at(stream, offset, max(sector_size, 512))
    if len(boot) < 512 or boot[510:512] != b"\x55\xaa":
        return "Unknown", ""
    if boot[3:11] == b"NTFS    ":
        return "NTFS", ""
    if boot[3:11] == b"EXFAT   ":
        return "exFAT", ""
    if boot[82:90] == b"FAT32   ":
        label = boot[71:82].decode("ascii", errors="replace").strip()
        return "FAT32", label
    if boot[54:62] in (b"FAT12   ", b"FAT16   "):
        return boot[54:59].decode("ascii", errors="replace").strip(), ""
    return "Unknown", ""


def recover_deleted_fat32(
    source: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    partition: Partition,
    *,
    cancel_event: threading.Event | None = None,
    max_file_size: int = FAT32_MAX_FILE_SIZE,
) -> list[RecoveredFile]:
    """Recover deleted FAT32 short-name entries as contiguous cluster runs.

    FAT32 does not preserve deleted cluster chains. This deliberately limited
    recovery works only when a deleted entry's first cluster and size survive
    and its file occupied consecutive clusters.
    """
    if partition.filesystem != "FAT32":
        raise ValueError("Selected partition is not identified as FAT32.")
    if max_file_size < 1:
        raise ValueError("max_file_size must be positive")

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    recovered: list[RecoveredFile] = []
    visited_directories: set[int] = set()

    with open(os.fspath(source), "rb", buffering=0) as stream:
        volume = _read_fat32_volume(stream, partition)
        sequence = 0

        def walk_directory(cluster: int, depth: int) -> None:
            nonlocal sequence
            if depth > 32 or cluster in visited_directories:
                return
            visited_directories.add(cluster)
            for directory_cluster in _cluster_chain(stream, volume, cluster):
                if cancel_event is not None and cancel_event.is_set():
                    raise ScanCancelled("Scan cancelled by user.")
                directory_offset = _cluster_offset(volume, directory_cluster)
                stream.seek(directory_offset)
                directory_data = stream.read(volume.cluster_size)
                for position in range(0, len(directory_data) - 31, 32):
                    if cancel_event is not None and cancel_event.is_set():
                        raise ScanCancelled("Scan cancelled by user.")
                    entry = directory_data[position : position + 32]
                    first_byte = entry[0]
                    if first_byte == 0x00:
                        return
                    attributes = entry[11]
                    if attributes == 0x0F or attributes & 0x08:
                        continue
                    low_cluster = struct.unpack_from("<H", entry, 26)[0]
                    high_cluster = struct.unpack_from("<H", entry, 20)[0]
                    first_cluster = (high_cluster << 16) | low_cluster
                    file_size = struct.unpack_from("<I", entry, 28)[0]
                    is_deleted = first_byte == 0xE5
                    is_directory = bool(attributes & 0x10)
                    if is_deleted:
                        if (
                            not is_directory
                            and first_cluster >= 2
                            and file_size > 0
                            and file_size <= max_file_size
                            and first_cluster < volume.cluster_count + 2
                        ):
                            file_offset = _cluster_offset(volume, first_cluster)
                            available = (
                                volume.data_start
                                + volume.cluster_count * volume.cluster_size
                                - file_offset
                            )
                            if file_size <= available:
                                sequence += 1
                                extension = _deleted_extension(entry)
                                output_path = _fat_output_path(
                                    destination, sequence, file_offset, extension
                                )
                                _copy_cluster_run(
                                    stream, file_offset, file_size, output_path
                                )
                                recovered.append(
                                    RecoveredFile(
                                        output_path,
                                        "Deleted FAT32 file",
                                        file_size,
                                        file_offset,
                                        55,
                                    )
                                )
                        continue
                    if is_directory and first_cluster >= 2:
                        walk_directory(first_cluster, depth + 1)

        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled("Scan cancelled by user.")
        walk_directory(volume.root_cluster, 0)
    return recovered


def _read_fat32_volume(stream: BinaryIO, partition: Partition) -> _Fat32Volume:
    boot = _read_at(stream, partition.byte_offset, 512)
    if len(boot) != 512 or boot[510:512] != b"\x55\xaa" or boot[82:87] != b"FAT32":
        raise ValueError("The partition does not contain a valid FAT32 boot sector.")
    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    sectors_per_cluster = boot[13]
    reserved_sectors = struct.unpack_from("<H", boot, 14)[0]
    fat_count = boot[16]
    total_sectors = struct.unpack_from("<I", boot, 32)[0]
    sectors_per_fat = struct.unpack_from("<I", boot, 36)[0]
    root_cluster = struct.unpack_from("<I", boot, 44)[0] & 0x0FFFFFFF
    if (
        bytes_per_sector < 512
        or bytes_per_sector > 4096
        or bytes_per_sector & (bytes_per_sector - 1)
        or not sectors_per_cluster
        or sectors_per_cluster & (sectors_per_cluster - 1)
        or sectors_per_cluster > 128
        or not reserved_sectors
        or not 1 <= fat_count <= 4
        or not sectors_per_fat
        or total_sectors == 0
        or root_cluster < 2
    ):
        raise ValueError("FAT32 volume has invalid geometry.")
    if bytes_per_sector != SECTOR_SIZE or partition.sector_size != SECTOR_SIZE:
        raise ValueError("FAT32 recovery currently supports 512-byte sectors only.")
    if total_sectors > partition.sectors:
        raise ValueError("FAT32 volume size exceeds its partition bounds.")
    data_start_sector = reserved_sectors + fat_count * sectors_per_fat
    if data_start_sector >= total_sectors:
        raise ValueError("FAT32 data region is outside the volume.")
    cluster_count = (total_sectors - data_start_sector) // sectors_per_cluster
    if cluster_count + 2 > sectors_per_fat * bytes_per_sector // 4:
        raise ValueError("FAT32 allocation table is too small for the declared volume.")
    if root_cluster >= cluster_count + 2:
        raise ValueError("FAT32 root directory cluster is outside the volume.")
    return _Fat32Volume(
        partition,
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        fat_count,
        sectors_per_fat,
        root_cluster,
        partition.byte_offset + data_start_sector * bytes_per_sector,
        sectors_per_cluster * bytes_per_sector,
        cluster_count,
    )


def _cluster_chain(
    stream: BinaryIO, volume: _Fat32Volume, start_cluster: int
) -> list[int]:
    fat_offset = (
        volume.partition.byte_offset
        + volume.reserved_sectors * volume.bytes_per_sector
    )
    clusters: list[int] = []
    seen: set[int] = set()
    cluster = start_cluster
    while 2 <= cluster < volume.cluster_count + 2:
        if cluster in seen:
            break
        seen.add(cluster)
        clusters.append(cluster)
        stream.seek(fat_offset + cluster * 4)
        entry = stream.read(4)
        if len(entry) != 4:
            break
        next_cluster = struct.unpack("<I", entry)[0] & 0x0FFFFFFF
        if next_cluster >= FAT32_EOC or next_cluster in (
            FAT32_BAD_CLUSTER,
        ) or next_cluster >= FAT32_RESERVED:
            break
        cluster = next_cluster
    return clusters


def _cluster_offset(volume: _Fat32Volume, cluster: int) -> int:
    return volume.data_start + (cluster - 2) * volume.cluster_size


def _deleted_extension(entry: bytes) -> str:
    extension = entry[8:11].decode("ascii", errors="replace").strip()
    extension = re.sub(r"[^A-Za-z0-9_-]", "", extension).lower()
    return extension or "bin"


def _fat_output_path(
    directory: Path, sequence: int, offset: int, extension: str
) -> Path:
    candidate = directory / f"deleted_{sequence:04d}_{offset:012x}.{extension}"
    suffix = 1
    while candidate.exists():
        candidate = directory / f"deleted_{sequence:04d}_{offset:012x}_{suffix}.{extension}"
        suffix += 1
    return candidate


def _copy_cluster_run(stream: BinaryIO, offset: int, size: int, destination: Path) -> None:
    stream.seek(offset)
    remaining = size
    try:
        with destination.open("xb") as output:
            while remaining:
                block = stream.read(min(1024 * 1024, remaining))
                if not block:
                    raise OSError("Source ended before the recovered file was copied.")
                output.write(block)
                remaining -= len(block)
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def _read_at(stream: BinaryIO, offset: int, size: int) -> bytes:
    stream.seek(offset)
    return stream.read(size)
