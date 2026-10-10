"""Read-only signature carving for common files in disk images and raw devices."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, BinaryIO


@dataclass(frozen=True)
class FileSignature:
    extension: str
    magic: bytes
    kind: str
    offset: int = 0


@dataclass(frozen=True)
class RecoveredFile:
    path: Path
    kind: str
    size: int
    offset: int
    score: int


SIGNATURES = (
    FileSignature("jpg", b"\xff\xd8\xff", "JPEG photo"),
    FileSignature("png", b"\x89PNG\r\n\x1a\n", "PNG image"),
    FileSignature("gif", b"GIF87a", "GIF image"),
    FileSignature("gif", b"GIF89a", "GIF image"),
    FileSignature("pdf", b"%PDF-", "PDF document"),
    FileSignature("zip", b"PK\x03\x04", "ZIP archive"),
    FileSignature("mp4", b"ftyp", "MP4 video", offset=4),
)

DEFAULT_BLOCK_SIZE = 1024 * 1024
DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024
ZIP_EOCD = b"PK\x05\x06"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

ProgressCallback = Callable[[int, int | None], None]


class ScanCancelled(Exception):
    """Raised when the caller requests cancellation."""


def scan_source(
    source: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    *,
    progress: ProgressCallback | None = None,
    cancel_event: threading.Event | None = None,
    block_size: int = DEFAULT_BLOCK_SIZE,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> list[RecoveredFile]:
    """Carve complete, recognizable files from a seekable source.

    The source is only opened for reading. Recovered files are written to
    ``output_dir``; the source is never modified.
    """
    if block_size < 16:
        raise ValueError("block_size must be at least 16 bytes")
    if max_file_size < 1:
        raise ValueError("max_file_size must be positive")

    source_path = os.fspath(source)
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    try:
        total_size: int | None = os.path.getsize(source_path)
    except OSError:
        total_size = None
    if total_size == 0:
        total_size = None

    recovered: list[RecoveredFile] = []
    seen_offsets: set[tuple[int, str]] = set()
    overlap = max(len(signature.magic) + signature.offset for signature in SIGNATURES)
    carry = b""
    stream_offset = 0
    process_until = 0
    sequence = 0

    with open(source_path, "rb", buffering=0) as stream:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise ScanCancelled("Scan cancelled by user.")
            block = stream.read(block_size)
            if not block:
                process_until = stream_offset
                is_final = True
            else:
                stream_offset += len(block)
                process_until = max(0, stream_offset - overlap)
                is_final = False

            data = carry + block
            data_offset = stream_offset - len(block) - len(carry)
            candidates = _find_candidates(data, data_offset, process_until, is_final)
            for file_offset, signature in candidates:
                key = (file_offset, signature.extension)
                if file_offset < 0 or key in seen_offsets:
                    continue
                seen_offsets.add(key)
                if cancel_event is not None and cancel_event.is_set():
                    raise ScanCancelled("Scan cancelled by user.")
                end_offset = _find_file_end(
                    stream,
                    file_offset,
                    signature,
                    max_file_size,
                    total_size,
                )
                stream.seek(stream_offset)
                if end_offset is None:
                    continue
                file_size = end_offset - file_offset
                if file_size <= 0:
                    continue

                sequence += 1
                output_path = _unique_output_path(
                    destination, sequence, file_offset, signature.extension
                )
                _copy_range(stream, file_offset, file_size, output_path)
                stream.seek(stream_offset)
                recovered.append(
                    RecoveredFile(
                        path=output_path,
                        kind=signature.kind,
                        size=file_size,
                        offset=file_offset,
                        score=_recovery_score(signature.extension, file_size),
                    )
                )

            if progress is not None:
                progress(stream_offset, total_size)
            if is_final:
                break
            carry = data[-overlap:] if len(data) >= overlap else data

    recovered.sort(key=lambda item: (-item.score, item.offset))
    return recovered


def _find_candidates(
    data: bytes,
    data_offset: int,
    process_until: int,
    is_final: bool,
) -> list[tuple[int, FileSignature]]:
    found: list[tuple[int, FileSignature]] = []
    for signature in SIGNATURES:
        search_from = 0
        while True:
            match = data.find(signature.magic, search_from)
            if match < 0:
                break
            file_offset = data_offset + match - signature.offset
            if file_offset < process_until or is_final:
                found.append((file_offset, signature))
            search_from = match + 1
    found.sort(key=lambda candidate: candidate[0])
    return found


def _find_file_end(
    stream: BinaryIO,
    offset: int,
    signature: FileSignature,
    max_file_size: int,
    source_size: int | None,
) -> int | None:
    end_limit = offset + max_file_size
    if source_size is not None:
        end_limit = min(end_limit, source_size)
    if signature.extension == "jpg":
        return _find_marker(stream, offset + len(signature.magic), end_limit, b"\xff\xd9")
    if signature.extension == "png":
        return _find_png_end(stream, offset, end_limit)
    if signature.extension == "gif":
        return _find_marker(stream, offset + 6, end_limit, b"\x3b")
    if signature.extension == "pdf":
        marker_end = _find_marker(stream, offset + len(signature.magic), end_limit, b"%%EOF")
        if marker_end is None:
            return None
        return marker_end + _pdf_trailing_whitespace(stream, marker_end, end_limit)
    if signature.extension == "zip":
        return _find_zip_end(stream, offset, end_limit)
    if signature.extension == "mp4":
        return _find_mp4_end(stream, offset, end_limit)
    return None


def _find_marker(stream: BinaryIO, start: int, end: int, marker: bytes) -> int | None:
    stream.seek(start)
    position = start
    carry = b""
    while position < end:
        block = stream.read(min(DEFAULT_BLOCK_SIZE, end - position))
        if not block:
            return None
        data = carry + block
        match = data.find(marker)
        if match >= 0:
            return position - len(carry) + match + len(marker)
        carry = data[-(len(marker) - 1) :] if len(marker) > 1 else b""
        position += len(block)
    return None


def _find_png_end(stream: BinaryIO, offset: int, end_limit: int) -> int | None:
    position = offset + len(PNG_SIGNATURE)
    while position + 12 <= end_limit:
        stream.seek(position)
        chunk_header = stream.read(8)
        if len(chunk_header) != 8:
            return None
        chunk_length = int.from_bytes(chunk_header[:4], "big")
        chunk_type = chunk_header[4:]
        chunk_end = position + 12 + chunk_length
        if chunk_end > end_limit or not chunk_type.isalpha():
            return None
        if chunk_type == b"IEND":
            return chunk_end
        position = chunk_end
    return None


def _pdf_trailing_whitespace(stream: BinaryIO, position: int, end_limit: int) -> int:
    stream.seek(position)
    count = 0
    while position + count < end_limit:
        value = stream.read(1)
        if not value or value not in b" \t\r\n\x0c\x00":
            break
        count += 1
    return count


def _find_zip_end(stream: BinaryIO, offset: int, end_limit: int) -> int | None:
    search_end = min(end_limit, offset + DEFAULT_MAX_FILE_SIZE)
    window_size = min(65_557, search_end - offset)
    if window_size < 22:
        return None
    stream.seek(search_end - window_size)
    window = stream.read(window_size)
    cursor = len(window)
    while True:
        eocd = window.rfind(ZIP_EOCD, 0, cursor)
        if eocd < 0:
            return None
        if eocd + 22 <= len(window):
            comment_length = int.from_bytes(window[eocd + 20 : eocd + 22], "little")
            file_end = search_end - window_size + eocd + 22 + comment_length
            if file_end <= search_end:
                return file_end
        cursor = eocd


def _find_mp4_end(stream: BinaryIO, offset: int, end_limit: int) -> int | None:
    position = offset
    saw_ftyp = False
    saw_media = False
    while position + 8 <= end_limit:
        stream.seek(position)
        header = stream.read(8)
        if len(header) != 8:
            break
        box_size = int.from_bytes(header[:4], "big")
        box_type = header[4:]
        header_size = 8
        if box_size == 1:
            extended = stream.read(8)
            if len(extended) != 8:
                break
            box_size = int.from_bytes(extended, "big")
            header_size = 16
        elif box_size == 0:
            break
        if (
            box_size < header_size
            or not all(32 <= value <= 126 for value in box_type)
            or position + box_size > end_limit
        ):
            break
        saw_ftyp = saw_ftyp or box_type == b"ftyp"
        saw_media = saw_media or box_type in (b"mdat", b"moof")
        position += box_size
    if saw_ftyp and saw_media and position > offset:
        return position
    return None


def _copy_range(stream: BinaryIO, offset: int, size: int, destination: Path) -> None:
    stream.seek(offset)
    remaining = size
    try:
        with destination.open("xb") as output:
            while remaining:
                chunk = stream.read(min(DEFAULT_BLOCK_SIZE, remaining))
                if not chunk:
                    raise OSError("Source ended before the recovered file was copied.")
                output.write(chunk)
                remaining -= len(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def _unique_output_path(
    directory: Path, sequence: int, offset: int, extension: str
) -> Path:
    base = f"retrievo_{sequence:04d}_{offset:012x}"
    candidate = directory / f"{base}.{extension}"
    suffix = 1
    while candidate.exists():
        candidate = directory / f"{base}_{suffix}.{extension}"
        suffix += 1
    return candidate


def _recovery_score(extension: str, size: int) -> int:
    type_score = {"jpg": 82, "png": 90, "gif": 78, "pdf": 75, "zip": 80, "mp4": 72}
    size_bonus = min(10, size.bit_length())
    return min(99, type_score[extension] + size_bonus)
