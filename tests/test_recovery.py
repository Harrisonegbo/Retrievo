from __future__ import annotations

import struct
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from retrievo.gui import _same_location
from retrievo.recovery import ScanCancelled, scan_source


class RecoveryScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.image = self.root / "sample.img"
        self.output = self.root / "recovered"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _scan(self, image_data: bytes, *, block_size: int = 31):
        self.image.write_bytes(image_data)
        return scan_source(self.image, self.output, block_size=block_size)

    def test_recovers_jpeg_and_pdf_across_scan_block_boundaries(self) -> None:
        jpeg = b"\xff\xd8\xff\xe0sample-photo\xff\xd9"
        pdf = b"%PDF-1.7\nportfolio document\n%%EOF\n"
        results = self._scan(b"prefix" + jpeg + b"deleted-gap" + pdf + b"tail", block_size=16)

        self.assertEqual([item.kind for item in results], ["JPEG photo", "PDF document"])
        self.assertEqual(results[0].path.read_bytes(), jpeg)
        self.assertEqual(results[1].path.read_bytes(), pdf)
        self.assertEqual(results[0].offset, len(b"prefix"))
        self.assertEqual(results[1].offset, len(b"prefix" + jpeg + b"deleted-gap"))
        self.assertTrue(all(0 <= item.score <= 100 for item in results))

    def test_recovers_png_by_walking_chunks(self) -> None:
        image_data = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 1)
            + b"IHDR"
            + b"x"
            + b"\x00" * 4
            + struct.pack(">I", 0)
            + b"IEND"
            + b"\x00" * 4
        )
        results = self._scan(b"slack" + image_data)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].kind, "PNG image")
        self.assertEqual(results[0].path.read_bytes(), image_data)

    def test_recovers_zip_through_end_directory_record(self) -> None:
        archive_path = self.root / "valid.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("hello.txt", "recovery test")
        archive = archive_path.read_bytes()
        results = self._scan(b"unused" + archive)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].kind, "ZIP archive")
        self.assertEqual(results[0].path.read_bytes(), archive)

    def test_recovers_contiguous_mp4_boxes(self) -> None:
        ftyp_payload = b"isom\x00\x00\x02\x00isom"
        ftyp = struct.pack(">I4s", len(ftyp_payload) + 8, b"ftyp") + ftyp_payload
        media = struct.pack(">I4s", 12, b"mdat") + b"data"
        video = ftyp + media
        results = self._scan(b"slack" + video)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].kind, "MP4 video")
        self.assertEqual(results[0].path.read_bytes(), video)

    def test_ignores_incomplete_signatures_and_does_not_modify_source(self) -> None:
        content = b"\xff\xd8\xff incomplete image and %PDF-1.4 incomplete"
        results = self._scan(content)

        self.assertEqual(results, [])
        self.assertEqual(self.image.read_bytes(), content)

    def test_cancellation_is_reported(self) -> None:
        self.image.write_bytes(b"ordinary data")
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(ScanCancelled):
            scan_source(self.image, self.output, cancel_event=cancelled)

    def test_rejects_invalid_scan_limits(self) -> None:
        self.image.write_bytes(b"data")
        with self.assertRaises(ValueError):
            scan_source(self.image, self.output, block_size=1)
        with self.assertRaises(ValueError):
            scan_source(self.image, self.output, max_file_size=0)

    def test_gui_rejects_recovery_destination_on_source_volume(self) -> None:
        self.image.write_bytes(b"disk image")
        self.output.mkdir()

        self.assertTrue(_same_location(str(self.image), str(self.output)))


if __name__ == "__main__":
    unittest.main()
