# Retrievo

**Retrievo is a local-first disk triage and file-recovery prototype for Windows.** It reads disk images or manually selected raw devices, reports MBR/GPT partition layouts, identifies common filesystem boot sectors, attempts limited recovery of deleted FAT32 directory entries, and signature-carves supported file types. It does not upload evidence.

> **Scope and safety:** This is an educational portfolio project, not a validated forensic acquisition suite. It does not acquire bit-for-bit images, enforce hardware write blocking, manage cases or chain of custody, preserve a forensic audit log, or guarantee recovery. For evidence that may be used in legal or incident-response proceedings, use established forensic tools and documented procedures. Work from a verified image where possible, and never write output to the source device.

## Features

- Desktop interface built with Python and Tkinter; no runtime third-party packages.
- Read-only MBR and GPT partition-table parsing, with GPT header and partition-entry CRC checks and warnings.
- Filesystem boot-sector identification for FAT12/16/32, exFAT, and NTFS.
- Limited FAT32 deleted-file recovery from short directory entries whose first-cluster metadata remains intact.
- Signature carving for complete, contiguous JPEG, PNG, GIF, PDF, ZIP, and MP4 files.
- Source offsets, recovered sizes, detected file types, scan progress, and cancellation.
- Recovery output remains local and must be directed to a separate device.

The displayed integrity score is a deterministic triage heuristic—not an AI model or a validation that a recovered file opens correctly.

## Recovery coverage and limitations

| Capability | Current behavior | Important limitations |
| --- | --- | --- |
| Partition tables | Reads MBR (including extended/logical partitions) and primary GPT at the configured logical sector size (512 bytes by default); reports GPT CRC mismatches. | Does not repair partition tables, parse dynamic disks or backup GPT copies, enumerate Windows devices, or acquire images. A CRC warning means the table should not be trusted without independent validation. |
| Filesystem identification | Recognizes FAT12/16/32, exFAT, and NTFS boot-sector identifiers. | Identification is not filesystem parsing; exFAT and NTFS deleted-file recovery are not implemented. |
| FAT32 deleted entries | Walks active directories and attempts recovery of deleted short-name file entries with surviving first-cluster and size metadata on 512-byte-sector volumes. | FAT32 clears allocation chains on deletion. Recovery assumes file data is contiguous; fragmented files, deleted directories, long-name reconstruction, overwritten data, and entries whose metadata was cleared are unsupported. |
| Signature carving | Carves supported, structurally terminated files from unallocated or otherwise readable image regions. | Does not reconstruct filesystem paths or fragmented files; signatures can produce false positives. |

FAT32-recovered files receive generated names; original names are not preserved. Use a copy or image for testing and validate every recovered file independently. Do not treat scan output or this prototype as a forensic finding without a documented, independently verified workflow.

## Quick start

Requires Python 3.10 or newer. On Windows, install Python from [python.org](https://www.python.org/downloads/) and ensure Tkinter is included (it is included with the standard Windows installer).

```powershell
git clone https://github.com/YOUR-USERNAME/retrievo.git
cd retrievo
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
retrievo
```

Alternatively, run `python -m retrievo` from the project directory without installing it.

## Using Retrievo

1. Prefer a verified sector-by-sector image of the source device. Avoid further writes to the original device after data loss.
2. Select the image with **Browse image…**, or enter a Windows raw-device path such as `\\.\PhysicalDrive1`. Raw-device reads may require administrator privileges.
3. Choose **Analyze partitions** to inspect partition offsets, sizes, and detected filesystem identifiers.
4. Choose **Recover deleted FAT32 files** for the limited FAT32 directory-entry recovery path, or **Start recovery scan** for signature carving.
5. Direct recovered files to a different physical device. Double-click a result to open it.

Double-check the selected device number. Device discovery is intentionally manual to avoid silently selecting a source. The GUI opens sources for reading; it does not provide a hardware write blocker or guarantee that another process will not modify the device.

## Development and tests

No external runtime dependencies are required. Run the tests with the Python standard library:

```powershell
python -m unittest discover -s tests -v
```

Tests build synthetic disk images and exercise MBR/GPT parsing, GPT CRC warnings, FAT32 deleted-entry recovery, signature carving, cancellation, and source preservation. Do not test recovery against a disk containing data you cannot afford to lose.

## Roadmap

- Add verified, read-only image acquisition and cryptographic hashing with independently tested workflows.
- Add case metadata, append-only acquisition/recovery logs, and exportable reports.
- Add filesystem-aware recovery for NTFS and exFAT only after format specifications and test corpora are in place.
- Improve FAT32 deleted-file validation and fragmented-file recovery.
- Evaluate any ML-assisted triage model against a documented dataset before making AI claims.

## License

Released under the [MIT License](LICENSE).
