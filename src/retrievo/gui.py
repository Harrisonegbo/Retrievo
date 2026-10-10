"""Tk desktop interface for the Retrievo recovery scanner."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from retrievo.forensics import PartitionReport, analyze_partitions, recover_deleted_fat32
from retrievo.recovery import RecoveredFile, ScanCancelled, scan_source


class RetrievoApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Retrievo | File Recovery")
        self.root.geometry("980x680")
        self.root.minsize(800, 560)
        self.root.configure(bg="#f5f7fb")
        self.cancel_event: threading.Event | None = None
        self.results: list[RecoveredFile] = []
        self.operation_buttons: list[ttk.Button] = []

        self.source_var = tk.StringVar()
        self.output_var = tk.StringVar(value=str(Path.home() / "Retrievo Recovered"))
        self.status_var = tk.StringVar(value="Choose a disk image or enter a source device.")
        self._style()
        self._build()

    def _style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#f5f7fb")
        style.configure("TLabel", background="#f5f7fb", foreground="#27354a")
        style.configure("Heading.TLabel", font=("Segoe UI", 23, "bold"), foreground="#14233b")
        style.configure("Subheading.TLabel", font=("Segoe UI", 10), foreground="#617089")
        style.configure("Section.TLabel", font=("Segoe UI", 10, "bold"), foreground="#263750")
        style.configure("TButton", padding=(12, 8), font=("Segoe UI", 9))
        style.configure("Accent.TButton", background="#345de6", foreground="white")
        style.map("Accent.TButton", background=[("active", "#2549c8")])
        style.configure("Treeview", rowheight=30, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build(self) -> None:
        page = ttk.Frame(self.root, padding=(28, 22))
        page.pack(fill="both", expand=True)
        header = ttk.Frame(page)
        header.pack(fill="x")
        ttk.Label(header, text="Retrievo", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Local-first forensic triage · Read-only source analysis · No cloud upload",
            style="Subheading.TLabel",
        ).pack(anchor="w", pady=(2, 14))

        source_box = ttk.LabelFrame(page, text="  1  Source device or disk image  ", padding=14)
        source_box.pack(fill="x", pady=(0, 10))
        source_row = ttk.Frame(source_box)
        source_row.pack(fill="x")
        ttk.Entry(source_row, textvariable=self.source_var).pack(side="left", fill="x", expand=True)
        ttk.Button(source_row, text="Browse image…", command=self._browse_source).pack(
            side="left", padx=(8, 0)
        )
        ttk.Label(
            source_box,
            text=r"Windows raw device example: \\.\PhysicalDrive1  ·  Scan a disk image when possible.",
            style="Subheading.TLabel",
        ).pack(anchor="w", pady=(8, 0))

        output_box = ttk.LabelFrame(page, text="  2  Recovery destination  ", padding=14)
        output_box.pack(fill="x", pady=(0, 12))
        output_row = ttk.Frame(output_box)
        output_row.pack(fill="x")
        ttk.Entry(output_row, textvariable=self.output_var).pack(side="left", fill="x", expand=True)
        ttk.Button(output_row, text="Choose folder…", command=self._browse_output).pack(
            side="left", padx=(8, 0)
        )
        ttk.Label(
            output_box,
            text="Choose a different physical device or drive for recovered files. Never save onto the source.",
            style="Subheading.TLabel",
        ).pack(anchor="w", pady=(8, 0))

        controls = ttk.Frame(page)
        controls.pack(fill="x", pady=(0, 10))
        self.scan_button = ttk.Button(
            controls, text="Start recovery scan", style="Accent.TButton", command=self._start_scan
        )
        self.scan_button.pack(side="left")
        self.partition_button = ttk.Button(
            controls, text="Analyze partitions", command=self._analyze_partitions
        )
        self.partition_button.pack(side="left", padx=(8, 0))
        self.fat_button = ttk.Button(
            controls,
            text="Recover deleted FAT32 files",
            command=self._recover_deleted_fat32,
        )
        self.fat_button.pack(side="left", padx=(8, 0))
        self.operation_buttons = [self.scan_button, self.partition_button, self.fat_button]
        self.cancel_button = ttk.Button(
            controls, text="Cancel scan", command=self._cancel_scan, state="disabled"
        )
        self.cancel_button.pack(side="left", padx=(8, 0))
        self.open_button = ttk.Button(
            controls, text="Open recovery folder", command=self._open_output, state="disabled"
        )
        self.open_button.pack(side="right")

        self.progress = ttk.Progressbar(page, mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(0, 6))
        ttk.Label(page, textvariable=self.status_var, style="Subheading.TLabel").pack(
            anchor="w", pady=(0, 10)
        )

        result_box = ttk.LabelFrame(page, text="  Recovered files  ", padding=10)
        result_box.pack(fill="both", expand=True)
        columns = ("kind", "size", "offset", "score")
        self.tree = ttk.Treeview(result_box, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("kind", text="Detected type")
        self.tree.heading("size", text="Size")
        self.tree.heading("offset", text="Source offset")
        self.tree.heading("score", text="Integrity score")
        self.tree.column("kind", width=210, anchor="w")
        self.tree.column("size", width=110, anchor="e")
        self.tree.column("offset", width=180, anchor="e")
        self.tree.column("score", width=130, anchor="center")
        scrollbar = ttk.Scrollbar(result_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._open_selected)

        ttk.Label(
            page,
            text="MBR/GPT analysis · Limited FAT32 deleted-entry recovery · Signature carving · No recovery guarantee",
            style="Subheading.TLabel",
        ).pack(anchor="w", pady=(10, 0))

    def _browse_source(self) -> None:
        filename = filedialog.askopenfilename(
            title="Choose a disk image",
            filetypes=[
                ("Disk images", "*.img *.dd *.raw *.bin *.iso"),
                ("All files", "*.*"),
            ],
        )
        if filename:
            self.source_var.set(filename)

    def _browse_output(self) -> None:
        directory = filedialog.askdirectory(title="Choose a recovery destination")
        if directory:
            self.output_var.set(directory)

    def _start_scan(self) -> None:
        source = self.source_var.get().strip()
        output = self.output_var.get().strip()
        if not source or not output:
            messagebox.showwarning("Missing location", "Choose a source and a recovery destination.")
            return
        if _same_location(source, output):
            messagebox.showerror(
                "Unsafe destination",
                "The recovery destination must not be the source device or disk image.",
            )
            return
        if not messagebox.askokcancel(
            "Confirm read-only scan",
            "The source will be opened for reading only. Ensure the recovery destination is on a "
            "different device. Raw device access may require running Retrievo as administrator.",
        ):
            return

        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.cancel_event = threading.Event()
        self._set_operation_active(True, cancellable=True)
        self.cancel_button.configure(state="normal")
        self.open_button.configure(state="disabled")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self.status_var.set("Scanning source…")
        worker = threading.Thread(target=self._run_scan, args=(source, output), daemon=True)
        worker.start()

    def _analyze_partitions(self) -> None:
        source = self.source_var.get().strip()
        if not source:
            messagebox.showwarning("Missing source", "Choose a source device or disk image.")
            return
        self._set_operation_active(True, cancellable=False)
        self.status_var.set("Reading partition table and checking filesystem boot sectors…")
        threading.Thread(target=self._run_partition_analysis, args=(source,), daemon=True).start()

    def _run_partition_analysis(self, source: str) -> None:
        try:
            report = analyze_partitions(source)
        except (OSError, ValueError) as error:
            self.root.after(0, self._scan_failed, str(error))
        else:
            self.root.after(0, self._show_partition_report, report)

    def _show_partition_report(self, report: PartitionReport) -> None:
        self._set_operation_active(False, cancellable=False)
        lines = [f"Partition scheme: {report.scheme}", f"Logical sector size: {report.sector_size} bytes"]
        if not report.partitions:
            lines.append("No valid partitions were found.")
        for partition in report.partitions:
            lines.extend(
                (
                    "",
                    f"Partition {partition.number} ({partition.scheme})",
                    f"  Type: {partition.partition_type}",
                    f"  Filesystem: {partition.filesystem}",
                    f"  Start: LBA {partition.start_lba} (byte offset {partition.byte_offset:,})",
                    f"  Size: {partition.sectors:,} sectors ({partition.byte_size:,} bytes)",
                )
            )
            if partition.label:
                lines.append(f"  Label: {partition.label}")
        if report.warnings:
            lines.extend(("", "Warnings:"))
            lines.extend(f"  - {warning}" for warning in report.warnings)
        self.status_var.set(f"Partition analysis complete · {len(report.partitions)} partition(s)")
        messagebox.showinfo("Partition analysis", "\n".join(lines))

    def _recover_deleted_fat32(self) -> None:
        source = self.source_var.get().strip()
        output = self.output_var.get().strip()
        if not source or not output:
            messagebox.showwarning("Missing location", "Choose a source and a recovery destination.")
            return
        if _same_location(source, output):
            messagebox.showerror(
                "Unsafe destination",
                "The recovery destination must not be on the source device.",
            )
            return
        if not messagebox.askokcancel(
            "Confirm FAT32 recovery",
            "Retrievo will inspect the partition table and FAT32 directory entries, then write "
            "recoverable files to the selected destination. Deleted FAT chains are not preserved; "
            "only contiguous files with intact first-cluster metadata may be recovered.",
        ):
            return
        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.cancel_event = threading.Event()
        self._set_operation_active(True, cancellable=True)
        self.cancel_button.configure(state="normal")
        self.open_button.configure(state="disabled")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self.status_var.set("Analyzing partitions and searching FAT32 deleted entries…")
        threading.Thread(
            target=self._run_deleted_recovery, args=(source, output), daemon=True
        ).start()

    def _run_deleted_recovery(self, source: str, output: str) -> None:
        try:
            report = analyze_partitions(source)
            if report.warnings:
                raise ValueError(
                    "Partition-table warnings prevent automated recovery:\n"
                    + "\n".join(report.warnings)
                )
            fat32_partitions = [
                partition for partition in report.partitions if partition.filesystem == "FAT32"
            ]
            if not fat32_partitions:
                raise ValueError(
                    f"No FAT32 partitions were identified in the {report.scheme} source."
                )
            results: list[RecoveredFile] = []
            for partition in fat32_partitions:
                if self.cancel_event is not None and self.cancel_event.is_set():
                    raise ScanCancelled("Scan cancelled by user.")
                results.extend(
                    recover_deleted_fat32(
                        source,
                        output,
                        partition,
                        cancel_event=self.cancel_event,
                    )
                )
        except ScanCancelled:
            self.root.after(0, self._finish_scan, [], "FAT32 recovery cancelled.")
        except (OSError, ValueError) as error:
            self.root.after(0, self._scan_failed, str(error))
        else:
            message = (
                "FAT32 analysis complete; no eligible deleted entries were found."
                if not results
                else None
            )
            self.root.after(0, self._finish_scan, results, message)

    def _run_scan(self, source: str, output: str) -> None:
        try:
            results = scan_source(
                source,
                output,
                progress=lambda current, total: self.root.after(
                    0, self._update_progress, current, total
                ),
                cancel_event=self.cancel_event,
            )
        except ScanCancelled:
            self.root.after(0, self._finish_scan, [], "Scan cancelled.")
        except (OSError, ValueError) as error:
            self.root.after(0, self._scan_failed, str(error))
        else:
            self.root.after(0, self._finish_scan, results, None)

    def _update_progress(self, current: int, total: int | None) -> None:
        if total is None:
            self.progress.configure(mode="indeterminate")
            return
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=max(total, 1))
        self.progress["value"] = current
        self.status_var.set(f"Scanned {current:,} of {total:,} bytes…")

    def _finish_scan(self, results: list[RecoveredFile], message: str | None) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=100, value=0)
        self._set_operation_active(False, cancellable=False)
        self.cancel_button.configure(state="disabled")
        self.results = results
        for recovered in results:
            self.tree.insert(
                "",
                "end",
                iid=str(len(self.tree.get_children())),
                values=(
                    recovered.kind,
                    _format_size(recovered.size),
                    f"0x{recovered.offset:016x}",
                    f"{recovered.score}/100",
                ),
            )
        if message:
            self.status_var.set(message)
        else:
            self.status_var.set(
                f"Scan complete · {len(results)} recoverable file(s) saved to {self.output_var.get()}"
            )
        self.open_button.configure(state="normal" if Path(self.output_var.get()).is_dir() else "disabled")

    def _scan_failed(self, error: str) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=100, value=0)
        self._set_operation_active(False, cancellable=False)
        self.cancel_button.configure(state="disabled")
        self.status_var.set("Scan failed.")
        messagebox.showerror("Recovery scan failed", error)

    def _cancel_scan(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()
            self.status_var.set("Cancelling scan…")

    def _set_operation_active(self, active: bool, *, cancellable: bool) -> None:
        state = "disabled" if active else "normal"
        for button in self.operation_buttons:
            button.configure(state=state)
        self.cancel_button.configure(state="normal" if active and cancellable else "disabled")

    def _open_output(self) -> None:
        directory = Path(self.output_var.get())
        if directory.is_dir():
            if sys.platform == "win32":
                os.startfile(directory)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(directory)])
            else:
                subprocess.Popen(["xdg-open", str(directory)])

    def _open_selected(self, _event: tk.Event[tk.Misc]) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        index = int(selection[0])
        if index < len(self.results):
            recovered_path = self.results[index].path
            if sys.platform == "win32":
                os.startfile(recovered_path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(recovered_path)])
            else:
                subprocess.Popen(["xdg-open", str(recovered_path)])


def _same_location(source: str, output: str) -> bool:
    source_normalized = os.path.normcase(os.path.abspath(source))
    output_normalized = os.path.normcase(os.path.abspath(output))
    if source_normalized == output_normalized or source_normalized.startswith(
        output_normalized.rstrip(os.sep) + os.sep
    ):
        return True
    if source.startswith("\\\\.\\"):
        return False
    try:
        source_device = os.stat(source_normalized).st_dev
        output_parent = Path(output_normalized)
        while not output_parent.exists() and output_parent != output_parent.parent:
            output_parent = output_parent.parent
        if output_parent.exists() and os.stat(output_parent).st_dev == source_device:
            return True
    except OSError:
        pass
    try:
        common_path = os.path.commonpath((source_normalized, output_normalized))
    except ValueError:
        return False
    return common_path == source_normalized


def _format_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def main() -> None:
    root = tk.Tk()
    RetrievoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
