#!/usr/bin/env python3
"""mkstrings.py — Extract printable ASCII and wide (UTF-16LE) strings from a binary file.

Usage:
    python mkstrings.py FILE [--min-length N] [--encoding {ascii,wide,both}]
                             [--out-dir OUT_DIR] [--case-dir CASE_DIR] [--dry-run]
                             [-v] [-q]

Core behaviour:
    - FILE           : Path to the binary file to scan (required positional argument).
    - --min-length N : Minimum number of characters for a string to be reported
                       (default: 4).
    - --encoding     : Which string flavours to extract:
                         ascii  — 7-bit printable bytes (0x20-0x7e plus TAB/CR/LF)
                         wide   — UTF-16LE two-byte sequences (printable chars only)
                         both   — both ASCII and wide (default)
    - --out-dir      : Write extracted strings to OUT_DIR/FILENAME.strings.txt.
                       Each output line: 0x00001234  [ASCII]  <string>
                                     or: 0x00001234  [WIDE]   <string>
    - --case-dir     : Write to the case\'s static/ subdir and append audit log.
    - --dry-run      : Scan and print summary counts, do not write any file.
    - -v / --verbose : Enable DEBUG-level logging.
    - -q / --quiet   : Suppress INFO messages.

Implementation details:
    ASCII extraction streams the file in 64 KiB chunks, accumulating bytes in
    the printable range (0x20-0x7e) plus whitespace (0x09, 0x0a, 0x0d).  When
    a non-printable byte is encountered and the accumulated run is at least
    --min-length characters long, the run is emitted with its starting offset.

    Wide (UTF-16LE) extraction memory-maps the file via the mmap module to avoid
    loading it entirely into the Python heap.  The scan advances two bytes at a
    time, looking for runs of (printable_byte, 0x00) pairs.  Candidate byte
    sequences of at least min_length * 2 bytes are decoded as UTF-16LE and
    accepted only when every decoded character is printable (code-point 0x20-0x7e).

Exit codes:
    0  OK
    2  Bad arguments
    3  File not found
    5  Permission error
    6  Filesystem / write error
    10 Unexpected error
"""

from __future__ import annotations

import argparse
import mmap
import sys
from pathlib import Path
from typing import Iterator

try:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent / "lib"))
    from toolkit_common import (
        setup_logging, get_logger, confirm, resolve_path,
        require_file, require_dir, human_size, audit_log_append,
        find_case_root, is_case_root, compute_hash, validate_algorithm,
        CASE_SUBDIRS, AUDIT_LOG_FILENAME, SUPPORTED_HASH_ALGORITHMS,
        EXIT_OK, EXIT_BAD_ARGS, EXIT_NOT_FOUND, EXIT_ALREADY_EXISTS,
        EXIT_PERM_ERROR, EXIT_FS_ERROR, EXIT_VALIDATION, EXIT_UNEXPECTED,
    )
except Exception:
    def setup_logging(verbose=False, quiet=False):
        import logging
        lvl = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
        logging.basicConfig(level=lvl, format="%(asctime)s %(levelname)s %(message)s")
        return logging.getLogger("toolkit")
    def get_logger(name="toolkit"):
        import logging; return logging.getLogger(name)
    def confirm(prompt="Proceed? [y/N]: ", default_no=True):
        try: return input(prompt).strip().lower() == "y"
        except EOFError: return False
    def resolve_path(raw):
        from pathlib import Path; return Path(raw).expanduser().resolve()
    def require_file(path, label="File"):
        if not path.exists(): raise FileNotFoundError(f"{label} does not exist: {path}")
        if not path.is_file(): raise ValueError(f"{label} is not a regular file: {path}")
    def require_dir(path, label="Directory"):
        if not path.exists(): raise FileNotFoundError(f"{label} does not exist: {path}")
        if not path.is_dir(): raise NotADirectoryError(f"{label} is not a directory: {path}")
    def human_size(n):
        if n < 1024: return f"{n} B"
        for u in ("KB", "MB", "GB", "TB"):
            n /= 1024.0
            if n < 1024: return f"{n:.1f} {u}"
        return f"{n:.1f} PB"
    def audit_log_append(case_root, event_type, details=None): pass
    def find_case_root(path): return None
    def is_case_root(path): return False
    def compute_hash(file_path, algorithm="sha256", chunk_size=65536):
        import hashlib
        h = hashlib.new(algorithm.lower())
        with file_path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                h.update(chunk)
        return h.hexdigest()
    def validate_algorithm(alg):
        a = alg.lower()
        if a not in ("md5", "sha1", "sha256", "sha512"):
            raise ValueError(f"Unsupported algorithm: {alg}")
        return a
    CASE_SUBDIRS = frozenset({"samples", "static", "dynamic", "iocs", "notes", "output", "reports"})
    AUDIT_LOG_FILENAME = "audit.log"
    SUPPORTED_HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
    EXIT_OK = 0; EXIT_BAD_ARGS = 2; EXIT_NOT_FOUND = 3; EXIT_ALREADY_EXISTS = 4
    EXIT_PERM_ERROR = 5; EXIT_FS_ERROR = 6; EXIT_VALIDATION = 7; EXIT_UNEXPECTED = 10

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CHUNK: int = 65536  # 64 KiB streaming chunk size

# Bytes considered printable for ASCII string extraction
_ASCII_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

# Characters considered printable for wide string acceptance
_WIDE_PRINTABLE_RANGE = range(0x20, 0x7F)

VALID_ENCODINGS = ("ascii", "wide", "both")


# ---------------------------------------------------------------------------
# ASCII string extraction
# ---------------------------------------------------------------------------

def extract_ascii(
    file_path: Path,
    min_length: int,
) -> Iterator[tuple[int, str]]:
    """Yield (file_offset, string) for each ASCII string in *file_path*.

    Streams the file in 64 KiB chunks, accumulating bytes whose values fall
    within the printable ASCII range (0x20-0x7e) plus TAB (0x09), LF (0x0a),
    and CR (0x0d).  A run is emitted when it reaches *min_length* characters
    and terminates on the first non-printable byte.

    Args:
        file_path:  Path to the binary file to scan.
        min_length: Minimum character count for an emitted string.

    Yields:
        (start_offset, string) tuples in file order.
    """
    buf: list[int] = []
    start_offset: int = 0
    current_offset: int = 0

    with file_path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            for byte in chunk:
                if byte in _ASCII_PRINTABLE:
                    if not buf:
                        start_offset = current_offset
                    buf.append(byte)
                else:
                    if len(buf) >= min_length:
                        yield start_offset, bytes(buf).decode("ascii", errors="replace")
                    buf = []
                current_offset += 1

    # Flush any trailing run at end-of-file
    if len(buf) >= min_length:
        yield start_offset, bytes(buf).decode("ascii", errors="replace")


# ---------------------------------------------------------------------------
# Wide (UTF-16LE) string extraction
# ---------------------------------------------------------------------------

def extract_wide(
    file_path: Path,
    min_length: int,
) -> Iterator[tuple[int, str]]:
    """Yield (file_offset, string) for each wide (UTF-16LE) string in *file_path*.

    Uses ``mmap`` so that the OS manages paging; the Python process does not
    load the entire file into memory.  Scans two bytes at a time for runs of
    (printable_byte, 0x00) pairs.  A candidate sequence is decoded as
    UTF-16LE and accepted only if every resulting character has a code-point
    in [0x20, 0x7e].

    Args:
        file_path:  Path to the binary file to scan.
        min_length: Minimum character count for an emitted string.

    Yields:
        (start_offset, string) tuples in file order.
    """
    file_size = file_path.stat().st_size
    if file_size < 2:
        return

    with file_path.open("rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            run_start: int = -1
            run_bytes: list[int] = []
            i: int = 0
            length = len(mm)

            while i + 1 < length:
                lo = mm[i]
                hi = mm[i + 1]
                if hi == 0x00 and lo in _ASCII_PRINTABLE:
                    if run_start < 0:
                        run_start = i
                    run_bytes.append(lo)
                    run_bytes.append(hi)
                    i += 2
                else:
                    # End of run — evaluate what we accumulated
                    if run_start >= 0 and len(run_bytes) >= min_length * 2:
                        candidate = bytes(run_bytes)
                        try:
                            decoded = candidate.decode("utf-16-le")
                        except UnicodeDecodeError:
                            decoded = ""
                        if decoded and all(
                            0x20 <= ord(ch) <= 0x7E for ch in decoded
                        ):
                            yield run_start, decoded
                    run_start = -1
                    run_bytes = []
                    i += 1

            # Flush any trailing run
            if run_start >= 0 and len(run_bytes) >= min_length * 2:
                candidate = bytes(run_bytes)
                try:
                    decoded = candidate.decode("utf-16-le")
                except UnicodeDecodeError:
                    decoded = ""
                if decoded and all(0x20 <= ord(ch) <= 0x7E for ch in decoded):
                    yield run_start, decoded


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_entry(offset: int, tag: str, string: str) -> str:
    """Format a single string entry line for the output file.

    Format: ``0x00001234  [ASCII]  <string>``
    """
    return f"0x{offset:08x}  [{tag:<5}]  {string}"


def output_filename(file_path: Path) -> str:
    """Return the conventional strings output filename for *file_path*."""
    return f"{file_path.name}.strings.txt"


# ---------------------------------------------------------------------------
# Core extraction logic
# ---------------------------------------------------------------------------

def collect_strings(
    file_path: Path,
    min_length: int,
    encoding: str,
) -> tuple[list[tuple[int, str, str]], int, int]:
    """Extract strings from *file_path* and return them with per-type counts.

    Args:
        file_path:  Path to the file to scan.
        min_length: Minimum string length.
        encoding:   One of 'ascii', 'wide', 'both'.

    Returns:
        (entries, ascii_count, wide_count) where *entries* is a list of
        (offset, tag, string) tuples sorted by file offset, and the counts
        track how many of each type were found.
    """
    entries: list[tuple[int, str, str]] = []
    ascii_count = 0
    wide_count = 0

    if encoding in ("ascii", "both"):
        for offset, s in extract_ascii(file_path, min_length):
            entries.append((offset, "ASCII", s))
            ascii_count += 1

    if encoding in ("wide", "both"):
        for offset, s in extract_wide(file_path, min_length):
            entries.append((offset, "WIDE", s))
            wide_count += 1

    # Sort combined results by file offset for readability
    if encoding == "both":
        entries.sort(key=lambda t: t[0])

    return entries, ascii_count, wide_count


# ---------------------------------------------------------------------------
# File writing
# ---------------------------------------------------------------------------

def write_strings_file(
    entries: list[tuple[int, str, str]],
    dest: Path,
) -> None:
    """Write *entries* to *dest* as a plain-text file, one string per line."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8", errors="replace") as fh:
        for offset, tag, string in entries:
            fh.write(format_entry(offset, tag, string))
            fh.write("\n")


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(
    file_str: str,
    min_length: int,
    encoding: str,
    out_dir_str: str | None,
    case_dir_str: str | None,
    dry_run: bool,
) -> tuple[int, str]:
    """Extract strings from *file_str* and optionally write results to disk.

    Args:
        file_str:     Path string of the file to scan.
        min_length:   Minimum string character length.
        encoding:     'ascii', 'wide', or 'both'.
        out_dir_str:  Optional output directory.
        case_dir_str: Optional case root; output goes to its static/ subdir.
        dry_run:      If True, skip all file writes.

    Returns:
        (exit_code, message) — non-empty *message* is printed to stderr.
    """
    log = get_logger("mkstrings")

    # --- validate encoding ---------------------------------------------------
    if encoding not in VALID_ENCODINGS:
        return EXIT_BAD_ARGS, (
            f"Invalid encoding '{encoding}'. Choose from: {', '.join(VALID_ENCODINGS)}"
        )

    # --- validate min_length -------------------------------------------------
    if min_length < 1:
        return EXIT_BAD_ARGS, f"--min-length must be >= 1, got {min_length}"

    # --- resolve target file -------------------------------------------------
    try:
        file_path = resolve_path(file_str)
        require_file(file_path, "Target file")
    except FileNotFoundError as exc:
        return EXIT_NOT_FOUND, str(exc)
    except ValueError as exc:
        return EXIT_BAD_ARGS, str(exc)

    # --- validate case directory ---------------------------------------------
    case_root: Path | None = None
    if case_dir_str:
        case_root = resolve_path(case_dir_str)
        if not case_root.is_dir():
            return EXIT_NOT_FOUND, f"Case directory does not exist: {case_root}"

    # --- validate output directory -------------------------------------------
    out_dir: Path | None = None
    if out_dir_str:
        out_dir = resolve_path(out_dir_str)

    if out_dir is not None and case_root is not None:
        log.warning("Both --out-dir and --case-dir given; --case-dir takes precedence.")

    # --- extract strings -----------------------------------------------------
    try:
        entries, ascii_count, wide_count = collect_strings(file_path, min_length, encoding)
    except PermissionError as exc:
        return EXIT_PERM_ERROR, f"Permission denied reading file: {exc}"
    except Exception as exc:
        log.debug("Unexpected error during extraction", exc_info=True)
        return EXIT_UNEXPECTED, f"Unexpected error: {exc}"

    # --- determine destination path ------------------------------------------
    dest: Path | None = None
    if case_root is not None:
        static_dir = case_root / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        dest = static_dir / output_filename(file_path)
    elif out_dir is not None:
        dest = out_dir / output_filename(file_path)

    # --- print summary -------------------------------------------------------
    summary_lines = [
        f"File      : {file_path.name}",
    ]
    if encoding in ("ascii", "both"):
        summary_lines.append(f"ASCII     : {ascii_count} strings found")
    if encoding in ("wide", "both"):
        summary_lines.append(f"Wide      : {wide_count} strings found")
    if dest is not None:
        summary_lines.append(
            f"Output    : {'[dry-run] ' if dry_run else ''}{dest}"
        )
    print("\n".join(summary_lines))

    # --- write output file ---------------------------------------------------
    if dest is not None:
        if dry_run:
            log.info("[dry-run] Would write %d entries to: %s", len(entries), dest)
        else:
            try:
                write_strings_file(entries, dest)
                log.info("Strings file written: %s", dest)
            except PermissionError as exc:
                return EXIT_PERM_ERROR, f"Permission denied writing strings file: {exc}"
            except OSError as exc:
                return EXIT_FS_ERROR, f"Failed to write strings file: {exc}"

            if case_root is not None:
                try:
                    audit_log_append(
                        case_root,
                        "mkstrings",
                        {
                            "file": str(file_path),
                            "output": str(dest),
                            "ascii_count": ascii_count,
                            "wide_count": wide_count,
                            "min_length": min_length,
                            "encoding": encoding,
                        },
                    )
                except Exception as exc:
                    log.warning("Audit log append failed: %s", exc)

    return EXIT_OK, ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and return command-line arguments for mkstrings."""
    parser = argparse.ArgumentParser(
        prog="mkstrings.py",
        description=(
            "Extract printable ASCII and wide (UTF-16LE) strings from a binary file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file",
        metavar="FILE",
        help="Path to the binary file to scan.",
    )
    parser.add_argument(
        "--min-length",
        metavar="N",
        type=int,
        default=4,
        help="Minimum string length to report (default: 4).",
    )
    parser.add_argument(
        "--encoding",
        choices=VALID_ENCODINGS,
        default="both",
        help="String encoding to extract: ascii, wide, or both (default: both).",
    )
    parser.add_argument(
        "--out-dir",
        metavar="OUT_DIR",
        default=None,
        help="Directory to write the strings output file into.",
    )
    parser.add_argument(
        "--case-dir",
        metavar="CASE_DIR",
        default=None,
        help="Case root; output goes to its static/ subdir and audit log is updated.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print string counts but do not write any file.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable DEBUG-level logging.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress INFO-level messages.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Entry point for mkstrings."""
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    exit_code, message = run(
        file_str=args.file,
        min_length=args.min_length,
        encoding=args.encoding,
        out_dir_str=args.out_dir,
        case_dir_str=args.case_dir,
        dry_run=args.dry_run,
    )

    if message:
        print(message, file=sys.stderr)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
