#!/usr/bin/env python3
"""fileinfo.py — Static file profiler: magic bytes, entropy, MIME, hashes, and timestamps.

Usage:
    python fileinfo.py FILE [--out-dir OUT_DIR] [--json] [--case-dir CASE_DIR] [--dry-run]
                            [-v] [-q]

Core behaviour:
    - FILE          : Path to any file to analyse (required positional argument).
    - --out-dir     : Write a JSON report to OUT_DIR/FILENAME_fileinfo.json.
    - --json        : Print JSON report to stdout instead of human-readable text.
    - --case-dir    : If given, write the JSON report into the case\'s static/ sub-
                      directory and append an entry to the case audit log.
    - --dry-run     : Compute and print everything, but do not write any files.
    - -v / --verbose: Enable DEBUG-level logging.
    - -q / --quiet  : Suppress INFO messages.

Output fields:
    filename, path, size_bytes, size_human, magic_type, magic_description,
    mime_type, entropy_bits, entropy_label, md5, sha256,
    mtime, ctime, birthtime (macOS only).

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
import json
import math
import mimetypes
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
# Magic byte signatures — checked in list order (longer/more-specific
# signatures appear before shorter ones that share a common prefix).
# ---------------------------------------------------------------------------
MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'OLE2',      'OLE2 Compound Document (Office 97-2003)'),
    (b'Rar!\x1a\x07\x01\x00',              'RAR5',      'RAR Archive v5'),
    (b'Rar!\x1a\x07\x00',                  'RAR4',      'RAR Archive v4'),
    (b'7z\xbc\xaf\x27\x1c',               '7ZIP',      '7-Zip Archive'),
    (b'\x89PNG\r\n\x1a\n',                 'PNG',       'PNG Image'),
    (b'GIF89a',                             'GIF',       'GIF Image (89a)'),
    (b'GIF87a',                             'GIF',       'GIF Image (87a)'),
    (b'\xff\xd8\xff',                       'JPEG',      'JPEG Image'),
    (b'PK\x03\x04',                        'ZIP',       'ZIP Archive'),
    (b'PK\x05\x06',                        'ZIP',       'ZIP Archive (empty)'),
    (b'\x1f\x8b',                          'GZIP',      'GZIP Compressed'),
    (b'BZh',                               'BZIP2',     'BZIP2 Compressed'),
    (b'\xca\xfe\xba\xbe',                  'MACHO_FAT', 'Mach-O Fat Binary'),
    (b'\xcf\xfa\xed\xfe',                  'MACHO64',   'Mach-O 64-bit'),
    (b'\xce\xfa\xed\xfe',                  'MACHO32',   'Mach-O 32-bit'),
    (b'\x7fELF',                           'ELF',       'ELF Executable/Library'),
    (b'MZ',                                'PE',        'Windows Executable (PE)'),
    (b'%PDF',                              'PDF',       'PDF Document'),
    (b'{\x5crtf',                          'RTF',       'Rich Text Format'),
]

_CHUNK: int = 65536  # 64 KiB read chunk


# ---------------------------------------------------------------------------
# Magic detection
# ---------------------------------------------------------------------------

def detect_magic(header: bytes) -> tuple[str, str]:
    """Return (short_type, description) for the first matching magic signature.

    Signatures are compared via ``startswith`` against *header*, which should
    be the first 32 bytes of the target file.  Returns ('UNKNOWN', 'Unknown
    format') when no signature matches.
    """
    for magic, short_type, description in MAGIC_SIGNATURES:
        if header.startswith(magic):
            return short_type, description
    return 'UNKNOWN', 'Unknown format'


def read_header(file_path: Path, n: int = 32) -> bytes:
    """Read and return the first *n* bytes of *file_path*."""
    with file_path.open("rb") as fh:
        return fh.read(n)


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def compute_entropy(file_path: Path) -> float:
    """Compute Shannon entropy (bits/byte) by streaming in 64 KiB chunks.

    Returns a float in [0.0, 8.0].  An empty file returns 0.0.
    """
    counts: list[int] = [0] * 256
    total: int = 0
    with file_path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            for byte in chunk:
                counts[byte] += 1
    if total == 0:
        return 0.0
    entropy: float = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def entropy_label(entropy: float) -> str:
    """Return a human-readable label describing a Shannon entropy value."""
    if entropy < 1.0:
        return 'very low (highly repetitive)'
    if entropy < 3.5:
        return 'low (typical plaintext)'
    if entropy < 6.5:
        return 'medium (mixed/compressed)'
    if entropy < 7.5:
        return 'high (likely compressed)'
    return 'very high (likely packed or encrypted)'


# ---------------------------------------------------------------------------
# MIME type
# ---------------------------------------------------------------------------

_MAGIC_MIME_FALLBACK: dict[str, str] = {
    'PE':        'application/x-dosexec',
    'ELF':       'application/x-elf',
    'MACHO64':   'application/x-mach-binary',
    'MACHO32':   'application/x-mach-binary',
    'MACHO_FAT': 'application/x-mach-binary',
    'PDF':       'application/pdf',
    'ZIP':       'application/zip',
    'GZIP':      'application/gzip',
    'BZIP2':     'application/x-bzip2',
    '7ZIP':      'application/x-7z-compressed',
    'RAR4':      'application/x-rar-compressed',
    'RAR5':      'application/x-rar-compressed',
    'PNG':       'image/png',
    'JPEG':      'image/jpeg',
    'GIF':       'image/gif',
    'OLE2':      'application/vnd.ms-office',
    'RTF':       'application/rtf',
}


def guess_mime(file_path: Path, magic_type: str) -> str:
    """Guess MIME type via mimetypes, falling back to a magic-type lookup table."""
    mime, _ = mimetypes.guess_type(str(file_path))
    if mime:
        return mime
    return _MAGIC_MIME_FALLBACK.get(magic_type, 'application/octet-stream')


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def _utc_str(ts: float) -> str:
    """Convert a POSIX timestamp to YYYY-MM-DD HH:MM:SS UTC."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def collect_timestamps(stat: os.stat_result) -> dict[str, str]:
    """Return mtime, ctime, and (on macOS/BSD) birthtime from *stat*."""
    ts: dict[str, str] = {
        'mtime': _utc_str(stat.st_mtime),
        'ctime': _utc_str(stat.st_ctime),
    }
    if hasattr(stat, 'st_birthtime'):
        ts['birthtime'] = _utc_str(stat.st_birthtime)  # type: ignore[attr-defined]
    return ts


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyse_file(file_path: Path) -> dict[str, Any]:
    """Run all static-analysis steps on *file_path* and return a result dict.

    Raises:
        FileNotFoundError: if the path does not exist or is not a regular file.
        PermissionError:   if the file cannot be opened.
    """
    require_file(file_path)

    header = read_header(file_path, 32)
    magic_type, magic_desc = detect_magic(header)
    entropy = compute_entropy(file_path)
    mime = guess_mime(file_path, magic_type)
    stat = file_path.stat()
    size = stat.st_size

    md5_hash = compute_hash(file_path, "md5")
    sha256_hash = compute_hash(file_path, "sha256")

    result: dict[str, Any] = {
        'filename':          file_path.name,
        'path':              str(file_path),
        'size_bytes':        size,
        'size_human':        human_size(size),
        'magic_type':        magic_type,
        'magic_description': magic_desc,
        'mime_type':         mime,
        'entropy_bits':      round(entropy, 4),
        'entropy_label':     entropy_label(entropy),
        'md5':               md5_hash,
        'sha256':            sha256_hash,
    }
    result.update(collect_timestamps(stat))
    return result


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_human(report: dict[str, Any]) -> str:
    """Render *report* as aligned human-readable text."""
    lines = [
        f"File      : {report['filename']}",
        f"Path      : {report['path']}",
        f"Size      : {report['size_human']}  ({report['size_bytes']:,} bytes)",
        f"Type      : {report['magic_type']}  ({report['magic_description']})",
        f"MIME      : {report['mime_type']}",
        f"Entropy   : {report['entropy_bits']:.2f} bits/byte  [{report['entropy_label']}]",
        f"Modified  : {report['mtime']}",
    ]
    if 'ctime' in report:
        lines.append(f"Changed   : {report['ctime']}")
    if 'birthtime' in report:
        lines.append(f"Created   : {report['birthtime']}")
    lines += [
        f"MD5       : {report['md5']}",
        f"SHA256    : {report['sha256']}",
    ]
    return "\n".join(lines)


def format_json(report: dict[str, Any]) -> str:
    """Render *report* as indented JSON."""
    return json.dumps(report, indent=2)


# ---------------------------------------------------------------------------
# File writing
# ---------------------------------------------------------------------------

def report_filename(file_path: Path) -> str:
    """Return the conventional JSON report filename for *file_path*."""
    return f"{file_path.name}_fileinfo.json"


def write_report(report: dict[str, Any], dest: Path) -> None:
    """Write *report* as indented JSON to *dest*, creating parent dirs as needed."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(
    file_str: str,
    out_dir_str: str | None,
    use_json: bool,
    case_dir_str: str | None,
    dry_run: bool,
) -> tuple[int, str]:
    """Analyse *file_str* and optionally write a JSON report to disk.

    Args:
        file_str:     Path string of the file to analyse.
        out_dir_str:  Optional output directory for the JSON report.
        use_json:     Print JSON to stdout when True; human text otherwise.
        case_dir_str: Optional case root; report is written to its static/ subdir.
        dry_run:      Skip all file writes when True.

    Returns:
        (exit_code, message) — non-empty *message* is printed to stderr.
    """
    log = get_logger("fileinfo")

    # --- resolve and validate target file ------------------------------------
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

    # --- run analysis --------------------------------------------------------
    try:
        report = analyse_file(file_path)
    except PermissionError as exc:
        return EXIT_PERM_ERROR, f"Permission denied reading file: {exc}"
    except Exception as exc:
        log.debug("Unexpected error during analysis", exc_info=True)
        return EXIT_UNEXPECTED, f"Unexpected error: {exc}"

    # --- print to stdout -----------------------------------------------------
    if use_json:
        print(format_json(report))
    else:
        print(format_human(report))

    # --- determine write destination -----------------------------------------
    dest: Path | None = None
    if case_root is not None:
        static_dir = case_root / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        dest = static_dir / report_filename(file_path)
    elif out_dir is not None:
        dest = out_dir / report_filename(file_path)

    # --- write report --------------------------------------------------------
    if dest is not None:
        if dry_run:
            log.info("[dry-run] Would write report to: %s", dest)
        else:
            try:
                write_report(report, dest)
                log.info("Report written: %s", dest)
            except PermissionError as exc:
                return EXIT_PERM_ERROR, f"Permission denied writing report: {exc}"
            except OSError as exc:
                return EXIT_FS_ERROR, f"Failed to write report: {exc}"

            if case_root is not None:
                try:
                    audit_log_append(
                        case_root,
                        "fileinfo",
                        {
                            "file": str(file_path),
                            "report": str(dest),
                            "sha256": report["sha256"],
                        },
                    )
                except Exception as exc:
                    log.warning("Audit log append failed: %s", exc)

    return EXIT_OK, ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="fileinfo.py",
        description="Static file profiler: magic bytes, entropy, MIME, hashes, timestamps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file",
        metavar="FILE",
        help="Path to the file to analyse.",
    )
    parser.add_argument(
        "--out-dir",
        metavar="OUT_DIR",
        default=None,
        help="Directory to write the JSON report into.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Print JSON to stdout instead of human-readable text.",
    )
    parser.add_argument(
        "--case-dir",
        metavar="CASE_DIR",
        default=None,
        help="Case root; report is written to its static/ subdir and audit log updated.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Compute and display results, but do not write any files.",
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
    """Entry point for fileinfo."""
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    exit_code, message = run(
        file_str=args.file,
        out_dir_str=args.out_dir,
        use_json=args.json,
        case_dir_str=args.case_dir,
        dry_run=args.dry_run,
    )

    if message:
        print(message, file=sys.stderr)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
