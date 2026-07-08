#!/usr/bin/env python3
"""
lscases.py

List all malware analysis case directories under a base directory.

Usage:
    python lscases.py [--base-dir BASE_DIR] [--verbose]

Core behaviour:
 - Lists all case directories under BASE_DIR (default: ~/malware_cases)
 - Detects a case directory if EITHER:
     a) Its name matches pattern YYYY-MM-DD_* (date-prefixed), OR
     b) It contains at least 3 of the canonical subdirs:
        samples, static, dynamic, iocs, notes, output, reports
 - For each case, shows:
     DATE     : extracted from dirname prefix YYYY-MM-DD (or directory mtime)
     NAME     : case name (dirname without date prefix if present)
     SAMPLES  : count of files directly in samples/ subdir (0 if absent)
     SIZE     : total size of all files under the case dir (human_size format)
     PATH     : absolute path (--verbose only)
 - Output: aligned columns to stdout
     DATE        NAME                         SAMPLES    SIZE
     ----------  ---------------------------  -------    ------
     2026-06-25  operation_darkweb            3          2.4 MB
     2026-06-24  ransomware_analysis_q3       7          15.2 MB
 - Prints total count of cases at the end
 - If base-dir does not exist: prints message and exits 0 (not an error)

Implementation details:
 - Standard library only (pathlib, argparse, re, os, datetime)
 - is_case_dir() delegates to is_case_root() from toolkit_common
 - Streaming-safe; skips directories with permission errors gracefully
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

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
        for u in ("KB","MB","GB","TB"):
            n /= 1024.0
            if n < 1024: return f"{n:.1f} {u}"
        return f"{n:.1f} PB"
    def audit_log_append(case_root, event_type, details=None): pass
    def find_case_root(path): return None
    def is_case_root(path):
        if not path.is_dir(): return False
        try:
            children = {p.name for p in path.iterdir() if p.is_dir()}
        except PermissionError:
            return False
        canonical = {"samples", "static", "dynamic", "iocs", "notes", "output", "reports"}
        return len(children & canonical) >= 3
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


# -- Regex for date-prefixed dirname (YYYY-MM-DD_*) --
_DATE_PREFIX_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:_(.*))?$")


# -- Helper functions --

def get_dir_size(path: Path) -> int:
    """
    Recursively total all file sizes under path.
    Skips entries that raise PermissionError or OSError gracefully.
    """
    total = 0
    try:
        for entry in os.scandir(path):
            try:
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
                elif entry.is_dir(follow_symlinks=False):
                    total += get_dir_size(Path(entry.path))
            except (PermissionError, OSError):
                continue
    except (PermissionError, OSError):
        pass
    return total


def count_samples(case_root: Path) -> int:
    """
    Count regular files directly inside case_root/samples/.
    Returns 0 if the samples/ directory does not exist or is inaccessible.
    """
    samples_dir = case_root / "samples"
    if not samples_dir.is_dir():
        return 0
    count = 0
    try:
        for entry in os.scandir(samples_dir):
            if entry.is_file(follow_symlinks=False):
                count += 1
    except (PermissionError, OSError):
        pass
    return count


def parse_case_date(path: Path) -> str:
    """
    Extract YYYY-MM-DD from dirname prefix.
    Falls back to directory mtime formatted as YYYY-MM-DD when no prefix found.
    """
    m = _DATE_PREFIX_RE.match(path.name)
    if m:
        return m.group(1)
    try:
        mtime = path.stat().st_mtime
        return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d")
    except OSError:
        return "unknown"


def parse_case_name(path: Path) -> str:
    """
    Return the human-readable case name.
    Strips the YYYY-MM-DD_ prefix if present; otherwise returns the full dirname.
    """
    m = _DATE_PREFIX_RE.match(path.name)
    if m:
        remainder = m.group(2)
        return remainder if remainder else path.name
    return path.name


def is_case_dir(path: Path) -> bool:
    """
    Return True if path is a valid case directory.

    Accepts a directory if EITHER:
      - Its name matches the YYYY-MM-DD_* date-prefix pattern, OR
      - is_case_root() from toolkit_common returns True (>= 3 canonical subdirs).
    """
    if not path.is_dir():
        return False
    if _DATE_PREFIX_RE.match(path.name):
        return True
    return is_case_root(path)


def format_table(cases: list[dict], verbose: bool = False) -> str:
    """
    Build an aligned, column-headed table string from a list of case dicts.

    Each dict must contain keys: date, name, samples, size, path.
    Returns the complete table as a single string (without a trailing newline).
    """
    if not cases:
        return ""

    col_date    = "DATE"
    col_name    = "NAME"
    col_samples = "SAMPLES"
    col_size    = "SIZE"
    col_path    = "PATH"

    w_date    = max(len(col_date),    max(len(c["date"])         for c in cases))
    w_name    = max(len(col_name),    max(len(c["name"])         for c in cases))
    w_samples = max(len(col_samples), max(len(str(c["samples"])) for c in cases))
    w_size    = max(len(col_size),    max(len(c["size"])         for c in cases))

    def row(date: str, name: str, samples: str, size: str, path: str = "") -> str:
        parts = [
            date.ljust(w_date),
            name.ljust(w_name),
            samples.ljust(w_samples),
            size.ljust(w_size),
        ]
        if verbose:
            parts.append(path)
        return "  ".join(parts).rstrip()

    lines_out: list[str] = [
        row(col_date, col_name, col_samples, col_size, col_path),
        row("-" * w_date, "-" * w_name, "-" * w_samples, "-" * w_size,
            "-" * len(col_path) if verbose else ""),
    ]
    for c in cases:
        lines_out.append(row(c["date"], c["name"], str(c["samples"]), c["size"],
                             str(c["path"])))
    return "\n".join(lines_out)


def run(base_dir_str: str, verbose: bool = False) -> tuple[int, str]:
    """
    Main logic: scan base_dir for case directories, format and print a table,
    then print the total count.

    Returns (exit_code, message). On success message is empty.
    """
    log = get_logger("toolkit.lscases")
    base_dir = resolve_path(base_dir_str)

    if not base_dir.exists():
        print(f"Base directory does not exist yet: {base_dir}")
        print("No cases found. Create cases with mkcase.py.")
        return EXIT_OK, ""

    if not base_dir.is_dir():
        return EXIT_BAD_ARGS, f"Base path is not a directory: {base_dir}"

    log.debug("Scanning base directory: %s", base_dir)

    try:
        entries = sorted(base_dir.iterdir(), key=lambda p: p.name)
    except PermissionError as exc:
        return EXIT_PERM_ERROR, f"Permission denied reading base directory: {exc}"
    except OSError as exc:
        return EXIT_FS_ERROR, f"Error reading base directory: {exc}"

    cases: list[dict] = []
    for entry in entries:
        if not entry.is_dir():
            continue
        if not is_case_dir(entry):
            log.debug("Skipping non-case directory: %s", entry.name)
            continue
        log.debug("Found case: %s", entry.name)
        cases.append({
            "date":    parse_case_date(entry),
            "name":    parse_case_name(entry),
            "samples": count_samples(entry),
            "size":    human_size(get_dir_size(entry)),
            "path":    entry.resolve(),
        })

    if not cases:
        print(f"No case directories found under: {base_dir}")
        print("Use mkcase.py to create a new case.")
        return EXIT_OK, ""

    print(format_table(cases, verbose=verbose))
    print()
    print(f"Total: {len(cases)} case(s)")
    return EXIT_OK, ""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="List malware analysis case directories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--base-dir", "-b",
        default="~/malware_cases",
        help="Base directory to scan for cases (default: ~/malware_cases)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show additional PATH column in output",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    args = parse_args(argv)
    setup_logging(verbose=args.verbose)
    exit_code, message = run(args.base_dir, verbose=args.verbose)
    if exit_code != EXIT_OK:
        print(f"Error: {message}", file=sys.stderr)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
