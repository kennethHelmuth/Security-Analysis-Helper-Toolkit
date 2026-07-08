#!/usr/bin/env python3
"""defang.py — Defang or refang IOC values for safe sharing in reports and emails.

Usage:
    python defang.py [VALUE ...] [--file FILE] [--refang] [--dry-run]
    echo 'http://evil.com' | python defang.py
    python defang.py 'http://evil.com/payload.exe'
    python defang.py 'hxxp://evil[.]com' --refang

Core behaviour:
- Reads IOC values from: positional VALUE args, --file FILE (one per line),
  or stdin if neither given.
- Default mode: defang (make IOC safe for pasting in reports/emails).
- --refang: reverse; restore defanged IOC to active form.
- --dry-run: print what would happen, do not write files (note: this script
  only outputs to stdout so --dry-run is informational).
- Output: one transformed value per line to stdout.

Defanging rules (applied IN THIS ORDER):
  1. Replace 'https://'  with 'hxxps[://]'
  2. Replace 'http://'   with 'hxxp[://]'
  3. Replace 'ftp://'    with 'fxp[://]'
  4. Replace '@'         with '[@]'  (email at-sign)
  5. Replace '.'         with '[.]'  (all remaining dots)

Refanging rules (applied IN THIS ORDER):
  1. Replace 'hxxps[://]' with 'https://'
  2. Replace 'hxxp[://]'  with 'http://'
  3. Replace 'fxp[://]'   with 'ftp://'
  4. Replace '[://]'       with '://'  (catch any remaining bracketed schemes)
  5. Replace '[@]'         with '@'
  6. Replace '[.]'         with '.'

Exit codes: 0=ok, 2=bad args, 3=file not found, 5=permission error, 10=unexpected
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# toolkit_common import
# ---------------------------------------------------------------------------
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
# Transform functions
# ---------------------------------------------------------------------------

def defang_value(value: str) -> str:
    """Apply defanging rules in order to make an IOC safe for sharing.

    Rules are applied using plain str.replace() in a fixed order to ensure
    predictable, auditable transforms without regex complexity.

    Args:
        value: The raw IOC string to defang.

    Returns:
        The defanged string.
    """
    value = value.replace("https://", "hxxps[://]")
    value = value.replace("http://",  "hxxp[://]")
    value = value.replace("ftp://",   "fxp[://]")
    value = value.replace("@",        "[@]")
    value = value.replace(".",        "[.]")
    return value


def refang_value(value: str) -> str:
    """Apply refanging rules in order to restore an IOC to its active form.

    Rules are applied using plain str.replace() in a fixed order to ensure
    predictable, auditable transforms without regex complexity.

    Args:
        value: The defanged IOC string to restore.

    Returns:
        The refanged (active) string.
    """
    value = value.replace("hxxps[://]", "https://")
    value = value.replace("hxxp[://]",  "http://")
    value = value.replace("fxp[://]",   "ftp://")
    value = value.replace("[://]",       "://")
    value = value.replace("[@]",         "@")
    value = value.replace("[.]",         ".")
    return value


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def read_values_from_file(file_path: Path) -> list[str]:
    """Read IOC values from a file, one per line.

    Blank lines and lines beginning with '#' (comments) are skipped.
    Trailing whitespace is stripped from each line.

    Args:
        file_path: Path to the IOC list file.

    Returns:
        List of non-empty, non-comment stripped line strings.
    """
    values: list[str] = []
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip()
            if not line or line.startswith("#"):
                continue
            values.append(line)
    return values


def read_values_from_stdin() -> list[str]:
    """Read IOC values from stdin, one per line.

    Blank lines and lines beginning with '#' are skipped.
    Trailing whitespace is stripped from each line.

    Returns:
        List of non-empty, non-comment stripped line strings.
    """
    values: list[str] = []
    for raw in sys.stdin:
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        values.append(line)
    return values


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------

def process_values(values: list[str], refang: bool) -> list[str]:
    """Transform each value using defang or refang rules.

    Args:
        values: Raw or defanged IOC strings to transform.
        refang: When True apply refanging; when False apply defanging.

    Returns:
        List of transformed strings in the same order as input.
    """
    transform = refang_value if refang else defang_value
    return [transform(v) for v in values]


# ---------------------------------------------------------------------------
# Core run / CLI
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> tuple[int, str]:
    """Main logic: collect, transform, and emit IOC values.

    Args:
        args: Parsed argument namespace from parse_args().

    Returns:
        A (exit_code, message) tuple. Message is empty string on success.
    """
    log = get_logger("defang")
    mode_label = "refang" if args.refang else "defang"

    if args.dry_run:
        log.info("[dry-run] Mode: %s - no files will be written.", mode_label)

    # ------------------------------------------------------------------
    # Collect input values
    # ------------------------------------------------------------------
    values: list[str] = []

    if args.values:
        values.extend(args.values)

    if args.file:
        file_path = resolve_path(args.file)
        try:
            require_file(file_path, label="--file")
        except FileNotFoundError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_NOT_FOUND, str(exc)
        except PermissionError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_PERM_ERROR, str(exc)
        try:
            file_values = read_values_from_file(file_path)
            log.debug("Read %d value(s) from %s", len(file_values), file_path)
            values.extend(file_values)
        except PermissionError as exc:
            print(f"ERROR: Permission denied reading %s: %s", file_path, exc, file=sys.stderr)
            return EXIT_PERM_ERROR, str(exc)
        except OSError as exc:
            print(f"ERROR: Could not read {file_path}: {exc}", file=sys.stderr)
            return EXIT_UNEXPECTED, str(exc)

    # Fall back to stdin when no positional args and no --file supplied
    if not args.values and not args.file:
        log.debug("No positional values or --file given; reading from stdin.")
        try:
            values.extend(read_values_from_stdin())
        except KeyboardInterrupt:
            return EXIT_OK, ""

    if not values:
        msg = "No input values provided."
        print(f"ERROR: {msg}", file=sys.stderr)
        return EXIT_BAD_ARGS, msg

    # ------------------------------------------------------------------
    # Transform
    # ------------------------------------------------------------------
    try:
        results = process_values(values, refang=args.refang)
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: Unexpected error during transform: {exc}", file=sys.stderr)
        return EXIT_UNEXPECTED, str(exc)

    # ------------------------------------------------------------------
    # Emit
    # ------------------------------------------------------------------
    if args.dry_run:
        log.info("[dry-run] Would output %d transformed value(s):", len(results))
        for original, transformed in zip(values, results):
            log.info("  %s  ->  %s", original, transformed)
    else:
        for transformed in results:
            print(transformed)

    log.debug("Processed %d value(s) (mode=%s).", len(results), mode_label)
    return EXIT_OK, ""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for defang.py.

    Args:
        argv: Argument list to parse; defaults to sys.argv[1:] when None.

    Returns:
        Populated argparse.Namespace.
    """
    parser = argparse.ArgumentParser(
        prog="defang.py",
        description="Defang or refang IOC values for safe sharing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python defang.py 'http://evil.com/payload.exe'\n"
            "  echo 'http://evil.com' | python defang.py\n"
            "  python defang.py --file iocs.txt\n"
            "  python defang.py 'hxxp://evil[.]com' --refang\n"
            "  python defang.py --file defanged.txt --refang\n"
        ),
    )

    parser.add_argument(
        "values",
        metavar="VALUE",
        nargs="*",
        help="One or more IOC values to transform (URLs, IPs, domains, emails).",
    )
    parser.add_argument(
        "--file", "-f",
        metavar="FILE",
        help=(
            "Path to a file of IOC values, one per line "
            "(# comments and blank lines are skipped)."
        ),
    )
    parser.add_argument(
        "--refang",
        action="store_true",
        default=False,
        help="Reverse mode: restore defanged IOCs to their active form.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show what would be output without printing results to stdout.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose/debug logging.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Suppress informational messages; only print errors.",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Entry point for defang.py.

    Args:
        argv: Argument list; defaults to sys.argv[1:] when None.
    """
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    exit_code, message = run(args)
    if exit_code != EXIT_OK and message:
        print(f"FATAL: {message}", file=sys.stderr)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
