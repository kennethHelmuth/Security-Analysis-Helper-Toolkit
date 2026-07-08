#!/usr/bin/env python3
"""
addsample.py

Register a malware sample into an existing mkcase.py case directory.

Usage:
    python addsample.py SAMPLE_PATH CASE_DIR [--algorithm ALGO] [--move] [--yes] [--dry-run]

Core behaviour:
 - SAMPLE_PATH  : path to the file to register (must be a regular file).
 - CASE_DIR     : path to an existing mkcase.py case root (validated via is_case_root()).
 - --algorithm  : hash algorithm to use when fingerprinting the sample
                  (default: sha256; supported: md5, sha1, sha256, sha512).
 - --move       : move the file into the case instead of copying it (default: copy).
 - --yes / -y   : skip the interactive confirmation prompt.
 - --dry-run    : print what would be done; make no filesystem changes.

 Destination is always CASE_DIR/samples/ORIGINAL_FILENAME.
 If the destination already exists the script exits with code 4 (EXIT_ALREADY_EXISTS).
 On a successful (non-dry-run) operation the destination file is chmod'd 0o400
 (owner read-only) and an entry is appended to the case audit log.

 Exit codes: 0=ok  2=bad args  3=not found  4=already exists  5=perm  6=fs  10=unexpected
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

# ── toolkit_common import ──────────────────────────────────────────────────
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
# ──────────────────────────────────────────────────────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Register a malware sample into an existing mkcase.py case directory. "
            "Copies (or moves) the file into CASE_DIR/samples/, computes its hash, "
            "sets the destination read-only, and appends an audit log entry."
        )
    )
    parser.add_argument(
        "sample_path",
        help="Path to the sample file to register.",
    )
    parser.add_argument(
        "case_dir",
        help="Path to an existing mkcase.py case root directory.",
    )
    parser.add_argument(
        "--algorithm",
        "-a",
        default="sha256",
        metavar="ALGO",
        help=(
            "Hash algorithm to use (default: sha256). "
            "Supported: md5, sha1, sha256, sha512."
        ),
    )
    parser.add_argument(
        "--move",
        action="store_true",
        help="Move the file into the case instead of copying it.",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the interactive confirmation prompt.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making any filesystem changes.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress informational output; only print errors.",
    )
    return parser.parse_args(argv)


# ── Validation helpers ─────────────────────────────────────────────────────

def validate_sample_path(raw: str) -> Path:
    """
    Resolve and validate that *raw* points to an existing regular file.

    Returns the resolved Path on success.
    Raises FileNotFoundError or ValueError on failure.
    """
    path = resolve_path(raw)
    require_file(path, label="Sample")
    return path


def validate_case_dir(raw: str) -> Path:
    """
    Resolve *raw* and confirm it is a valid mkcase.py case root.

    Returns the resolved Path on success.
    Raises FileNotFoundError if the directory does not exist, or
    ValueError if the directory exists but is not a valid case root.
    """
    path = resolve_path(raw)
    require_dir(path, label="Case directory")
    if not is_case_root(path):
        raise ValueError(
            f"Directory does not look like a valid mkcase.py case root: {path}\n"
            f"  Expected at least 3 of: {', '.join(sorted(CASE_SUBDIRS))}"
        )
    return path


# ── Core transfer ──────────────────────────────────────────────────────────

def build_dest_path(case_dir: Path, sample_path: Path) -> Path:
    """Return the destination path inside CASE_DIR/samples/."""
    return case_dir / "samples" / sample_path.name


def transfer_file(src: Path, dest: Path, move: bool, dry_run: bool) -> None:
    """
    Copy or move *src* to *dest*.

    When *dry_run* is True no filesystem changes are made.
    Raises PermissionError or OSError on failure.
    """
    if dry_run:
        return
    if move:
        shutil.move(str(src), dest)
    else:
        shutil.copy2(str(src), dest)


def set_readonly(path: Path, dry_run: bool) -> None:
    """
    Apply chmod 0o400 (owner read-only) to *path*.

    When *dry_run* is True this is a no-op.
    """
    if dry_run:
        return
    path.chmod(0o400)


# ── Summary printing ───────────────────────────────────────────────────────

def print_summary(
    sample_name: str,
    sample_path: Path,
    dest_path: Path,
    hash_value: str,
    algorithm: str,
    size_bytes: int,
    action: str,
    case_dir: Path,
    dry_run: bool,
) -> None:
    """Print a structured one-page summary of the operation."""
    prefix = "[DRY-RUN] " if dry_run else ""
    label = algorithm.upper()
    print(f"{prefix}Sample    : {sample_name}")
    print(f"{prefix}Source    : {sample_path}")
    print(f"{prefix}Dest      : {dest_path}")
    print(f"{prefix}{label:<9} : {hash_value}")
    print(f"{prefix}Size      : {human_size(size_bytes)}")
    print(f"{prefix}Action    : {action}")
    print(f"{prefix}Case      : {case_dir}")


# ── run() ──────────────────────────────────────────────────────────────────

def run(
    sample_path_str: str,
    case_dir_str: str,
    algorithm: str,
    move: bool,
    yes: bool,
    dry_run: bool,
) -> tuple[int, str]:
    """
    Perform the full addsample operation.

    Returns (exit_code, message).  exit_code == EXIT_OK on success.
    All errors are described in the returned message string; callers
    should direct error messages to stderr.
    """
    log = get_logger("toolkit.addsample")

    # ── Validate algorithm ────────────────────────────────────────────────
    try:
        algorithm = validate_algorithm(algorithm)
    except ValueError as exc:
        return EXIT_BAD_ARGS, str(exc)

    # ── Validate sample path ──────────────────────────────────────────────
    try:
        sample_path = validate_sample_path(sample_path_str)
    except FileNotFoundError as exc:
        return EXIT_NOT_FOUND, str(exc)
    except ValueError as exc:
        return EXIT_BAD_ARGS, str(exc)

    # ── Validate case directory ───────────────────────────────────────────
    try:
        case_dir = validate_case_dir(case_dir_str)
    except FileNotFoundError as exc:
        return EXIT_NOT_FOUND, str(exc)
    except (ValueError, NotADirectoryError) as exc:
        return EXIT_BAD_ARGS, str(exc)

    # ── Check destination ─────────────────────────────────────────────────
    dest_path = build_dest_path(case_dir, sample_path)
    if dest_path.exists():
        return EXIT_ALREADY_EXISTS, (
            f"Destination already exists: {dest_path}\n"
            "Remove or rename the existing file before re-registering."
        )

    # ── Compute hash (streaming) ──────────────────────────────────────────
    log.debug("Computing %s hash of %s ...", algorithm, sample_path)
    try:
        hash_value = compute_hash(sample_path, algorithm=algorithm)
    except PermissionError as exc:
        return EXIT_PERM_ERROR, f"Cannot read sample for hashing: {exc}"
    except OSError as exc:
        return EXIT_FS_ERROR, f"I/O error while hashing sample: {exc}"
    except Exception as exc:
        return EXIT_UNEXPECTED, f"Unexpected error while hashing: {exc}"

    size_bytes: int = sample_path.stat().st_size
    action = "move" if move else "copy"

    # ── Print summary ─────────────────────────────────────────────────────
    print_summary(
        sample_name=sample_path.name,
        sample_path=sample_path,
        dest_path=dest_path,
        hash_value=hash_value,
        algorithm=algorithm,
        size_bytes=size_bytes,
        action=action,
        case_dir=case_dir,
        dry_run=dry_run,
    )

    if dry_run:
        return EXIT_OK, "Dry-run complete — no changes made."

    # ── Confirm ───────────────────────────────────────────────────────────
    if not yes:
        prompt = f"Register '{sample_path.name}' into case (action={action})? [y/N]: "
        if not confirm(prompt):
            return EXIT_OK, "Aborted by user — no changes made."

    # ── Transfer file ─────────────────────────────────────────────────────
    log.debug("%s %s -> %s", action.capitalize(), sample_path, dest_path)
    try:
        transfer_file(sample_path, dest_path, move=move, dry_run=dry_run)
    except PermissionError as exc:
        return EXIT_PERM_ERROR, f"Permission denied during file {action}: {exc}"
    except OSError as exc:
        return EXIT_FS_ERROR, f"Filesystem error during file {action}: {exc}"
    except Exception as exc:
        return EXIT_UNEXPECTED, f"Unexpected error during file {action}: {exc}"

    # ── Set read-only ─────────────────────────────────────────────────────
    try:
        set_readonly(dest_path, dry_run=dry_run)
    except PermissionError as exc:
        return EXIT_PERM_ERROR, f"Cannot chmod destination: {exc}"
    except OSError as exc:
        return EXIT_FS_ERROR, f"Filesystem error setting permissions: {exc}"

    # ── Audit log ─────────────────────────────────────────────────────────
    details: dict[str, str] = {
        "sample": sample_path.name,
        "sha256": hash_value,
        "source": str(sample_path),
        "action": action,
        "dest": str(dest_path),
    }
    try:
        audit_log_append(case_dir, "addsample", details)
    except Exception as exc:
        # Audit log failure is non-fatal — warn and continue.
        log.warning("Could not write audit log: %s", exc)

    return EXIT_OK, f"Sample registered: {dest_path}"


# ── main() ─────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    exit_code, message = run(
        sample_path_str=args.sample_path,
        case_dir_str=args.case_dir,
        algorithm=args.algorithm,
        move=args.move,
        yes=args.yes,
        dry_run=args.dry_run,
    )

    if exit_code == EXIT_OK:
        print(message)
    else:
        print(f"Error: {message}", file=sys.stderr)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
