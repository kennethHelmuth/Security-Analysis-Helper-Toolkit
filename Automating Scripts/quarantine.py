#!/usr/bin/env python3
"""
quarantine.py

Quarantine a suspicious file by locking down its permissions and optionally renaming it.

Usage:
    python quarantine.py FILE [--rename] [--case-dir CASE_DIR] [--yes] [--dry-run]

Core behaviour:
 - FILE         : path to the file to quarantine (must be a regular file).
 - --rename     : append a .quarantine suffix to the filename; fails if the
                  renamed path already exists (exit code 4, EXIT_ALREADY_EXISTS).
                  Default: do NOT rename — only apply chmod.
 - --case-dir   : optional path to an existing mkcase.py case root; when provided
                  an audit log entry is written there after a successful operation.
 - --yes / -y   : skip the interactive confirmation prompt.
 - --dry-run    : show what would be done; make no filesystem changes.

 Operation sequence (non-dry-run):
   1. Compute sha256 hash of FILE (streaming, 64 KiB chunks).
   2. If --rename: rename FILE -> FILE.quarantine
      (abort with exit code 4 if FILE.quarantine already exists).
   3. chmod the final path to 0o400 (owner read-only).
   4. If --case-dir provided: write audit log entry.

 Printed summary:
   File       : evil.exe
   SHA256     : abc123...
   Renamed    : yes -> evil.exe.quarantine   (or "no")
   Permissions: 0o400 (read-only)
   Status     : Quarantined

 Exit codes: 0=ok  2=bad args  3=not found  4=already exists  5=perm  6=fs  10=unexpected
"""

from __future__ import annotations

import argparse
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

_QUARANTINE_SUFFIX = ".quarantine"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Quarantine a suspicious file by restricting its permissions to 0o400 "
            "(owner read-only). Optionally appends a .quarantine suffix and writes "
            "an audit log entry to a mkcase.py case directory."
        )
    )
    parser.add_argument(
        "file",
        help="Path to the file to quarantine.",
    )
    parser.add_argument(
        "--rename",
        action="store_true",
        help=(
            "Append a .quarantine suffix to the filename "
            "(fails if FILE.quarantine already exists)."
        ),
    )
    parser.add_argument(
        "--case-dir",
        default=None,
        metavar="CASE_DIR",
        help=(
            "Optional path to an existing mkcase.py case root. "
            "When provided, an audit log entry is written there."
        ),
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

def validate_file(raw: str) -> Path:
    """
    Resolve and validate that *raw* points to an existing regular file.

    Returns the resolved Path on success.
    Raises FileNotFoundError or ValueError on failure.
    """
    path = resolve_path(raw)
    require_file(path, label="File")
    return path


def validate_case_dir_optional(raw: str | None) -> Path | None:
    """
    If *raw* is given, resolve it and verify it is a valid mkcase.py case root.

    Returns the resolved Path, or None when *raw* is None.
    Raises FileNotFoundError / ValueError on invalid input.
    """
    if raw is None:
        return None
    path = resolve_path(raw)
    require_dir(path, label="Case directory")
    if not is_case_root(path):
        raise ValueError(
            f"Directory does not look like a valid mkcase.py case root: {path}\n"
            f"  Expected at least 3 of: {', '.join(sorted(CASE_SUBDIRS))}"
        )
    return path


# ── Quarantine operations ──────────────────────────────────────────────────

def build_renamed_path(file_path: Path) -> Path:
    """Return the path with the .quarantine suffix appended."""
    return file_path.parent / (file_path.name + _QUARANTINE_SUFFIX)


def rename_to_quarantine(file_path: Path, renamed_path: Path, dry_run: bool) -> None:
    """
    Rename *file_path* to *renamed_path*.

    When *dry_run* is True no filesystem changes are made.
    Raises FileExistsError if *renamed_path* already exists,
    PermissionError or OSError on other failures.
    """
    if dry_run:
        return
    if renamed_path.exists():
        raise FileExistsError(
            f"Rename target already exists: {renamed_path}"
        )
    file_path.rename(renamed_path)


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
    original_name: str,
    hash_value: str,
    rename: bool,
    renamed_path: Path | None,
    final_path: Path,
    dry_run: bool,
) -> None:
    """Print a structured one-page summary of the quarantine operation."""
    prefix = "[DRY-RUN] " if dry_run else ""
    if rename and renamed_path is not None:
        renamed_str = f"yes -> {renamed_path.name}"
    else:
        renamed_str = "no"
    print(f"{prefix}File       : {original_name}")
    print(f"{prefix}SHA256     : {hash_value}")
    print(f"{prefix}Renamed    : {renamed_str}")
    print(f"{prefix}Permissions: 0o400 (read-only)")
    if dry_run:
        print(f"{prefix}Status     : Would be quarantined")
    else:
        print(f"{prefix}Status     : Quarantined")


# ── run() ──────────────────────────────────────────────────────────────────

def run(
    file_str: str,
    rename: bool,
    case_dir_str: str | None,
    yes: bool,
    dry_run: bool,
) -> tuple[int, str]:
    """
    Perform the full quarantine operation.

    Returns (exit_code, message).  exit_code == EXIT_OK on success.
    All errors are described in the returned message string; callers
    should direct error messages to stderr.
    """
    log = get_logger("toolkit.quarantine")

    # ── Validate file path ────────────────────────────────────────────────
    try:
        file_path = validate_file(file_str)
    except FileNotFoundError as exc:
        return EXIT_NOT_FOUND, str(exc)
    except ValueError as exc:
        return EXIT_BAD_ARGS, str(exc)

    original_name: str = file_path.name

    # ── Validate optional case directory ──────────────────────────────────
    try:
        case_dir: Path | None = validate_case_dir_optional(case_dir_str)
    except FileNotFoundError as exc:
        return EXIT_NOT_FOUND, str(exc)
    except (ValueError, NotADirectoryError) as exc:
        return EXIT_BAD_ARGS, str(exc)

    # ── Determine rename target early (collision check before hashing) ────
    renamed_path: Path | None = None
    if rename:
        renamed_path = build_renamed_path(file_path)
        if renamed_path.exists():
            return EXIT_ALREADY_EXISTS, (
                f"Rename target already exists: {renamed_path}\n"
                "Remove or rename the existing file and try again."
            )

    # ── Compute sha256 hash (streaming) ───────────────────────────────────
    log.debug("Computing sha256 hash of %s ...", file_path)
    try:
        hash_value = compute_hash(file_path, algorithm="sha256")
    except PermissionError as exc:
        return EXIT_PERM_ERROR, f"Cannot read file for hashing: {exc}"
    except OSError as exc:
        return EXIT_FS_ERROR, f"I/O error while hashing file: {exc}"
    except Exception as exc:
        return EXIT_UNEXPECTED, f"Unexpected error while hashing: {exc}"

    # The final path after the optional rename
    final_path: Path = renamed_path if (rename and renamed_path is not None) else file_path

    # ── Print summary ─────────────────────────────────────────────────────
    print_summary(
        original_name=original_name,
        hash_value=hash_value,
        rename=rename,
        renamed_path=renamed_path,
        final_path=final_path,
        dry_run=dry_run,
    )

    if dry_run:
        return EXIT_OK, "Dry-run complete — no changes made."

    # ── Confirm ───────────────────────────────────────────────────────────
    if not yes:
        action_desc = "rename and chmod 0o400" if rename else "chmod 0o400"
        prompt = f"Quarantine '{original_name}' ({action_desc})? [y/N]: "
        if not confirm(prompt):
            return EXIT_OK, "Aborted by user — no changes made."

    # ── Rename (if requested) ─────────────────────────────────────────────
    if rename and renamed_path is not None:
        log.debug("Renaming %s -> %s", file_path, renamed_path)
        try:
            rename_to_quarantine(file_path, renamed_path, dry_run=dry_run)
        except FileExistsError as exc:
            return EXIT_ALREADY_EXISTS, str(exc)
        except PermissionError as exc:
            return EXIT_PERM_ERROR, f"Permission denied renaming file: {exc}"
        except OSError as exc:
            return EXIT_FS_ERROR, f"Filesystem error renaming file: {exc}"
        except Exception as exc:
            return EXIT_UNEXPECTED, f"Unexpected error renaming file: {exc}"

    # ── chmod 0o400 ───────────────────────────────────────────────────────
    log.debug("Setting permissions 0o400 on %s", final_path)
    try:
        set_readonly(final_path, dry_run=dry_run)
    except PermissionError as exc:
        return EXIT_PERM_ERROR, f"Cannot chmod file: {exc}"
    except OSError as exc:
        return EXIT_FS_ERROR, f"Filesystem error setting permissions: {exc}"

    # ── Audit log (optional) ──────────────────────────────────────────────
    if case_dir is not None:
        details: dict[str, str] = {
            "file": original_name,
            "sha256": hash_value,
            "renamed": "yes" if rename else "no",
            "final_path": str(final_path),
        }
        try:
            audit_log_append(case_dir, "quarantine", details)
        except Exception as exc:
            # Non-fatal: warn but do not roll back the quarantine.
            log.warning("Could not write audit log: %s", exc)

    return EXIT_OK, f"File quarantined: {final_path}"


# ── main() ─────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    exit_code, message = run(
        file_str=args.file,
        rename=args.rename,
        case_dir_str=args.case_dir,
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
