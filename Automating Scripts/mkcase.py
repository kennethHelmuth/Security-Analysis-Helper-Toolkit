#!/usr/bin/env python3
"""
mkcase.py

Create a standardized malware analysis case directory tree.

Usage:
    python mkcase.py CASE_NAME [--base-dir BASE_DIR] [--dry-run]

Core behavior:
 - Creates a directory named YYYYMMDD_<sanitized_case_name> under BASE_DIR (default: ~/malware_cases)
 - Does not overwrite existing case directories (exits with error)
 - Creates the following subdirectories:
       samples/, static/, dynamic/, iocs/, notes/, output/, reports/
 - Sets permissions 0o700 on the case root
 - Supports --dry-run to show what would be done without performing filesystem changes

Implementation details:
 - Uses only Python standard library
 - Uses pathlib for path handling
 - Uses argparse for CLI
 - Includes type hints and small, testable functions
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path
from typing import List, Tuple


SUBDIRS: List[str] = ["samples", "static", "dynamic", "iocs", "notes", "output", "reports"]


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Create a malware analysis case directory with a standardized layout."
    )
    parser.add_argument(
        "case_name",
        help="Case name (will be sanitized; allowed: letters, numbers, dash, underscore)",
    )
    parser.add_argument(
        "--base-dir",
        "-b",
        default="~/malware_cases",
        help="Base directory under which the case folder will be created (default: ~/malware_cases)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be created without making any changes",
    )
    return parser.parse_args(argv)


def sanitize_case_name(raw: str) -> str:
    """
    Sanitize case name to allow only letters, numbers, dash and underscore.
    Any disallowed characters are replaced with underscore.
    """
    sanitized = re.sub(r"[^A-Za-z0-9_-]", "_", raw)
    # Trim leading/trailing underscores or dashes optionally (keeps readability)
    sanitized = sanitized.strip("_-")
    if not sanitized:
        raise ValueError("Case name is empty after sanitization. Provide a valid case_name.")
    return sanitized


def make_case_folder_name(case_name: str, today: date | None = None) -> str:
    """Return the folder name prefixed with YYYYMMDD_."""
    if today is None:
        today = date.today()
    prefix = today.strftime("%Y-%m-%d")
    return f"{prefix}_{case_name}"


def resolve_base_dir(base_dir_str: str) -> Path:
    """Return an absolute Path for the base directory (expands ~)."""
    base = Path(base_dir_str).expanduser().resolve()
    return base


def check_preconditions(base_dir: Path, case_root: Path) -> None:
    """
    Validate the base_dir and case_root conditions.
    - base_dir must not be a file (if exists)
    - case_root must not already exist (no overwrite)
    """
    if base_dir.exists() and not base_dir.is_dir():
        raise FileExistsError(f"Base path exists and is not a directory: {base_dir}")
    if case_root.exists():
        raise FileExistsError(f"Case directory already exists: {case_root}")


def create_directories(case_root: Path, subdirs: List[str], dry_run: bool = False) -> List[Path]:
    """
    Create the case_root and subdirectories.
    Returns list of created paths (absolute).
    If dry_run is True, do not perform filesystem changes; just return what would be created.
    """
    created = []
    # case_root
    created.append(case_root.resolve())
    if not dry_run:
        case_root.mkdir(parents=False, exist_ok=False)

    # subdirs
    for name in subdirs:
        p = (case_root / name).resolve()
        created.append(p)
        if not dry_run:
            p.mkdir(parents=False, exist_ok=False)
    return created


def ensure_base_dir_exists(base_dir: Path, dry_run: bool = False) -> bool:
    """
    Ensure base_dir exists. Returns True if base_dir was created (or would be created in dry-run).
    """
    if base_dir.exists():
        return False
    if dry_run:
        return True
    base_dir.mkdir(parents=True, exist_ok=True)
    return True


def set_case_root_permissions(case_root: Path, mode: int = 0o700, dry_run: bool = False) -> None:
    """Set permissions on case_root (owner rwx only)."""
    if dry_run:
        return
    # Path.chmod accepts an int like 0o700
    case_root.chmod(mode)


def print_created_paths(created: List[Path], dry_run: bool = False) -> None:
    """Print each created path. For dry-run, prefix with indication."""
    for p in created:
        if dry_run:
            print(f"[DRY-RUN] Would create: {p}")
        else:
            print(f"Created: {p}")


def run(case_name_raw: str, base_dir_str: str, dry_run: bool = False) -> Tuple[int, str]:
    """
    Perform the overall operation. Returns (exit_code, message).
    On success exit_code is 0 and message contains the case_root path message.
    On failure exit_code is non-zero and message contains an error description.
    """
    try:
        sanitized = sanitize_case_name(case_name_raw)
    except ValueError as exc:
        return 2, f"Invalid case name: {exc}"

    folder_name = make_case_folder_name(sanitized)
    base_dir = resolve_base_dir(base_dir_str)
    case_root = base_dir / folder_name

    # Check preconditions: base_dir may be created if needed; check case_root does not exist
    try:
        # If base_dir does not exist, we will create it (or indicate in dry-run)
        if base_dir.exists() and not base_dir.is_dir():
            return 3, f"Base path exists and is not a directory: {base_dir}"

        # If case_root already exists -> error (must not overwrite)
        if case_root.exists():
            return 4, f"Case directory already exists: {case_root}"

        # Ensure base_dir exists (create if needed)
        base_created = ensure_base_dir_exists(base_dir, dry_run=dry_run)
        if dry_run and base_created:
            print(f"[DRY-RUN] Would create base directory: {base_dir}")
        elif not dry_run and base_created:
            print(f"Created base directory: {base_dir}")

        # Create case_root and subdirs
        created_paths = create_directories(case_root, SUBDIRS, dry_run=dry_run)

        # Set permissions on case_root
        set_case_root_permissions(case_root, mode=0o700, dry_run=dry_run)

        # Print created paths
        print_created_paths(created_paths, dry_run=dry_run)

        if dry_run:
            return 0, f"Dry-run: Case directory would be created at: {case_root.resolve()}"
        else:
            return 0, f"Case directory created at: {case_root.resolve()}"

    except FileExistsError as fee:
        return 5, str(fee)
    except PermissionError as pe:
        return 6, f"Permission error: {pe}"
    except OSError as oe:
        return 7, f"Filesystem error: {oe}"
    except Exception as e:  # catch-all for unexpected errors
        return 10, f"Unexpected error: {e}"


def main(argv: List[str] | None = None) -> None:
    """Main entrypoint for the script."""
    args = parse_args(argv)
    exit_code, message = run(args.case_name, args.base_dir, dry_run=args.dry_run)
    if exit_code == 0:
        print(message)
        sys.exit(0)
    else:
        print(f"Error: {message}", file=sys.stderr)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
