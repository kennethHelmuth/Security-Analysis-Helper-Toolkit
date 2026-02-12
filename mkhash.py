#!/usr/bin/env python3
"""
mkhash.py

Generate a cryptographic hash for a file and optionally save it to a dated log file.

Usage:
    python mkhash.py FILE_PATH ALGORITHM [--out-dir OUT_DIR] [--append] [--yes]

Requirements:
 - Python 3.11+
 - Only standard library
 - Uses pathlib, argparse, hashlib, datetime
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import datetime, date
from pathlib import Path
from typing import IO


# Supported algorithms (lowercase)
SUPPORTED_ALGS = {"md5", "sha1", "sha256", "sha512"}
DEFAULT_OUT_DIR = "~/malware_cases/hashes"
READ_CHUNK = 64 * 1024  # 64 KiB


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    p = argparse.ArgumentParser(description="Compute file hash and optionally log it to a dated file.")
    p.add_argument("file_path", help="Path to the file to hash")
    p.add_argument("algorithm", help="Hash algorithm (md5, sha1, sha256, sha512)")
    p.add_argument(
        "--out-dir",
        "-o",
        default=DEFAULT_OUT_DIR,
        help=f"Output directory to store hashes (default: {DEFAULT_OUT_DIR})",
    )
    p.add_argument(
        "--append",
        action="store_true",
        help="Append to existing daily log instead of erroring when log exists",
    )
    p.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Automatically save without asking for confirmation",
    )
    return p.parse_args(argv)


def validate_algorithm(alg: str) -> str:
    """
    Validate the requested algorithm and return normalized algorithm name.
    Raises ValueError if unsupported.
    """
    normalized = alg.lower()
    if normalized not in SUPPORTED_ALGS:
        raise ValueError(f"Unsupported algorithm '{alg}'. Supported: {', '.join(sorted(SUPPORTED_ALGS))}")
    return normalized


def compute_hash(file_path: Path, algorithm: str, chunk_size: int = READ_CHUNK) -> str:
    """
    Compute hash for the file using streaming reads.
    Returns hex digest string.
    """
    hasher = hashlib.new(algorithm)
    try:
        with file_path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
    except PermissionError as e:
        raise PermissionError(f"Permission denied reading file: {file_path}") from e
    except OSError as e:
        raise OSError(f"Error reading file: {file_path} : {e}") from e
    return hasher.hexdigest()


def confirm_save(prompt_text: str = "Save this hash to log file? [y/N]: ") -> bool:
    """
    Prompt the user for yes/no confirmation. Default is No.
    Returns True only if user types 'y' or 'Y'.
    """
    try:
        resp = input(prompt_text).strip().lower()
    except EOFError:
        # If input is not available, default to No
        return False
    return resp == "y"


def get_log_file_path(out_dir: Path, today_date: date | None = None) -> Path:
    """
    Return the Path to the dated log file: YYYY-MM-DD_hashes.txt under out_dir.
    """
    if today_date is None:
        today_date = date.today()
    filename = f"{today_date.strftime('%Y-%m-%d')}_hashes.txt"
    return out_dir / filename


def write_hash_log(
    out_dir: Path,
    algorithm: str,
    file_name: str,
    hash_value: str,
    append: bool = False,
    timestamp: datetime | None = None,
) -> Path:
    """
    Write (append) a single line to the dated log file.
    If append is False and the log file already exists, raises FileExistsError.
    Returns the Path to the log file written.
    """
    if timestamp is None:
        timestamp = datetime.now()

    # Ensure directory exists
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        raise PermissionError(f"Cannot create output directory: {out_dir}") from e
    except OSError as e:
        raise OSError(f"Error creating output directory: {out_dir} : {e}") from e

    log_path = get_log_file_path(out_dir, today_date=timestamp.date())

    if log_path.exists() and not append:
        # Spec requires error if log exists and append not set
        raise FileExistsError(f"Log file already exists: {log_path} (use --append to append)")

    line = f"[{timestamp.strftime('%H:%M:%S')}] {algorithm}  {file_name}  {hash_value}\n"

    # Open file in append mode (create if missing)
    try:
        with log_path.open("a", encoding="utf-8") as fh:  # append will create if not exists
            fh.write(line)
    except PermissionError as e:
        raise PermissionError(f"Permission denied writing to log file: {log_path}") from e
    except OSError as e:
        raise OSError(f"Error writing to log file: {log_path} : {e}") from e

    return log_path


def print_result(algorithm: str, file_path: Path, hash_value: str) -> None:
    """Print the computed hash in the required format."""
    print(f"Algorithm : {algorithm}")
    print(f"File      : {file_path.name}")
    print(f"Hash      : {hash_value}")


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    args = parse_args(argv)

    # Resolve file path
    file_path = Path(args.file_path).expanduser()
    try:
        file_path = file_path.resolve(strict=False)
    except Exception:
        # resolve may fail for permission reasons; continue with given path
        file_path = Path(args.file_path).expanduser()

    # Validate file exists and is a file
    if not file_path.exists() or not file_path.is_file():
        print(f"Error: File does not exist or is not a regular file: {file_path}", file=sys.stderr)
        sys.exit(3)

    # Validate algorithm
    try:
        algorithm = validate_algorithm(args.algorithm)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    # Compute hash
    try:
        hash_value = compute_hash(file_path, algorithm)
    except PermissionError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(4)
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(5)
    except Exception as e:
        print(f"Unexpected error while hashing file: {e}", file=sys.stderr)
        sys.exit(10)

    # Print result
    print_result(algorithm, file_path, hash_value)

    # Determine whether to save
    save_decision = args.yes or confirm_save()
    if not save_decision:
        print("Not saved.")
        sys.exit(0)

    # Prepare out_dir
    out_dir = Path(args.out_dir).expanduser().resolve()

    # Attempt to write log
    try:
        log_path = write_hash_log(out_dir, algorithm, file_path.name, hash_value, append=args.append)
    except FileExistsError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(6)
    except PermissionError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(7)
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(8)
    except Exception as e:
        print(f"Unexpected error while writing log: {e}", file=sys.stderr)
        sys.exit(11)

    print(f"Saved to: {log_path}")
    sys.exit(0)


if __name__ == "__main__":
    main()
