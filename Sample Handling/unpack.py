#!/usr/bin/env python3
"""
unpack.py

Safely extract zip, tar (including compressed tar), and gzip archives.

Usage:
    python unpack.py ARCHIVE [--out-dir OUT_DIR] [--password PASSWORD]
                     [--max-uncompressed BYTES] [--allow-symlinks]
                     [--case-dir CASE_DIR] [--yes] [--dry-run]

Core behaviour (SAFETY-CRITICAL):
  - Path traversal guard: ensures all extracted files resolve inside target directory.
  - Zip bomb guard: aborts if total uncompressed size exceeds max-uncompressed (default 500 MB).
  - Symlink rejection: rejects symlinks/hardlinks unless --allow-symlinks is set.
  - Permissions: sets extracted directories to 0o700 and files to 0o600.
  - Generates a sha256 hash manifest (extraction_manifest.txt) of all extracted files.
  - Supports zip, tar, tar.gz, tar.bz2, tar.xz, and single gzip formats.
  - Detects formats via file magic bytes.

Exit codes:
    0   success
    2   invalid arguments / unsupported format
    3   archive not found
    5   permission error
    6   filesystem error / path traversal attempt / zip bomb block
    7   corrupt archive / bad password
    10  unexpected error
"""

from __future__ import annotations

import argparse
import gzip
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

# ---------- toolkit_common import (optional; standalone stubs if absent) ----------
try:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent / "lib"))
    from toolkit_common import (
        setup_logging, get_logger, confirm, resolve_path,
        require_file, human_size, audit_log_append,
        find_case_root, is_case_root, compute_hash,
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
    EXIT_OK=0; EXIT_BAD_ARGS=2; EXIT_NOT_FOUND=3; EXIT_ALREADY_EXISTS=4
    EXIT_PERM_ERROR=5; EXIT_FS_ERROR=6; EXIT_VALIDATION=7; EXIT_UNEXPECTED=10

DEFAULT_MAX_UNCOMPRESSED = 500 * 1024 * 1024  # 500 MB

def detect_format(archive_path: Path) -> str | None:
    """Detect archive format based on file magic bytes."""
    try:
        with archive_path.open("rb") as f:
            magic = f.read(4)
    except Exception:
        return None

    if magic.startswith(b"PK\x03\x04") or magic.startswith(b"PK\x05\x06"):
        return "zip"
    if magic.startswith(b"\x1f\x8b"):
        # Could be tar.gz or just gzip single file. Check via tarfile.is_tarfile()
        try:
            if tarfile.is_tarfile(str(archive_path)):
                return "tar"
        except Exception:
            pass
        return "gzip_single"

    # General tar detection
    try:
        if tarfile.is_tarfile(str(archive_path)):
            return "tar"
    except Exception:
        pass

    return None

def is_safe_member_path(member_name: str, out_dir: Path) -> bool:
    """Verify that joining the member_name with out_dir stays within out_dir."""
    try:
        out_resolved = out_dir.resolve()
        joined = out_dir / member_name
        joined_resolved = joined.resolve(strict=False)
        # Avoid suffix-prefix issues: e.g. /tmp/dir vs /tmp/dir_evil
        return joined_resolved == out_resolved or out_resolved in joined_resolved.parents
    except Exception:
        return False

def set_extracted_permissions(path: Path, is_dir: bool) -> None:
    """Set directories to 0o700 and files to 0o600."""
    try:
        if is_dir:
            path.chmod(0o700)
        else:
            path.chmod(0o600)
    except Exception:
        pass

def write_manifest(out_dir: Path, extracted_files: list[Path]) -> Path:
    """Write SHA256 hashes of all extracted files to extraction_manifest.txt."""
    manifest_path = out_dir / "extraction_manifest.txt"
    lines = []
    for f_path in sorted(extracted_files):
        if f_path.is_file() and f_path != manifest_path:
            try:
                sha256 = compute_hash(f_path, "sha256")
                size = f_path.stat().st_size
                lines.append(f"{sha256}  {f_path.name}  {size}\n")
            except Exception:
                pass
    with manifest_path.open("w", encoding="utf-8") as f:
        f.writelines(lines)
    return manifest_path

def extract_zip(
    archive: Path,
    out_dir: Path,
    password: bytes | None,
    max_uncomp: int,
    allow_symlinks: bool,
    dry_run: bool,
) -> list[Path]:
    """Extract a ZIP archive safely."""
    extracted: list[Path] = []
    with zipfile.ZipFile(archive) as zf:
        if password:
            zf.setpassword(password)

        # Check total size first
        total_size = sum(info.file_size for info in zf.infolist())
        if total_size > max_uncomp:
            raise ValueError(f"Zip bomb guard: total uncompressed size ({human_size(total_size)}) exceeds limit.")

        # Dry run / display
        if dry_run:
            print("[DRY-RUN] Zip contents:")
            for info in zf.infolist():
                print(f"  {info.filename} ({human_size(info.file_size)})")
            return []

        # Validate all paths and check for symlinks
        for info in zf.infolist():
            if not is_safe_member_path(info.filename, out_dir):
                raise PermissionError(f"Path traversal detected in zip member: {info.filename}")
            
            # Check for symlink/hardlink via external_attr
            # In ZIP, Unix mode is stored in the upper 16 bits of external_attr
            attr = info.external_attr >> 16
            if attr & 0o120000 == 0o120000:  # S_IFLNK
                if not allow_symlinks:
                    raise PermissionError(f"Symlinks are disabled. Rejected zip member: {info.filename}")

        out_dir.mkdir(parents=True, exist_ok=True)
        set_extracted_permissions(out_dir, is_dir=True)

        for info in zf.infolist():
            dest = out_dir / info.filename
            
            # Ensure parent directories are created safely
            dest.parent.mkdir(parents=True, exist_ok=True)
            set_extracted_permissions(dest.parent, is_dir=True)

            # If it's a directory member
            if info.filename.endswith("/"):
                dest.mkdir(parents=True, exist_ok=True)
                set_extracted_permissions(dest, is_dir=True)
                continue

            # Extract file
            try:
                with zf.open(info) as src_file, dest.open("wb") as dest_file:
                    shutil.copyfileobj(src_file, dest_file)
            except RuntimeError as e:
                # zipfile raises RuntimeError for wrong password
                if "password" in str(e).lower() or "decrypt" in str(e).lower():
                    raise ValueError("Incorrect password or decryption failure.")
                raise e

            set_extracted_permissions(dest, is_dir=False)
            extracted.append(dest)

    return extracted

def extract_tar(
    archive: Path,
    out_dir: Path,
    max_uncomp: int,
    allow_symlinks: bool,
    dry_run: bool,
) -> list[Path]:
    """Extract a tar archive safely."""
    extracted: list[Path] = []
    with tarfile.open(archive) as tf:
        # Check size and paths
        total_size = 0
        for member in tf.getmembers():
            total_size += member.size
            if total_size > max_uncomp:
                raise ValueError(f"Zip bomb guard: total uncompressed size ({human_size(total_size)}) exceeds limit.")

            if not is_safe_member_path(member.name, out_dir):
                raise PermissionError(f"Path traversal detected in tar member: {member.name}")

            # Rejections
            if member.isdev():
                raise PermissionError(f"Device file rejected: {member.name}")
            
            if member.islnk() or member.issym():
                if not allow_symlinks:
                    raise PermissionError(f"Symlinks/links are disabled. Rejected tar member: {member.name}")

        if dry_run:
            print("[DRY-RUN] Tar contents:")
            for member in tf.getmembers():
                print(f"  {member.name} ({human_size(member.size)})")
            return []

        out_dir.mkdir(parents=True, exist_ok=True)
        set_extracted_permissions(out_dir, is_dir=True)

        for member in tf.getmembers():
            dest = out_dir / member.name
            
            # Ensure parent directories
            dest.parent.mkdir(parents=True, exist_ok=True)
            set_extracted_permissions(dest.parent, is_dir=True)

            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
                set_extracted_permissions(dest, is_dir=True)
                continue

            if member.isfile():
                with tf.extractfile(member) as src_file, dest.open("wb") as dest_file: # type: ignore
                    shutil.copyfileobj(src_file, dest_file)
                set_extracted_permissions(dest, is_dir=False)
                extracted.append(dest)
            elif (member.issym() or member.islnk()) and allow_symlinks:
                # Re-create link safely
                tf.extract(member, path=out_dir)
                extracted.append(dest)

    return extracted

def extract_gzip_single(archive: Path, out_dir: Path, dry_run: bool) -> list[Path]:
    """Decompress a single gzip file."""
    # Target filename strips .gz if present, or appends _decompressed
    stem = archive.stem
    if archive.suffix.lower() == ".gz":
        dest_filename = stem
    else:
        dest_filename = f"{archive.name}_decompressed"

    dest = out_dir / dest_filename

    if dry_run:
        print(f"[DRY-RUN] Gzip single file: would decompress to {dest.name}")
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    set_extracted_permissions(out_dir, is_dir=True)

    with gzip.open(archive, "rb") as src_file, dest.open("wb") as dest_file:
        shutil.copyfileobj(src_file, dest_file)

    set_extracted_permissions(dest, is_dir=False)
    return [dest]

def run(
    archive_str: str,
    out_dir_str: str | None,
    password_str: str | None,
    max_uncomp: int,
    allow_symlinks: bool,
    case_dir_str: str | None,
    yes: bool,
    dry_run: bool,
) -> tuple[int, str]:
    """Execute safety checks and perform archive extraction."""
    archive_path = resolve_path(archive_str)

    try:
        require_file(archive_path, "Archive")
    except FileNotFoundError as e:
        return EXIT_NOT_FOUND, str(e)
    except ValueError as e:
        return EXIT_BAD_ARGS, str(e)

    fmt = detect_format(archive_path)
    if not fmt:
        return EXIT_BAD_ARGS, f"Unsupported or unrecognized archive format for: {archive_path.name}"

    # Determine default output directory
    if out_dir_str:
        out_dir = resolve_path(out_dir_str)
    else:
        # Default: directory same as archive, named archive stem
        out_dir = archive_path.parent / archive_path.stem

    if out_dir.exists() and not out_dir.is_dir():
        return EXIT_FS_ERROR, f"Output path exists and is not a directory: {out_dir}"

    if not dry_run and not yes:
        if not confirm(f"Extract {archive_path.name} to {out_dir}? [y/N]: "):
            return EXIT_OK, "Operation cancelled by user."

    # Perform extraction
    try:
        password_bytes = password_str.encode("utf-8") if password_str else None
        extracted_files: list[Path] = []

        if fmt == "zip":
            extracted_files = extract_zip(archive_path, out_dir, password_bytes, max_uncomp, allow_symlinks, dry_run)
        elif fmt == "tar":
            extracted_files = extract_tar(archive_path, out_dir, max_uncomp, allow_symlinks, dry_run)
        elif fmt == "gzip_single":
            extracted_files = extract_gzip_single(archive_path, out_dir, dry_run)

        if dry_run:
            return EXIT_OK, "Dry-run complete."

        # Write manifest
        manifest_path = write_manifest(out_dir, extracted_files)

        # Audit log if applicable
        if case_dir_str:
            case_dir = resolve_path(case_dir_str)
            if is_case_root(case_dir):
                audit_log_append(case_dir, "unpack", {
                    "archive": archive_path.name,
                    "out_dir": str(out_dir),
                    "files_extracted": len(extracted_files),
                    "manifest": str(manifest_path),
                })

        return EXIT_OK, f"Successfully extracted {len(extracted_files)} files to {out_dir}"

    except ValueError as e:
        # Catch zip-bomb or decryption runtime errors
        return EXIT_VALIDATION, str(e)
    except PermissionError as e:
        return EXIT_PERM_ERROR, str(e)
    except OSError as e:
        return EXIT_FS_ERROR, f"Filesystem error during extraction: {e}"
    except Exception as e:
        return EXIT_UNEXPECTED, f"Unexpected error: {e}"

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    p = argparse.ArgumentParser(description="Safely extract archives with security boundaries.")
    p.add_argument("archive", help="Path to archive file to extract")
    p.add_argument("--out-dir", "-o", default=None, help="Output directory path")
    p.add_argument("--password", "-p", default=None, help="Password for zip archive")
    p.add_argument("--max-uncompressed", type=int, default=DEFAULT_MAX_UNCOMPRESSED,
                   help=f"Max total uncompressed size limit (default: {DEFAULT_MAX_UNCOMPRESSED} bytes)")
    p.add_argument("--allow-symlinks", action="store_true", help="Allow symlinks (dangerous, off by default)")
    p.add_argument("--case-dir", default=None, help="Case root directory for audit logging")
    p.add_argument("--yes", "-y", action="store_true", help="Automatically confirm extraction")
    p.add_argument("--dry-run", action="store_true", help="Show contents/would-be actions without writing")
    return p.parse_args(argv)

def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    args = parse_args(argv)
    exit_code, message = run(
        args.archive,
        args.out_dir,
        args.password,
        args.max_uncompressed,
        args.allow_symlinks,
        args.case_dir,
        args.yes,
        args.dry_run,
    )
    if exit_code != EXIT_OK:
        print(f"Error: {message}", file=sys.stderr)
    else:
        print(message)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
