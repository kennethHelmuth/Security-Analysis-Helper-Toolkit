#!/usr/bin/env python3
"""
toolkit_common.py

Shared utilities for the Security Analysis Helper Toolkit.

This module is imported by other scripts in the toolkit.  It is NOT designed
to be run directly.  All public symbols are stable API within this toolkit.

Provides
--------
setup_logging(verbose, quiet)       Configure stdlib logging; return Logger.
get_logger(name)                    Return a child logger under 'toolkit'.
confirm(prompt, default_no)         Interactive yes/no prompt; safe default = No.
resolve_path(raw)                   Expand ~ and resolve to absolute Path.
require_file(path, label)           Raise if path is not a regular file.
require_dir(path, label)            Raise if path is not a directory.
human_size(n_bytes)                 Format byte count as human-readable string.
audit_log_append(case_root, ...)    Append a structured line to the case audit log.
find_case_root(path)                Walk upward to find a mkcase.py case root.
EXIT_*                              Documented exit code constants.

Python 3.11+.  Standard library only.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------- Exit code constants ----------
EXIT_OK             = 0   # success
EXIT_BAD_ARGS       = 2   # invalid arguments or missing required input
EXIT_NOT_FOUND      = 3   # file or directory does not exist
EXIT_ALREADY_EXISTS = 4   # output would overwrite an existing resource
EXIT_PERM_ERROR     = 5   # permission denied
EXIT_FS_ERROR       = 6   # generic filesystem / OS error
EXIT_VALIDATION     = 7   # input failed validation
EXIT_UNEXPECTED     = 10  # catch-all for unexpected exceptions


# ---------- Logging ----------
_LOG_FMT = "%(asctime)s %(levelname)s %(message)s"
_LOGGER_NAME = "toolkit"


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """
    Configure and return the root toolkit logger.

    verbose=True  -> DEBUG level
    quiet=True    -> WARNING level (suppresses INFO)
    default       -> INFO level

    Attaches a single StreamHandler to stdout (keeps stderr clean for errors).
    Safe to call multiple times; existing handlers are replaced each call.
    """
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    if quiet:
        level = logging.WARNING

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_LOG_FMT))
    logger.addHandler(handler)
    return logger


def get_logger(name: str = _LOGGER_NAME) -> logging.Logger:
    """Return a child logger under the 'toolkit' namespace."""
    return logging.getLogger(name)


# ---------- Interactive confirmation ----------
def confirm(prompt: str = "Proceed? [y/N]: ", default_no: bool = True) -> bool:
    """
    Prompt the user for yes/no confirmation.

    Returns True only if the user types 'y' or 'Y'.
    If stdin is not available (piped / EOF), defaults to False (safe default).
    """
    try:
        resp = input(prompt).strip().lower()
    except EOFError:
        return False
    return resp == "y"


# ---------- Path helpers ----------
def resolve_path(raw: str) -> Path:
    """
    Expand '~' and resolve to an absolute Path.
    Does NOT require the path to exist.
    """
    return Path(raw).expanduser().resolve()


def require_file(path: Path, label: str = "File") -> None:
    """
    Raise FileNotFoundError if path does not exist or is not a regular file.
    The label is used in the error message for clarity.
    """
    if not path.exists():
        raise FileNotFoundError(f"{label} does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"{label} is not a regular file: {path}")


def require_dir(path: Path, label: str = "Directory") -> None:
    """
    Raise FileNotFoundError / NotADirectoryError if path is not a directory.
    """
    if not path.exists():
        raise FileNotFoundError(f"{label} does not exist: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"{label} is not a directory: {path}")


# ---------- Human-readable formatting ----------
def human_size(n_bytes: int) -> str:
    """
    Return a human-readable representation of a byte count.

    Examples
    --------
    human_size(500)         -> "500 B"
    human_size(2048)        -> "2.0 KB"
    human_size(1_500_000)   -> "1.4 MB"
    """
    if n_bytes < 1024:
        return f"{n_bytes} B"
    n: float = float(n_bytes)
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


# ---------- Case subdirectory constants ----------
# Canonical subdirectory names created by mkcase.py.
# Used by multiple tools to detect and validate case roots.
CASE_SUBDIRS: frozenset[str] = frozenset(
    {"samples", "static", "dynamic", "iocs", "notes", "output", "reports"}
)
_MIN_CASE_MATCH = 3  # minimum overlap to identify a case root


def is_case_root(path: Path) -> bool:
    """
    Return True if path looks like a mkcase.py case root.

    Checks that at least _MIN_CASE_MATCH of the canonical subdirectories
    are present as immediate children.
    """
    if not path.is_dir():
        return False
    try:
        children = {p.name for p in path.iterdir() if p.is_dir()}
    except PermissionError:
        return False
    return len(children & CASE_SUBDIRS) >= _MIN_CASE_MATCH


def find_case_root(path: Path) -> Path | None:
    """
    Walk upward from path to locate a mkcase.py case root directory.

    A directory is considered a case root if at least three of the
    canonical subdirectories (samples, static, dynamic, iocs, notes,
    output, reports) are present as immediate children.

    Returns the case root Path, or None if not found within 6 levels.
    """
    candidate = path if path.is_dir() else path.parent
    for _ in range(6):
        if candidate == candidate.parent:
            break
        if is_case_root(candidate):
            return candidate
        candidate = candidate.parent
    return None


# ---------- Case audit log ----------
AUDIT_LOG_FILENAME = "audit.log"


def _iso_now() -> str:
    """Return current UTC time as an ISO-8601 string (seconds precision)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def audit_log_append(
    case_root: Path,
    event_type: str,
    details: dict[str, Any] | None = None,
) -> Path:
    """
    Append a single structured line to the case audit log.

    The log lives at <case_root>/audit.log. Each line has the form::

        [2026-06-25T08:00:00+00:00]  event_type  key=value  key=value ...

    The format is plain text, one event per line, grep/awk/tail friendly.

    Returns the Path to the audit log file.
    Raises OSError / PermissionError on write failure.

    Parameters
    ----------
    case_root : Path
        Root directory of the case (created by mkcase.py).
    event_type : str
        Short identifier for the event, e.g. "addsample", "unpack".
    details : dict, optional
        Key-value pairs appended after the event type.  Values are
        sanitized (newlines stripped, whitespace trimmed).
    """
    log_path = case_root / AUDIT_LOG_FILENAME
    ts = _iso_now()
    parts: list[str] = [f"[{ts}]", event_type]
    if details:
        for k, v in details.items():
            safe_v = str(v).replace("\n", " ").replace("\r", "").strip()
            parts.append(f"{k}={safe_v}")
    line = "  ".join(parts) + "\n"
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(line)
    return log_path


# ---------- Hash utility ----------
# Re-exported here so scripts that only need a hash don't also have to import
# hashlib directly.  Streaming, safe for large files.
_READ_CHUNK = 64 * 1024  # 64 KiB


def compute_hash(file_path: Path, algorithm: str = "sha256", chunk_size: int = _READ_CHUNK) -> str:
    """
    Compute the hash of file_path using the given algorithm.

    Reads the file in streaming chunks to handle arbitrarily large files.
    Returns the lowercase hex digest string.

    Raises
    ------
    PermissionError  if the file cannot be opened for reading.
    OSError          for other I/O errors.
    ValueError       if the algorithm is not supported by hashlib.
    """
    import hashlib
    hasher = hashlib.new(algorithm.lower())
    with file_path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


SUPPORTED_HASH_ALGORITHMS: tuple[str, ...] = ("md5", "sha1", "sha256", "sha512")


def validate_algorithm(alg: str) -> str:
    """
    Validate and normalise a hash algorithm name.

    Returns the lowercase algorithm name.
    Raises ValueError if not in SUPPORTED_HASH_ALGORITHMS.
    """
    normalized = alg.lower()
    if normalized not in SUPPORTED_HASH_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{alg}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_HASH_ALGORITHMS))}"
        )
    return normalized
