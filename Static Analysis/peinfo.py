#!/usr/bin/env python3
"""
peinfo.py

Parse Windows PE/COFF file headers and produce a structured static analysis report.

Usage:
    python peinfo.py FILE [--out-dir OUT_DIR] [--json] [--case-dir CASE_DIR] [--dry-run]

Core behaviour:
  - Reads FILE as a binary PE image (capped at 100 MB)
  - Validates the MZ and PE signatures; exits with error code 6 if not a PE
  - Parses: DOS header, COFF header, Optional header (PE32 and PE32+), section
    table, import directory, export directory, and debug directory (CodeView PDB path)
  - Uses ONLY Python standard library struct module — no pefile dependency
  - Prints a human-readable summary to stdout (or JSON with --json)
  - With --out-dir: writes a JSON report to OUT_DIR/FILENAME_peinfo.json
  - With --case-dir: writes to case static/ subdirectory and appends audit log
  - Supports --dry-run to parse and display without writing files

Implementation details:
  - Uses only Python standard library (struct, json, math, datetime, argparse, pathlib)
  - Imports toolkit_common if available; falls back to inline stubs if not
  - All struct parsing wrapped in try/except; partial results returned on error
  - Per-section entropy calculated using Shannon formula
  - Import table capped at 1 000 DLLs and 10 000 total functions (DoS safety)
  - Export name table capped at 10 000 names

Exit codes:
    0   success
    2   invalid arguments
    3   file not found or not a regular file
    5   permission error
    6   not a valid PE file / parse error
    10  unexpected error
"""

from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from datetime import datetime, timezone
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
    def resolve_path(raw):
        return Path(raw).expanduser().resolve()
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

# ---------- Constants ----------
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

MACHINES: dict[int, str] = {
    0x0000: "Any",
    0x014c: "x86 (i386)",
    0x8664: "x86-64 (AMD64)",
    0x0200: "Intel Itanium (IA-64)",
    0x01c4: "ARM Thumb-2",
    0xaa64: "ARM64",
    0x01c0: "ARM (little-endian)",
    0x0266: "MIPS16",
    0x0366: "MIPS FPU",
    0x0466: "MIPS FPU16",
    0x01f0: "PowerPC",
    0x01f1: "PowerPC FP",
    0x0162: "MIPS (R3000)",
    0x0168: "MIPS (R10000)",
    0x0169: "MIPS (WCE v2)",
    0x01a2: "Hitachi SH3",
    0x01a6: "Hitachi SH4",
    0x01a8: "Hitachi SH5",
    0x01d3: "Matsushita AM33",
    0x01f9: "EFI Byte Code",
    0x0200: "IA64",
    0x5032: "RISC-V 32-bit",
    0x5064: "RISC-V 64-bit",
    0x5128: "RISC-V 128-bit",
}

SUBSYSTEMS: dict[int, str] = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot Application",
}

CHARACTERISTICS_FLAGS: list[tuple[int, str]] = [
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"),
    (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0100, "BYTES_REVERSED_LO"),
    (0x0200, "IS_32BIT"),
    (0x0400, "DEBUG_STRIPPED"),
    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),
    (0x4000, "UP_SYSTEM_ONLY"),
    (0x8000, "BYTES_REVERSED_HI"),
]

SECTION_FLAGS: list[tuple[int, str]] = [
    (0x00000020, "CODE"),
    (0x00000040, "INITIALIZED_DATA"),
    (0x00000080, "UNINITIALIZED_DATA"),
    (0x02000000, "DISCARDABLE"),
    (0x04000000, "NOT_CACHED"),
    (0x08000000, "NOT_PAGED"),
    (0x10000000, "SHARED"),
    (0x20000000, "EXECUTE"),
    (0x40000000, "READ"),
    (0x80000000, "WRITE"),
]

DLL_CHARACTERISTICS_FLAGS: list[tuple[int, str]] = [
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]

_MAX_IMPORT_DLLS  = 1_000
_MAX_IMPORT_FUNCS = 10_000
_MAX_EXPORT_NAMES = 10_000
_MAX_DEBUG_ENTRIES = 100


# ---------- Low-level read helpers ----------
def read_u16(data: bytes, offset: int) -> int:
    """Unpack a little-endian unsigned 16-bit integer from data at offset."""
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data: bytes, offset: int) -> int:
    """Unpack a little-endian unsigned 32-bit integer from data at offset."""
    return struct.unpack_from("<I", data, offset)[0]


def read_u64(data: bytes, offset: int) -> int:
    """Unpack a little-endian unsigned 64-bit integer from data at offset."""
    return struct.unpack_from("<Q", data, offset)[0]


def read_cstr(data: bytes, offset: int, max_len: int = 260) -> str:
    """
    Read a null-terminated C string from data at offset.
    Decodes as UTF-8 with replacement for non-UTF-8 bytes.
    """
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, offset + max_len)
    if end == -1:
        end = min(offset + max_len, len(data))
    try:
        return data[offset:end].decode("utf-8", errors="replace")
    except Exception:
        return ""


def decode_flags(value: int, flag_table: list[tuple[int, str]]) -> list[str]:
    """Return a list of flag names present in value."""
    return [name for mask, name in flag_table if value & mask]


# ---------- Section RVA resolution ----------
def rva_to_offset(rva: int, sections: list[dict[str, Any]]) -> int | None:
    """
    Convert a Relative Virtual Address (RVA) to a file offset.

    Iterates the section table and finds which section the RVA falls into,
    then computes the corresponding raw file offset.  Returns None if the
    RVA does not map into any section.
    """
    for s in sections:
        va      = s["virtual_address"]
        raw     = s["pointer_to_raw_data"]
        raw_sz  = s["size_of_raw_data"]
        vsz     = s["virtual_size"]
        span    = max(vsz, raw_sz)
        if span > 0 and va <= rva < va + span:
            return raw + (rva - va)
    return None


# ---------- Entropy ----------
def section_entropy(data: bytes, raw_offset: int, raw_size: int) -> float:
    """
    Compute the Shannon entropy of the raw bytes of a section.

    Returns a float in [0, 8] (bits per byte).  Returns 0.0 for empty sections.
    """
    if raw_size == 0 or raw_offset >= len(data):
        return 0.0
    end = min(raw_offset + raw_size, len(data))
    chunk = data[raw_offset:end]
    if not chunk:
        return 0.0
    freq: list[int] = [0] * 256
    for b in chunk:
        freq[b] += 1
    total = len(chunk)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ---------- Parse sections ----------
def parse_sections(data: bytes, section_table_offset: int, num_sections: int) -> list[dict[str, Any]]:
    """
    Parse the PE section table.

    Returns a list of dicts with keys:
        name, virtual_size, virtual_address, size_of_raw_data,
        pointer_to_raw_data, characteristics, flags, entropy
    """
    sections: list[dict[str, Any]] = []
    SECTION_ENTRY_SIZE = 40
    for i in range(num_sections):
        off = section_table_offset + i * SECTION_ENTRY_SIZE
        if off + SECTION_ENTRY_SIZE > len(data):
            break
        try:
            (raw_name, vsz, va, raw_sz, raw_ptr,
             ptr_relocs, ptr_lines, num_relocs, num_lines, chars) = struct.unpack_from(
                "<8sIIIIIIHHI", data, off
            )
        except struct.error:
            break
        name_str = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")
        ent = section_entropy(data, raw_ptr, raw_sz)
        sections.append({
            "name": name_str,
            "virtual_size": vsz,
            "virtual_address": va,
            "size_of_raw_data": raw_sz,
            "pointer_to_raw_data": raw_ptr,
            "characteristics": chars,
            "flags": decode_flags(chars, SECTION_FLAGS),
            "entropy": ent,
        })
    return sections


# ---------- Parse imports ----------
def parse_imports(
    data: bytes,
    import_rva: int,
    sections: list[dict[str, Any]],
    is_64bit: bool,
) -> list[dict[str, Any]]:
    """
    Parse the Import Directory Table.

    Returns a list of dicts: {dll_name: str, functions: list[str]}
    Capped at _MAX_IMPORT_DLLS DLLs and _MAX_IMPORT_FUNCS total functions.
    """
    result: list[dict[str, Any]] = []
    if import_rva == 0:
        return result

    offset = rva_to_offset(import_rva, sections)
    if offset is None:
        return result

    DESCRIPTOR_SIZE = 20  # IMAGE_IMPORT_DESCRIPTOR
    thunk_size  = 8 if is_64bit else 4
    thunk_fmt   = "<Q" if is_64bit else "<I"
    ordinal_flag = (1 << 63) if is_64bit else (1 << 31)
    total_funcs = 0

    for dll_idx in range(_MAX_IMPORT_DLLS):
        entry_off = offset + dll_idx * DESCRIPTOR_SIZE
        if entry_off + DESCRIPTOR_SIZE > len(data):
            break
        try:
            orig_first_thunk, timestamp, fwd_chain, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", data, entry_off
            )
        except struct.error:
            break

        # All-zero entry is the null terminator
        if name_rva == 0 and first_thunk == 0:
            break

        name_off = rva_to_offset(name_rva, sections)
        dll_name = read_cstr(data, name_off) if name_off is not None else f"DLL@RVA_{name_rva:#010x}"

        functions: list[str] = []
        thunk_rva = orig_first_thunk if orig_first_thunk else first_thunk
        if thunk_rva:
            thunk_off = rva_to_offset(thunk_rva, sections)
            if thunk_off is not None:
                func_idx = 0
                while total_funcs < _MAX_IMPORT_FUNCS:
                    t_off = thunk_off + func_idx * thunk_size
                    if t_off + thunk_size > len(data):
                        break
                    try:
                        (thunk_val,) = struct.unpack_from(thunk_fmt, data, t_off)
                    except struct.error:
                        break
                    if thunk_val == 0:
                        break
                    if thunk_val & ordinal_flag:
                        ordinal = thunk_val & 0xFFFF
                        functions.append(f"Ordinal#{ordinal}")
                    else:
                        # IMAGE_IMPORT_BY_NAME: 2-byte hint + null-terminated name
                        clean_rva = thunk_val & ~ordinal_flag
                        ibn_off = rva_to_offset(clean_rva, sections)
                        if ibn_off is not None and ibn_off + 2 < len(data):
                            func_name = read_cstr(data, ibn_off + 2)
                            functions.append(func_name or f"Hint@{ibn_off + 2:#010x}")
                        else:
                            functions.append(f"RVA_{clean_rva:#010x}")
                    func_idx += 1
                    total_funcs += 1

        result.append({"dll_name": dll_name, "functions": functions})

    return result


# ---------- Parse exports ----------
def parse_exports(
    data: bytes,
    export_rva: int,
    sections: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Parse the Export Directory Table.

    Returns a dict with keys: dll_name (str | None), functions (list[str]).
    """
    out: dict[str, Any] = {"dll_name": None, "functions": []}
    if export_rva == 0:
        return out

    offset = rva_to_offset(export_rva, sections)
    if offset is None or offset + 40 > len(data):
        return out

    try:
        # IMAGE_EXPORT_DIRECTORY (40 bytes)
        (characteristics, timestamp, major_ver, minor_ver, name_rva,
         ordinal_base, num_funcs, num_names,
         addr_of_funcs, addr_of_names, addr_of_ords) = struct.unpack_from(
            "<IIHHIIIIIII", data, offset
        )
    except struct.error:
        return out

    name_off = rva_to_offset(name_rva, sections)
    if name_off is not None:
        out["dll_name"] = read_cstr(data, name_off)

    # Walk name pointer table
    names_off = rva_to_offset(addr_of_names, sections)
    if names_off is not None and num_names > 0:
        functions: list[str] = []
        for i in range(min(num_names, _MAX_EXPORT_NAMES)):
            ptr_off = names_off + i * 4
            if ptr_off + 4 > len(data):
                break
            try:
                (name_ptr_rva,) = struct.unpack_from("<I", data, ptr_off)
            except struct.error:
                break
            fn_off = rva_to_offset(name_ptr_rva, sections)
            if fn_off is not None:
                functions.append(read_cstr(data, fn_off))
        out["functions"] = functions

    return out


# ---------- Parse debug directory (PDB paths) ----------
def parse_debug_pdb(
    data: bytes,
    debug_rva: int,
    debug_size: int,
    sections: list[dict[str, Any]],
) -> list[str]:
    """
    Walk the Debug Directory for CodeView (type 2) entries and extract PDB paths.

    Returns a list of PDB path strings found in the file.
    """
    pdb_paths: list[str] = []
    if debug_rva == 0:
        return pdb_paths

    offset = rva_to_offset(debug_rva, sections)
    if offset is None:
        return pdb_paths

    DEBUG_ENTRY_SIZE = 28
    num_entries = min(debug_size // DEBUG_ENTRY_SIZE, _MAX_DEBUG_ENTRIES) if debug_size else _MAX_DEBUG_ENTRIES

    for i in range(num_entries):
        entry_off = offset + i * DEBUG_ENTRY_SIZE
        if entry_off + DEBUG_ENTRY_SIZE > len(data):
            break
        try:
            # IMAGE_DEBUG_DIRECTORY: characteristics(I) timestamp(I) major(H) minor(H)
            #   type(I) size_of_data(I) addr_of_raw(I) ptr_to_raw(I)
            (characteristics, timestamp, major_ver, minor_ver,
             debug_type, size_of_data, addr_of_raw, ptr_to_raw) = struct.unpack_from(
                "<IIHH IIII", data, entry_off
            )
        except struct.error:
            break

        # Stop at null terminator entry
        if debug_type == 0 and size_of_data == 0 and ptr_to_raw == 0:
            break

        if debug_type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue

        if ptr_to_raw == 0 or ptr_to_raw + 4 > len(data):
            continue

        cv_sig = data[ptr_to_raw:ptr_to_raw + 4]

        if cv_sig == b"RSDS":
            # RSDS: 4-byte sig + 16-byte GUID + 4-byte Age + null-terminated PDB path
            pdb_off = ptr_to_raw + 4 + 16 + 4
            if pdb_off < len(data):
                pdb = read_cstr(data, pdb_off, max_len=512)
                if pdb:
                    pdb_paths.append(pdb)

        elif cv_sig == b"NB10":
            # NB10: 4-byte sig + 4-byte offset + 4-byte timestamp + 4-byte age + null-terminated path
            pdb_off = ptr_to_raw + 4 + 4 + 4 + 4
            if pdb_off < len(data):
                pdb = read_cstr(data, pdb_off, max_len=512)
                if pdb:
                    pdb_paths.append(pdb)

    return pdb_paths


# ---------- Main parse routine ----------
def parse_pe(data: bytes) -> dict[str, Any]:
    """
    Parse a PE binary from raw bytes.

    Returns a dict with all parsed fields.  On format errors, returns a dict
    with 'error' key set and as much partial data as was successfully parsed.
    """
    result: dict[str, Any] = {"valid": False}

    if len(data) < 64:
        result["error"] = "File too small for DOS header"
        return result

    # DOS header
    e_magic = read_u16(data, 0)
    if e_magic != 0x5A4D:  # 'MZ'
        result["error"] = f"Invalid DOS magic: {e_magic:#06x} (expected 0x5a4d 'MZ')"
        return result
    result["dos_magic"] = "MZ"

    e_lfanew = read_u32(data, 0x3C)
    result["pe_header_offset"] = e_lfanew

    if e_lfanew + 24 > len(data):
        result["error"] = "PE header offset beyond file size"
        return result

    # PE signature
    pe_sig = data[e_lfanew:e_lfanew + 4]
    if pe_sig != b"PE\x00\x00":
        result["error"] = f"Invalid PE signature at offset {e_lfanew:#010x}: {pe_sig!r}"
        return result
    result["pe_signature"] = "PE"

    # COFF header (20 bytes at e_lfanew + 4)
    coff_off = e_lfanew + 4
    if coff_off + 20 > len(data):
        result["error"] = "COFF header truncated"
        return result

    (machine, num_sections, timestamp, ptr_sym_table,
     num_syms, sz_opt_hdr, characteristics) = struct.unpack_from("<HHIIIHH", data, coff_off)

    compile_time_utc = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    result["coff"] = {
        "machine": machine,
        "machine_name": MACHINES.get(machine, f"Unknown ({machine:#06x})"),
        "num_sections": num_sections,
        "timestamp": timestamp,
        "timestamp_utc": compile_time_utc,
        "sz_optional_header": sz_opt_hdr,
        "characteristics": characteristics,
        "characteristic_flags": decode_flags(characteristics, CHARACTERISTICS_FLAGS),
    }

    # Optional header
    opt_off = e_lfanew + 24  # = coff_off + 20
    if sz_opt_hdr < 2 or opt_off + sz_opt_hdr > len(data):
        result["error"] = "Optional header missing or truncated"
        return result

    opt_magic = read_u16(data, opt_off)
    is_64bit = (opt_magic == 0x020B)  # PE32+
    is_32bit = (opt_magic == 0x010B)  # PE32

    if not (is_32bit or is_64bit):
        result["error"] = f"Unsupported optional header magic: {opt_magic:#06x}"
        return result

    result["format"] = "PE32+" if is_64bit else "PE32"

    # Fields common to both PE32 and PE32+
    entry_point = read_u32(data, opt_off + 0x10)

    if is_32bit:
        image_base     = read_u32(data, opt_off + 0x1C)
        subsystem      = read_u16(data, opt_off + 0x44)
        dll_chars      = read_u16(data, opt_off + 0x46)
        num_data_dirs  = read_u32(data, opt_off + 0x5C)
        data_dirs_off  = opt_off + 0x60
    else:
        image_base     = read_u64(data, opt_off + 0x18)
        subsystem      = read_u16(data, opt_off + 0x44)
        dll_chars      = read_u16(data, opt_off + 0x46)
        num_data_dirs  = read_u32(data, opt_off + 0x6C)
        data_dirs_off  = opt_off + 0x70

    # Read data directory entries (RVA + Size pairs, 8 bytes each)
    data_dirs: list[dict[str, int]] = []
    for di in range(min(num_data_dirs, 16)):
        dir_off = data_dirs_off + di * 8
        if dir_off + 8 > len(data):
            break
        rva_d  = read_u32(data, dir_off)
        size_d = read_u32(data, dir_off + 4)
        data_dirs.append({"rva": rva_d, "size": size_d})

    # Pad to 16 entries for safe index access
    while len(data_dirs) < 16:
        data_dirs.append({"rva": 0, "size": 0})

    result["optional_header"] = {
        "magic": opt_magic,
        "entry_point_rva": entry_point,
        "image_base": image_base,
        "subsystem": subsystem,
        "subsystem_name": SUBSYSTEMS.get(subsystem, f"Unknown ({subsystem})"),
        "dll_characteristics": dll_chars,
        "dll_characteristic_flags": decode_flags(dll_chars, DLL_CHARACTERISTICS_FLAGS),
    }

    # Section table (starts immediately after the optional header)
    section_table_off = opt_off + sz_opt_hdr
    sections = parse_sections(data, section_table_off, num_sections)
    result["sections"] = sections

    # Imports (data_dir[1])
    import_rva  = data_dirs[1]["rva"]
    result["imports"] = parse_imports(data, import_rva, sections, is_64bit)

    # Exports (data_dir[0])
    export_rva  = data_dirs[0]["rva"]
    result["exports"] = parse_exports(data, export_rva, sections)

    # Debug / PDB (data_dir[6])
    debug_rva  = data_dirs[6]["rva"]
    debug_size = data_dirs[6]["size"]
    result["pdb_paths"] = parse_debug_pdb(data, debug_rva, debug_size, sections)

    result["valid"] = True
    return result


# ---------- Output formatting ----------
def format_pe_human(file_path: Path, info: dict[str, Any]) -> str:
    """Render the parsed PE info as a human-readable string."""
    lines: list[str] = []
    add = lines.append

    add(f"File         : {file_path.name}")
    add(f"Path         : {file_path}")
    add(f"Size         : {human_size(file_path.stat().st_size)}  ({file_path.stat().st_size:,} bytes)")

    if not info.get("valid"):
        add(f"Error        : {info.get('error', 'Unknown parse error')}")
        return "\n".join(lines)

    coff = info.get("coff", {})
    opt  = info.get("optional_header", {})

    add(f"Format       : {info.get('format', 'Unknown')}")
    add(f"Architecture : {coff.get('machine_name', 'Unknown')}")

    char_flags = coff.get("characteristic_flags", [])
    file_type = "DLL" if "DLL" in char_flags else "Executable"
    add(f"Type         : {file_type}  (flags: {', '.join(char_flags) or 'none'})")

    ts    = coff.get("timestamp", 0)
    ts_str = coff.get("timestamp_utc", "Unknown")
    add(f"Compile Time : {ts_str}  (Unix: {ts})")

    ib = opt.get("image_base", 0)
    add(f"Image Base   : {ib:#018x}")
    ep = opt.get("entry_point_rva", 0)
    add(f"Entry Point  : {ib + ep:#018x}  (RVA: {ep:#010x})")
    add(f"Subsystem    : {opt.get('subsystem_name', 'Unknown')}")

    dll_flags = opt.get("dll_characteristic_flags", [])
    add(f"DLL Chars    : {', '.join(dll_flags) or 'none'}")

    sections = info.get("sections", [])
    add(f"\nSections ({len(sections)}):")
    for s in sections:
        flags_str = "|".join(s.get("flags", [])) or "none"
        add(
            f"  {s['name']:<10} VA={s['virtual_address']:#010x}  "
            f"Raw={s['size_of_raw_data']:#010x}  "
            f"Entropy={s['entropy']:.2f}  "
            f"Flags={flags_str}"
        )

    imports = info.get("imports", [])
    if imports:
        total_funcs = sum(len(d["functions"]) for d in imports)
        add(f"\nImports ({len(imports)} DLLs, {total_funcs} functions):")
        for dll_info in imports:
            funcs = dll_info["functions"]
            preview = ", ".join(funcs[:8])
            suffix = f", ... (+{len(funcs) - 8} more)" if len(funcs) > 8 else ""
            add(f"  {dll_info['dll_name']}: {preview}{suffix}")
    else:
        add("\nImports: none")

    exports = info.get("exports", {})
    export_funcs = exports.get("functions", [])
    if export_funcs:
        export_dll = exports.get("dll_name") or "(unnamed)"
        add(f"\nExports: {export_dll}  ({len(export_funcs)} functions)")
        for fn in export_funcs[:20]:
            add(f"  {fn}")
        if len(export_funcs) > 20:
            add(f"  ... (+{len(export_funcs) - 20} more)")
    else:
        add("\nExports: none")

    pdb_paths = info.get("pdb_paths", [])
    if pdb_paths:
        add("\nPDB Paths:")
        for p in pdb_paths:
            add(f"  {p}")

    return "\n".join(lines)


# ---------- CLI ----------
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    p = argparse.ArgumentParser(
        description="Parse Windows PE headers (stdlib only — no pefile dependency)."
    )
    p.add_argument("file", help="PE file to analyse")
    p.add_argument(
        "--out-dir", "-o",
        default=None,
        help="Directory to write FILENAME_peinfo.json report",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Print parsed data as JSON to stdout",
    )
    p.add_argument(
        "--case-dir",
        default=None,
        help="Case root directory; writes report to case static/ and appends audit log",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and display; do not write any output files",
    )
    return p.parse_args(argv)


def run(
    file_str: str,
    out_dir_str: str | None,
    use_json: bool,
    case_dir_str: str | None,
    dry_run: bool,
) -> tuple[int, str]:
    """
    Perform the PE analysis operation.

    Returns (exit_code, message).  exit_code == 0 on success.
    """
    file_path = resolve_path(file_str)

    try:
        require_file(file_path, "PE file")
    except FileNotFoundError as e:
        return EXIT_NOT_FOUND, str(e)
    except ValueError as e:
        return EXIT_BAD_ARGS, str(e)

    # Size guard
    try:
        size = file_path.stat().st_size
    except PermissionError:
        return EXIT_PERM_ERROR, f"Permission denied: {file_path}"

    if size > MAX_FILE_SIZE:
        return EXIT_BAD_ARGS, f"File too large ({human_size(size)}); limit is {human_size(MAX_FILE_SIZE)}"

    # Read file
    try:
        data = file_path.read_bytes()
    except PermissionError:
        return EXIT_PERM_ERROR, f"Permission denied reading: {file_path}"
    except OSError as e:
        return EXIT_FS_ERROR, f"Error reading file: {e}"

    # Parse
    try:
        info = parse_pe(data)
    except Exception as e:
        return EXIT_UNEXPECTED, f"Unexpected parse error: {e}"

    if not info.get("valid"):
        msg = info.get("error", "Not a valid PE file")
        print(f"Error: {msg}", file=sys.stderr)
        return EXIT_FS_ERROR, msg

    # Augment with file path info
    info["file_name"] = file_path.name
    info["file_path"] = str(file_path)
    info["file_size"] = size
    info["file_size_human"] = human_size(size)

    # Human-readable output
    human_text = format_pe_human(file_path, info)
    if dry_run:
        print("[DRY-RUN] Would write report. Analysis results:")
        print(human_text)
        if use_json:
            print(json.dumps(info, indent=2, default=str))
        return EXIT_OK, "Dry-run complete"

    if use_json:
        print(json.dumps(info, indent=2, default=str))
    else:
        print(human_text)

    # Determine output directory
    effective_out_dir: Path | None = None
    if case_dir_str:
        case_dir = resolve_path(case_dir_str)
        if is_case_root(case_dir):
            effective_out_dir = case_dir / "static"
            effective_out_dir.mkdir(exist_ok=True)
        else:
            print(f"Warning: {case_dir} does not appear to be a case root; skipping audit log.", file=sys.stderr)
    elif out_dir_str:
        effective_out_dir = resolve_path(out_dir_str)

    if effective_out_dir:
        try:
            effective_out_dir.mkdir(parents=True, exist_ok=True)
            report_name = f"{file_path.stem}_peinfo.json"
            report_path = effective_out_dir / report_name
            report_path.write_text(json.dumps(info, indent=2, default=str), encoding="utf-8")
            print(f"Report    : {report_path}")

            if case_dir_str:
                case_dir = resolve_path(case_dir_str)
                if is_case_root(case_dir):
                    audit_log_append(case_dir, "peinfo", {
                        "file": file_path.name,
                        "architecture": info.get("coff", {}).get("machine_name", "?"),
                        "format": info.get("format", "?"),
                        "sections": len(info.get("sections", [])),
                        "import_dlls": len(info.get("imports", [])),
                        "report": str(report_path),
                    })
        except PermissionError as e:
            return EXIT_PERM_ERROR, f"Permission denied writing report: {e}"
        except OSError as e:
            return EXIT_FS_ERROR, f"Error writing report: {e}"

    return EXIT_OK, f"PE analysis complete: {file_path.name}"


def main(argv: list[str] | None = None) -> None:
    """Main entrypoint."""
    args = parse_args(argv)
    exit_code, message = run(
        args.file,
        args.out_dir,
        args.json,
        args.case_dir,
        args.dry_run,
    )
    if exit_code != EXIT_OK:
        print(f"Error: {message}", file=sys.stderr)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
