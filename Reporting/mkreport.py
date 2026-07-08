#!/usr/bin/env python3
"""
mkreport.py

Generate a standardized, structured Markdown case report from a case directory.

Usage:
    python mkreport.py CASE_DIR [--out-file OUT_FILE] [--dry-run]

Core behaviour:
  - Scans CASE_DIR (must be a valid case root directory).
  - Summarizes the case directory structure (subdirs, files, size).
  - Lists and hashes all files under samples/.
  - Summarizes static analysis artifacts (from static/ directory).
  - Summarizes indicator of compromise findings (from iocs/ directory).
  - Parses and renders the audit log (audit.log) as a Markdown table.
  - Includes content of files from notes/ as report sections.
  - Outputs Markdown format to case reports/ subdirectory or stdout.

Exit codes:
    0   success
    2   invalid arguments
    3   not a case root directory / directory not found
    5   permission error
    6   filesystem or write error
    10  unexpected error
"""

from __future__ import annotations

import argparse
import json
import re
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
        require_dir, human_size, audit_log_append,
        find_case_root, is_case_root, compute_hash,
        CASE_SUBDIRS, AUDIT_LOG_FILENAME,
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
        from pathlib import Path; return Path(raw).expanduser().resolve()
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
    CASE_SUBDIRS = frozenset({"samples", "static", "dynamic", "iocs", "notes", "output", "reports"})
    AUDIT_LOG_FILENAME = "audit.log"
    EXIT_OK=0; EXIT_BAD_ARGS=2; EXIT_NOT_FOUND=3; EXIT_ALREADY_EXISTS=4
    EXIT_PERM_ERROR=5; EXIT_FS_ERROR=6; EXIT_VALIDATION=7; EXIT_UNEXPECTED=10

def parse_case_name(case_dir: Path) -> str:
    """Extract case name from path name, stripping leading date prefix if present."""
    name = case_dir.name
    # Match YYYY-MM-DD_ or YYYYMMDD_ prefix
    m = re.match(r"^\d{4}-?\d{2}-?\d{2}_(.*)$", name)
    if m:
        return m.group(1).replace("_", " ").title()
    return name.replace("_", " ").title()

def get_dir_summary(path: Path) -> dict[str, dict[str, Any]]:
    """Get file counts and sizes for each canonical case subdirectory."""
    summary = {}
    for subdir in sorted(CASE_SUBDIRS):
        subdir_path = path / subdir
        if not subdir_path.is_dir():
            summary[subdir] = {"files": 0, "size": 0, "size_human": "0 B"}
            continue

        file_count = 0
        total_size = 0
        try:
            for item in subdir_path.rglob("*"):
                if item.is_file():
                    file_count += 1
                    total_size += item.stat().st_size
        except Exception:
            pass

        summary[subdir] = {
            "files": file_count,
            "size": total_size,
            "size_human": human_size(total_size)
        }
    return summary

def collect_samples(case_dir: Path) -> list[dict[str, Any]]:
    """List details of files inside the samples/ subdirectory."""
    samples = []
    samples_dir = case_dir / "samples"
    if samples_dir.is_dir():
        try:
            for item in sorted(samples_dir.iterdir()):
                if item.is_file():
                    size = item.stat().st_size
                    try:
                        sha256 = compute_hash(item, "sha256")
                    except Exception:
                        sha256 = "Unknown (Error hashing)"
                    samples.append({
                        "name": item.name,
                        "size": size,
                        "size_human": human_size(size),
                        "sha256": sha256
                    })
        except Exception:
            pass
    return samples

def collect_static_artifacts(case_dir: Path) -> list[dict[str, Any]]:
    """List static artifacts found in static/ and parse JSON output tools."""
    artifacts = []
    static_dir = case_dir / "static"
    if not static_dir.is_dir():
        return artifacts

    try:
        for item in sorted(static_dir.iterdir()):
            if not item.is_file():
                continue

            desc = "Unknown static analysis artifact"
            size = item.stat().st_size

            if item.name.endswith("_fileinfo.json"):
                try:
                    data = json.loads(item.read_text(encoding="utf-8", errors="replace"))
                    file_type = data.get("Type", data.get("type", "Unknown type"))
                    entropy = data.get("Entropy", data.get("entropy", ""))
                    entropy_str = f"entropy: {entropy}" if entropy else ""
                    desc = f"File type identification info ({file_type} {entropy_str})"
                except Exception:
                    desc = "File type identification info (Error parsing JSON)"

            elif item.name.endswith("_peinfo.json"):
                try:
                    data = json.loads(item.read_text(encoding="utf-8", errors="replace"))
                    arch = data.get("coff", {}).get("machine_name", "Unknown arch")
                    compile_time = data.get("coff", {}).get("timestamp_utc", "Unknown date")
                    imports_count = len(data.get("imports", []))
                    desc = f"PE header info ({arch}, compiled: {compile_time}, {imports_count} imported DLLs)"
                except Exception:
                    desc = "PE header analysis info (Error parsing JSON)"

            elif item.name.endswith(".strings.txt"):
                try:
                    with item.open("r", encoding="utf-8", errors="replace") as f:
                        lines = sum(1 for _ in f)
                    desc = f"Extracted strings ({lines} strings found)"
                except Exception:
                    desc = "Extracted strings text file"
            else:
                desc = f"Static file ({human_size(size)})"

            artifacts.append({
                "name": item.name,
                "description": desc,
                "size_human": human_size(size)
            })
    except Exception:
        pass

    return artifacts

def collect_ioc_findings(case_dir: Path) -> list[dict[str, Any]]:
    """List indicators of compromise from iocs/ subdirectory."""
    findings = []
    iocs_dir = case_dir / "iocs"
    if not iocs_dir.is_dir():
        return findings

    try:
        for item in sorted(iocs_dir.iterdir()):
            if not item.is_file():
                continue

            desc = "IOC list file"
            size = item.stat().st_size

            if item.name.endswith(".json"):
                try:
                    data = json.loads(item.read_text(encoding="utf-8", errors="replace"))
                    # If this is list of parsed ioc_harvester outputs
                    if isinstance(data, list):
                        type_counts = {}
                        top_iocs = []
                        for ioc in data:
                            ioc_type = ioc.get("type", "unknown")
                            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
                            if ioc.get("value") and ioc.get("confidence") is not None:
                                top_iocs.append((ioc["value"], ioc["type"], ioc["confidence"]))
                        
                        top_iocs.sort(key=lambda x: x[2], reverse=True)
                        type_str = ", ".join(f"{k}: {v}" for k, v in type_counts.items())
                        top_str = "; ".join(f"{val} ({t}:{c})" for val, t, c in top_iocs[:5])
                        desc = f"Extracted IOCs ({type_str}). Top matches: {top_str}"
                    else:
                        desc = "Structured JSON IOC report"
                except Exception:
                    desc = "JSON IOC file (Error parsing)"
            elif item.name.endswith(".csv"):
                try:
                    with item.open("r", encoding="utf-8", errors="replace") as f:
                        lines = sum(1 for _ in f) - 1 # exclude header
                    desc = f"CSV IOC table ({max(0, lines)} rows)"
                except Exception:
                    desc = "CSV IOC list file"
            else:
                desc = f"IOC file ({human_size(size)})"

            findings.append({
                "name": item.name,
                "description": desc,
                "size_human": human_size(size)
            })
    except Exception:
        pass

    return findings

def parse_audit_log(case_dir: Path) -> list[dict[str, str]]:
    """Parse audit.log file lines into timestamp, event, details dictionary list."""
    events = []
    log_path = case_dir / AUDIT_LOG_FILENAME
    if not log_path.is_file():
        return events

    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines:
            line_strip = line.strip()
            if not line_strip:
                continue

            # Log line format: [TIMESTAMP]  event_type  key=value  key=value
            m = re.match(r"^\[([^\]]+)\]\s+(\S+)(?:\s+(.*))?$", line_strip)
            if m:
                ts = m.group(1)
                event_type = m.group(2)
                details_raw = m.group(3) or ""
                
                # Format key=value pairs into a clean details string
                details_list = []
                for kv in re.findall(r"(\S+)=(\S+)", details_raw):
                    details_list.append(f"**{kv[0]}**: {kv[1]}")
                details = ", ".join(details_list) if details_list else details_raw
                
                events.append({
                    "timestamp": ts,
                    "event": event_type,
                    "details": details
                })
    except Exception:
        pass
    return events

def collect_notes(case_dir: Path) -> list[dict[str, str]]:
    """Collect note files contents from notes/ subdirectory."""
    notes = []
    notes_dir = case_dir / "notes"
    if not notes_dir.is_dir():
        return notes

    try:
        for item in sorted(notes_dir.iterdir()):
            if item.is_file() and item.suffix.lower() in (".txt", ".md", ".log", ""):
                try:
                    content = item.read_text(encoding="utf-8", errors="replace")
                    notes.append({
                        "name": item.name,
                        "content": content
                    })
                except Exception:
                    pass
    except Exception:
        pass
    return notes

def render_markdown(case_dir: Path, data: dict[str, Any]) -> str:
    """Construct report string from case data structure."""
    case_title = parse_case_name(case_dir)
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    md = []
    md.append(f"# Case Report: {case_title}\n")
    md.append(f"**Generated:** {generated_time}  ")
    md.append(f"**Case Directory:** `{case_dir}`\n")

    # 1. Directory Structure Summary
    md.append("## Case Structure\n")
    md.append("| Directory | Files | Size |")
    md.append("|-----------|-------|------|")
    for subdir, info in sorted(data["structure"].items()):
        md.append(f"| `{subdir}/` | {info['files']} | {info['size_human']} |")
    md.append("")

    # 2. Samples list
    md.append("## Samples\n")
    samples = data["samples"]
    if samples:
        md.append("| Filename | Size | SHA-256 |")
        md.append("|----------|------|---------|")
        for s in samples:
            md.append(f"| {s['name']} | {s['size_human']} | `{s['sha256']}` |")
    else:
        md.append("No samples registered in this case.")
    md.append("")

    # 3. Static Analysis Artifacts
    md.append("## Static Analysis Artifacts\n")
    static_files = data["static"]
    if static_files:
        md.append("| File | Size | Summary / Description |")
        md.append("|------|------|-----------------------|")
        for st in static_files:
            md.append(f"| {st['name']} | {st['size_human']} | {st['description']} |")
    else:
        md.append("No static analysis findings found.")
    md.append("")

    # 4. IOC Findings
    md.append("## IOC Findings\n")
    ioc_files = data["iocs"]
    if ioc_files:
        md.append("| File | Size | Summary / Description |")
        md.append("|------|------|-----------------------|")
        for ioc in ioc_files:
            md.append(f"| {ioc['name']} | {ioc['size_human']} | {ioc['description']} |")
    else:
        md.append("No indicators of compromise records found.")
    md.append("")

    # 5. Audit log table
    md.append("## Audit Trail\n")
    audit_events = data["audit"]
    if audit_events:
        md.append("| Timestamp | Event | Details |")
        md.append("|-----------|-------|---------|")
        for ev in audit_events:
            md.append(f"| {ev['timestamp']} | **{ev['event']}** | {ev['details']} |")
    else:
        md.append("Audit trail is empty.")
    md.append("")

    # 6. Notes
    md.append("## Analyst Notes\n")
    notes = data["notes"]
    if notes:
        for n in notes:
            md.append(f"### Note: {n['name']}\n")
            md.append("```text")
            md.append(n["content"].strip())
            md.append("```\n")
    else:
        md.append("No notes recorded.")
    md.append("")

    md.append("\n---")
    md.append("*Report generated by mkreport.py — Security Analysis Helper Toolkit*")

    return "\n".join(md)

def run(case_dir_str: str, out_file_str: str | None, dry_run: bool) -> tuple[int, str]:
    """Compile case components and generate Markdown output report."""
    case_dir = resolve_path(case_dir_str)

    try:
        require_dir(case_dir, "Case root")
    except (FileNotFoundError, NotADirectoryError) as e:
        return EXIT_NOT_FOUND, str(e)

    if not is_case_root(case_dir):
        return EXIT_VALIDATION, f"Directory is not a valid case root: {case_dir}"

    # Collect data
    data = {
        "structure": get_dir_summary(case_dir),
        "samples": collect_samples(case_dir),
        "static": collect_static_artifacts(case_dir),
        "iocs": collect_ioc_findings(case_dir),
        "audit": parse_audit_log(case_dir),
        "notes": collect_notes(case_dir)
    }

    report_content = render_markdown(case_dir, data)

    if dry_run:
        print("[DRY-RUN] Case report generated:")
        print(report_content)
        return EXIT_OK, "Dry-run complete."

    # Determine out file path
    if out_file_str:
        out_file = resolve_path(out_file_str)
    else:
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        out_file = case_dir / "reports" / f"case_report_{today}.md"

    try:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(report_content, encoding="utf-8")
        
        # Log to audit trail
        audit_log_append(case_dir, "mkreport", {
            "output_report": str(out_file),
            "samples_analyzed": len(data["samples"])
        })
        
        return EXIT_OK, f"Case report successfully written to: {out_file}"
    except Exception as e:
        return EXIT_FS_ERROR, f"Could not write report file: {e}"

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    p = argparse.ArgumentParser(description="Create structured case Markdown reports.")
    p.add_argument("case_dir", help="Path to the case root directory")
    p.add_argument("--out-file", "-o", default=None, help="Output markdown file path")
    p.add_argument("--dry-run", action="store_true", help="Print report to stdout without saving")
    return p.parse_args(argv)

def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    args = parse_args(argv)
    exit_code, msg = run(args.case_dir, args.out_file, args.dry_run)
    if exit_code != EXIT_OK:
        print(f"Error: {msg}", file=sys.stderr)
        sys.exit(exit_code)
    else:
        print(msg)
    sys.exit(0)

if __name__ == "__main__":
    main()
