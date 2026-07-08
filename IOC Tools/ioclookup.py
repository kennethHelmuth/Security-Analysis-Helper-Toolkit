#!/usr/bin/env python3
"""
ioclookup.py

Look up Indicators of Compromise (IOCs) in offline feeds or import threat lists into SQLite.

Usage:
    # Lookup IOCs:
    python ioclookup.py IOC [IOC ...] [--db DB_PATH] [--out-dir OUT_DIR]
                         [--case-dir CASE_DIR] [--vt-key KEY] [--mb-key KEY]

    # Import feed into SQLite:
    python ioclookup.py --import-feed FEED_FILE --feed-type {urlhaus,emerging-threats-ip,generic-csv,misp-csv} [--db DB_PATH]

Core behaviour:
  - Offline lookup mode: Queries a local SQLite database (default: ~/malware_cases/intel/ioc_feeds.db).
  - Online enrichment: Query VirusTotal or MalwareBazaar using API keys.
  - Import mode: Creates/updates a database schema and parses common CTI threat intelligence feeds.

Exit codes:
    0   success
    2   invalid arguments / missing database
    3   feed file not found
    5   permission error
    6   database connection or read/write error
    10  unexpected error
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
import urllib.parse
import urllib.request
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
        from pathlib import Path; return Path(raw).expanduser().resolve()
    def require_file(path, label="File"):
        if not path.exists(): raise FileNotFoundError(f"{label} does not exist: {path}")
        if not path.is_file(): raise ValueError(f"{label} is not a regular file: {path}")
    EXIT_OK=0; EXIT_BAD_ARGS=2; EXIT_NOT_FOUND=3; EXIT_ALREADY_EXISTS=4
    EXIT_PERM_ERROR=5; EXIT_FS_ERROR=6; EXIT_VALIDATION=7; EXIT_UNEXPECTED=10

DEFAULT_DB_PATH = "~/malware_cases/intel/ioc_feeds.db"

def get_db_connection(db_path: Path) -> sqlite3.Connection:
    """Return a connection to the SQLite database and create the schema if needed."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Create schema
    conn.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        source TEXT,
        tags TEXT,
        description TEXT,
        added_at TEXT NOT NULL,
        UNIQUE(type, value)
    );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, value);")
    conn.commit()
    return conn

def import_feed(conn: sqlite3.Connection, feed_path: Path, feed_type: str) -> tuple[int, int]:
    """Parse and load threat intelligence feeds into the SQLite database."""
    imported = 0
    skipped = 0
    now = datetime.now(timezone.utc).isoformat()

    # Read feed file
    try:
        with feed_path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        raise OSError(f"Could not read feed file: {e}")

    rows_to_insert = []

    if feed_type == "urlhaus":
        # CSV structure. Skip comments starting with '#'
        # Fields: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            # Parse as CSV row
            reader = csv.reader([line.strip()])
            try:
                row = next(reader)
                if len(row) >= 7:
                    threat = row[5]
                    tags = row[6]
                    merged_tags = f"{threat},{tags}".strip(",")
                    rows_to_insert.append(("url", row[2], "URLhaus", merged_tags, row[3], now))
            except Exception:
                skipped += 1

    elif feed_type == "emerging-threats-ip":
        # IP list, one per line. Skip comments starting with '#'
        for line in lines:
            line_val = line.strip()
            if not line_val or line_val.startswith("#"):
                continue
            rows_to_insert.append(("ip", line_val, "Emerging Threats", "blocklist", "", now))

    elif feed_type == "generic-csv":
        # CSV with headers. Must contain 'type' and 'value'.
        reader = csv.DictReader(lines)
        for row in reader:
            ioc_type = row.get("type")
            ioc_value = row.get("value")
            if not ioc_type or not ioc_value:
                skipped += 1
                continue
            source = row.get("source", "Generic CSV")
            tags = row.get("tags", "")
            desc = row.get("description", "")
            rows_to_insert.append((ioc_type, ioc_value, source, tags, desc, now))

    elif feed_type == "misp-csv":
        # MISP export CSV. Skip lines starting with #.
        # columns: uuid(0), event_id(1), category(2), type(3), value(4), comment(5)
        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            reader = csv.reader([line.strip()])
            try:
                row = next(reader)
                if len(row) >= 6:
                    rows_to_insert.append((row[3], row[4], "MISP", row[2], row[5], now))
            except Exception:
                skipped += 1

    # Insert into SQLite
    cursor = conn.cursor()
    for item in rows_to_insert:
        try:
            cursor.execute("""
            INSERT OR IGNORE INTO iocs (type, value, source, tags, description, added_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """, item)
            if cursor.rowcount > 0:
                imported += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1

    conn.commit()
    return imported, skipped

def extract_domain_from_url(url: str) -> str | None:
    """Helper to extract domain/host from URL to search as domain fallback."""
    try:
        parsed = urllib.parse.urlparse(url)
        # Handle cases where URL doesn't have scheme
        if not parsed.netloc and "//" not in url:
            parsed = urllib.parse.urlparse("//" + url)
        host = parsed.hostname
        return host if host else None
    except Exception:
        return None

def lookup_ioc(conn: sqlite3.Connection, ioc_value: str) -> list[dict[str, Any]]:
    """Query the local SQLite database for direct or domain fallback matches."""
    matches = []
    cursor = conn.cursor()

    # Try exact match
    cursor.execute("""
    SELECT type, value, source, tags, description, added_at
    FROM iocs
    WHERE value = ? OR value LIKE ?
    """, (ioc_value, f"%{ioc_value}%"))
    for row in cursor.fetchall():
        matches.append(dict(row))

    # Fallback: if it's a URL, try domain matching
    domain = extract_domain_from_url(ioc_value)
    if domain and domain != ioc_value:
        cursor.execute("""
        SELECT type, value, source, tags, description, added_at
        FROM iocs
        WHERE value = ? OR value LIKE ?
        """, (domain, f"%{domain}%"))
        for row in cursor.fetchall():
            matches.append(dict(row))

    # Deduplicate matches
    unique_matches = []
    seen = set()
    for m in matches:
        key = (m["type"], m["value"], m["source"])
        if key not in seen:
            seen.add(key)
            unique_matches.append(m)

    return unique_matches

def lookup_vt(hash_value: str, api_key: str) -> dict[str, Any] | None:
    """Query VirusTotal v3 API for file hash information."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    req = urllib.request.Request(url)
    req.add_header("x-apikey", api_key)

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            labels = data.get("data", {}).get("attributes", {}).get("popular_threat_classification", {})
            return {
                "positives": stats.get("malicious", 0),
                "total": sum(stats.values()),
                "suggested_label": labels.get("suggested_threat_label", "None"),
            }
    except Exception:
        return None

def lookup_mb(hash_value: str, api_key: str) -> dict[str, Any] | None:
    """Query MalwareBazaar API for file hash information."""
    # MalwareBazaar expects API requests using POST with x-www-form-urlencoded data
    url = "https://mb-api.abuse.ch/api/v1/"
    payload = {"query": "get_info", "hash": hash_value}
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data)
    if api_key:
        req.add_header("API-KEY", api_key)

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res = json.loads(response.read().decode("utf-8"))
            if res.get("query_status") == "ok":
                info = res.get("data", [{}])[0]
                return {
                    "file_name": info.get("file_name"),
                    "file_type": info.get("file_type"),
                    "first_seen": info.get("first_seen"),
                    "tags": info.get("tags", []),
                }
    except Exception:
        return None
    return None

def run(args: argparse.Namespace) -> tuple[int, str]:
    """Execute either Import Mode or Lookup Mode based on arguments."""
    db_path = resolve_path(args.db)

    # 1. IMPORT MODE
    if args.import_feed:
        feed_path = resolve_path(args.import_feed)
        try:
            require_file(feed_path, "Feed file")
        except FileNotFoundError as e:
            return EXIT_NOT_FOUND, str(e)

        if not args.feed_type:
            return EXIT_BAD_ARGS, "Error: --feed-type must be specified when importing."

        try:
            conn = get_db_connection(db_path)
            imported, skipped = import_feed(conn, feed_path, args.feed_type)
            conn.close()
            return EXIT_OK, f"Feed import completed. Imported: {imported}, Skipped: {skipped}."
        except sqlite3.Error as e:
            return EXIT_FS_ERROR, f"SQLite error: {e}"
        except Exception as e:
            return EXIT_UNEXPECTED, f"Import failed: {e}"

    # 2. LOOKUP MODE
    if not args.iocs:
        return EXIT_BAD_ARGS, "Error: Please specify one or more IOC values to query."

    # Establish db connection
    try:
        conn = get_db_connection(db_path)
    except Exception as e:
        return EXIT_FS_ERROR, f"Could not open threat feed database: {e}"

    results = {}
    for ioc in args.iocs:
        ioc_clean = ioc.strip()
        if not ioc_clean:
            continue

        local_matches = lookup_ioc(conn, ioc_clean)
        vt_data = None
        mb_data = None

        # Check if IOC is a hash for VT or MB lookup
        is_hash = len(ioc_clean) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in ioc_clean)

        if is_hash:
            if args.vt_key:
                vt_data = lookup_vt(ioc_clean, args.vt_key)
            if args.mb_key and len(ioc_clean) == 64:  # MalwareBazaar expects SHA256
                mb_data = lookup_mb(ioc_clean, args.mb_key)

        results[ioc_clean] = {
            "local_matches": local_matches,
            "virustotal": vt_data,
            "malwarebazaar": mb_data,
        }

        # Print results
        print(f"\nIOC      : {ioc_clean}")
        if local_matches:
            for match in local_matches:
                print(f"  Match    : {match['type']} | {match['value']} | {match['source']} | {match['tags']} | {match['added_at'][:10]}")
            print(f"  Status   : {len(local_matches)} match(es) found in local database")
        else:
            print("  Status   : Not found in local database")

        if vt_data:
            print(f"  VT info  : {vt_data['positives']}/{vt_data['total']} detections | label: {vt_data['suggested_label']}")
        if mb_data:
            print(f"  MB info  : {mb_data['file_name']} ({mb_data['file_type']}) | first seen: {mb_data['first_seen']} | tags: {', '.join(mb_data['tags'])}")

    conn.close()

    # Write output to json file if out-dir or case-dir specified
    effective_out_dir = None
    if args.case_dir:
        case_root = resolve_path(args.case_dir)
        if is_case_root(case_root):
            effective_out_dir = case_root / "iocs"
            effective_out_dir.mkdir(exist_ok=True)
        else:
            print(f"Warning: {case_root} is not a valid case root directory.", file=sys.stderr)
    elif args.out_dir:
        effective_out_dir = resolve_path(args.out_dir)

    if effective_out_dir and not args.dry_run:
        effective_out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_path = effective_out_dir / f"ioclookup_{timestamp}.json"
        try:
            report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
            print(f"\nSaved results to: {report_path}")

            if args.case_dir:
                case_root = resolve_path(args.case_dir)
                if is_case_root(case_root):
                    audit_log_append(case_root, "ioclookup", {
                        "iocs_queried": len(results),
                        "report_file": str(report_path),
                    })
        except Exception as e:
            return EXIT_FS_ERROR, f"Failed to write results file: {e}"

    return EXIT_OK, "IOC Lookup complete."

def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    p = argparse.ArgumentParser(description="Query local threat databases or enrich hashes.")
    p.add_argument("iocs", nargs="*", help="IOC value(s) to query")
    p.add_argument("--db", default=DEFAULT_DB_PATH, help=f"SQLite database path (default: {DEFAULT_DB_PATH})")
    p.add_argument("--import-feed", default=None, help="Path to feed file to import")
    p.add_argument("--feed-type", choices=["urlhaus", "emerging-threats-ip", "generic-csv", "misp-csv"],
                   help="Feed file format type")
    p.add_argument("--out-dir", "-o", default=None, help="Directory to save JSON lookup results")
    p.add_argument("--case-dir", default=None, help="Case root directory for logging and output")
    p.add_argument("--vt-key", default=None, help="VirusTotal v3 API key")
    p.add_argument("--mb-key", default=None, help="MalwareBazaar API key")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--dry-run", action="store_true", help="Simulate lookup and print results without file writes")
    args = p.parse_args(argv)

    exit_code, msg = run(args)
    if exit_code != EXIT_OK:
        print(f"Error: {msg}", file=sys.stderr)
        sys.exit(exit_code)
    sys.exit(0)

if __name__ == "__main__":
    main()
