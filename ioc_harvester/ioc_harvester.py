#!/usr/bin/env python3
"""
ioc_harvester.py

Scan files and directories, extract Indicators of Compromise (IOCs),
validate/normalize/deduplicate them, and export structured outputs.

Designed for Linux-first, offline CTI / malware-lab workflows.

Python 3.11+. Uses standard library only by default. Optional third-party
libraries (tldextract, publicsuffix2, idna, PyYAML) are used when available
to improve validation/normalization but are not required.

Author: kenneth Helmuth 
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import html
import io
import ipaddress
import json
import logging
import mimetypes
import os
import re
import sys
import time
import traceback
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple

# Optional third-party libs (used if available)
try:
    import tldextract  # type: ignore
except Exception:
    tldextract = None  # type: ignore

try:
    import idna  # type: ignore
except Exception:
    idna = None  # type: ignore

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

# ---------- Configuration & defaults ----------
DEFAULT_MAX_SIZE = 50_000_000  # 50 MB
DEFAULT_WORKERS = 4
DEFAULT_MIN_CONFIDENCE = 0
DEFAULT_INCLUDE = None
DEFAULT_EXCLUDE = None

ISO_NOW = lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()

# Weights for scoring (can be overridden via config)
DEFAULT_WEIGHTS = {
    "validated": 20,
    "context_indicator_field": 10,
    "noise_penalty": -30,
}

# JSON fields that increase confidence when IOC appears in them
HIGH_CONF_FIELDS = {"ioc", "indicator", "url", "domain", "email", "hash", "md5", "sha1", "sha256", "sha512"}

# File extensions to treat as textual
TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".json",
    ".csv",
    ".xml",
    ".html",
    ".htm",
    ".md",
    ".strings",
    ".yml",
    ".yaml",
}

# Suspicious filename extensions for contextual IOCs
SUSPICIOUS_FILE_EXTS = {".exe", ".dll", ".jar", ".apk", ".scr", ".bat", ".ps1"}

# Regex patterns used (docstrings above function show intent).
# Use conservative patterns to avoid excessive false positives.

# IPv4 / IPv6 (we'll validate with ipaddress)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")

# Hashes (hex)
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA512 = re.compile(r"\b[a-fA-F0-9]{128}\b")

# Email (conservative)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\b")

# URL (extract then validate with urllib.parse)
# Basic URL regex: scheme://host[:port]/path (conservative)
RE_URL = re.compile(
    r"\b(?:(?:https?|ftp)://)[^\s'\"<>]{3,4096}\b", flags=re.IGNORECASE
)

# Domain (conservative: labels separated by dots, TLD 2-63 chars)
RE_DOMAIN = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})\b"
)

# Bitcoin / Ethereum conservative heuristics (documented as optional)
RE_BITCOIN = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
RE_ETHEREUM = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# File names with suspicious extension
RE_FILENAME = re.compile(r"\b[\w\-/\\\.]{1,260}(\.(?:exe|dll|jar|apk|scr|bat|ps1))\b", flags=re.IGNORECASE)

# Very long random strings are likely noise (base64 / binary); simple heuristic:
RE_BASE64_LIKE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

# ssdeep-like pattern detection: strings with colons and comma-separated blocks like "3:abcd:efgh"
RE_SSPAT = re.compile(r"\b\d{1,3}:[A-Za-z0-9+/]{4,}:[A-Za-z0-9+/]{4,}\b")

# ---------- Data structures ----------
@dataclass
class SourceReference:
    path: str
    line: Optional[int] = None
    context: Optional[str] = None


@dataclass
class IOC:
    type: str
    raw: str
    value: str
    confidence: int = 0
    first_seen: str = field(default_factory=ISO_NOW)
    sources: List[SourceReference] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> str:
        return f"{self.type}:{self.value}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "sources": [asdict(s) for s in self.sources],
            "metadata": self.metadata,
        }


# ---------- Logging ----------
logger = logging.getLogger("ioc_harvester")


def setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    if quiet:
        level = logging.WARNING
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.setLevel(level)
    logger.handlers.clear()
    logger.addHandler(handler)


# ---------- Helpers: validation & normalization ----------
def normalize_domain(domain: str) -> Optional[str]:
    """
    Normalize domain:
    - strip surrounding dots
    - lowercase
    - optionally convert IDN via idna to punycode (if available)
    - ensure has at least two labels
    """
    dom = domain.strip().strip(".").lower()
    if not dom or dom.isdigit():
        return None
    if dom.count(".") < 1:
        # single-label names are rejected conservatively
        return None
    try:
        # convert to ascii/punycode if idna available
        if idna is not None:
            try:
                dom = idna.encode(dom).decode("ascii")
            except Exception:
                # fallback to original lowercased
                pass
        # Optional tldextract/publicsuffix validation
        if tldextract is not None:
            try:
                te = tldextract.extract(dom)
                if not te.suffix:
                    return None
            except Exception:
                pass
        # Basic TLD length check
        parts = dom.rsplit(".", 1)
        if len(parts) == 2 and 2 <= len(parts[1]) <= 63:
            return dom
    except Exception:
        return None
    return dom


def validate_ip(candidate: str) -> Optional[str]:
    try:
        if ":" in candidate:
            ip = ipaddress.IPv6Address(candidate)
        else:
            ip = ipaddress.IPv4Address(candidate)
        return str(ip)
    except Exception:
        return None


def normalize_url(raw_url: str) -> Optional[str]:
    try:
        url = raw_url.strip()
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None
        # Normalize: lowercase scheme and host
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname or ""
        # normalize hostname as domain or ip
        norm_host = hostname
        if normalize_domain(hostname) is not None:
            norm_host = normalize_domain(hostname)
        else:
            # maybe IP
            ip_norm = validate_ip(hostname)
            if ip_norm:
                norm_host = ip_norm
        # rebuild URL with safe quoting
        netloc = norm_host
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        path = urllib.parse.quote(urllib.parse.unquote(parsed.path), safe="/%:@[]()+,;=")
        query = urllib.parse.quote_plus(urllib.parse.unquote_plus(parsed.query), safe="=&")
        fragment = ""
        rebuilt = urllib.parse.urlunparse((scheme, netloc, path or "/", query, "", fragment))
        return rebuilt
    except Exception:
        return None


def normalize_email(raw: str) -> Optional[str]:
    e = raw.strip()
    if "@" not in e:
        return None
    local, _, domain = e.rpartition("@")
    norm_dom = normalize_domain(domain)
    if not norm_dom:
        return None
    return f"{local}@{norm_dom}"


def normalize_hash(raw: str) -> Optional[Tuple[str, str]]:
    v = raw.lower()
    l = len(v)
    if re.fullmatch(r"[a-f0-9]+", v) is None:
        return None
    if l == 32:
        return ("md5", v)
    if l == 40:
        return ("sha1", v)
    if l == 64:
        return ("sha256", v)
    if l == 128:
        return ("sha512", v)
    return None


def is_binary_file(path: Path, max_check: int = 2048) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(max_check)
            if not chunk:
                return False
            # Heuristic: NUL byte implies binary
            if b"\x00" in chunk:
                return True
            # High non-text byte ratio
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
            nontext = sum(1 for b in chunk if b not in text_chars)
            return (nontext / max(1, len(chunk))) > 0.30
    except Exception:
        return True


# ---------- Extraction functions ----------
def extract_iocs_from_text(text: str) -> Iterable[Tuple[str, str, str]]:
    """
    Extract candidate IOCs from free text.
    Yields tuples: (ioc_type_hint, raw_value, context_snippet)
    ioc_type_hint is a soft hint like "ip", "domain", "url", "email", "hash", "filename", "bitcoin", "ethereum", "ssdeep"
    """
    seen: Set[Tuple[str, str]] = set()

    # URLs first (they often contain domains and filenames)
    for m in RE_URL.finditer(text):
        raw = m.group(0)
        ctx = text[max(0, m.start() - 40): m.end() + 40].replace("\n", " ")
        key = ("url", raw)
        if key not in seen:
            seen.add(key)
            yield ("url", raw, ctx)

    # Domains
    for m in RE_DOMAIN.finditer(text):
        raw = m.group(1)
        ctx = text[max(0, m.start() - 40): m.end() + 40].replace("\n", " ")
        key = ("domain", raw)
        if key not in seen:
            seen.add(key)
            yield ("domain", raw, ctx)

    # IPs
    for m in RE_IPV4.finditer(text):
        raw = m.group(0)
        ctx = text[max(0, m.start() - 30): m.end() + 30]
        key = ("ip", raw)
        if key not in seen:
            seen.add(key)
            yield ("ip", raw, ctx)
    for m in RE_IPV6.finditer(text):
        raw = m.group(0)
        key = ("ip", raw)
        if key not in seen:
            seen.add(key)
            yield ("ip", raw, raw)

    # Emails
    for m in RE_EMAIL.finditer(text):
        raw = m.group(0)
        key = ("email", raw)
        if key not in seen:
            seen.add(key)
            yield ("email", raw, raw)

    # Hashes (large first to avoid shorter matches inside longer ones)
    for m in RE_SHA512.finditer(text):
        raw = m.group(0)
        if ("hash", raw) not in seen:
            seen.add(("hash", raw))
            yield ("hash", raw, raw)
    for m in RE_SHA256.finditer(text):
        raw = m.group(0)
        if ("hash", raw) not in seen:
            seen.add(("hash", raw))
            yield ("hash", raw, raw)
    for m in RE_SHA1.finditer(text):
        raw = m.group(0)
        if ("hash", raw) not in seen:
            seen.add(("hash", raw))
            yield ("hash", raw, raw)
    for m in RE_MD5.finditer(text):
        raw = m.group(0)
        if ("hash", raw) not in seen:
            seen.add(("hash", raw))
            yield ("hash", raw, raw)

    # Filenames
    for m in RE_FILENAME.finditer(text):
        raw = m.group(0)
        if ("filename", raw) not in seen:
            seen.add(("filename", raw))
            yield ("filename", raw, raw)

    # crypto wallets (optional)
    for m in RE_BITCOIN.finditer(text):
        raw = m.group(0)
        if ("bitcoin", raw) not in seen:
            seen.add(("bitcoin", raw))
            yield ("bitcoin", raw, raw)
    for m in RE_ETHEREUM.finditer(text):
        raw = m.group(0)
        if ("ethereum", raw) not in seen:
            seen.add(("ethereum", raw))
            yield ("ethereum", raw, raw)

    # ssdeep-like
    for m in RE_SSPAT.finditer(text):
        raw = m.group(0)
        if ("ssdeep", raw) not in seen:
            seen.add(("ssdeep", raw))
            yield ("ssdeep", raw, raw)

    # Base64-like long strings -> noise candidate (we tag but low confidence)
    for m in RE_BASE64_LIKE.finditer(text):
        raw = m.group(0)
        if ("noise_base64", raw) not in seen:
            seen.add(("noise_base64", raw))
            yield ("noise", raw, raw)


def extract_iocs_from_json(obj: Any, path: str = "$") -> Iterable[Tuple[str, str, str, Optional[str]]]:
    """
    Walk JSON-like structure recursively and extract IOCs from string values.

    Yields tuples: (ioc_type_hint, raw_value, context_snippet, json_path_key)
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            curpath = f"{path}.{k}"
            if isinstance(v, (dict, list)):
                yield from extract_iocs_from_json(v, curpath)
            elif isinstance(v, str):
                # Extract from value, but give context that it came from a JSON key
                for typ, raw, ctx in extract_iocs_from_text(v):
                    yield (typ, raw, ctx, curpath)
            else:
                # numbers/booleans etc: skip
                continue
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            curpath = f"{path}[{idx}]"
            if isinstance(item, (dict, list)):
                yield from extract_iocs_from_json(item, curpath)
            elif isinstance(item, str):
                for typ, raw, ctx in extract_iocs_from_text(item):
                    yield (typ, raw, ctx, curpath)
    elif isinstance(obj, str):
        for typ, raw, ctx in extract_iocs_from_text(obj):
            yield (typ, raw, ctx, path)


# ---------- File discovery & reading ----------
def discover_files(
    path: Path,
    recursive: bool = False,
    include: Optional[str] = None,
    exclude: Optional[str] = None,
    max_size: int = DEFAULT_MAX_SIZE,
) -> Generator[Path, None, None]:
    """
    Yield Path objects for files to scan under path.
    include/exclude are glob patterns (fnmatch). If include is None, include all.
    """
    path = Path(path)
    if path.is_file():
        if path.stat().st_size <= max_size:
            yield path
        return
    # directory
    for root, dirs, files in os.walk(path):
        for f in files:
            p = Path(root) / f
            try:
                if p.stat().st_size > max_size:
                    logger.debug("Skipping large file: %s", p)
                    continue
            except Exception:
                continue
            if include and not fnmatch.fnmatch(str(p.name), include):
                continue
            if exclude and fnmatch.fnmatch(str(p.name), exclude):
                continue
            yield p
        if not recursive:
            break


def read_file_stream(path: Path) -> Generator[Tuple[int, str], None, None]:
    """
    Yield (line_no, text) tuples for a file. Skip binary files.
    Reads in streaming mode, decodes with errors='replace'.
    """
    if is_binary_file(path):
        raise ValueError("Binary file skipped")
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, start=1):
                yield (i, line.rstrip("\n"))
    except Exception:
        # Some textual files may be large or have odd encodings; fallback to reading in chunks
        with path.open("rb") as fh:
            idx = 0
            for chunk in iter(lambda: fh.read(8192), b""):
                idx += 1
                try:
                    text = chunk.decode("utf-8", errors="replace")
                except Exception:
                    text = chunk.decode("latin-1", errors="replace")
                for j, ln in enumerate(text.splitlines(), start=1):
                    yield (idx * 1000 + j, ln)


# ---------- Core processing ----------
def normalize_and_validate(ioc_hint: str, raw: str, json_path: Optional[str] = None) -> Optional[IOC]:
    """
    Try to normalize and validate a raw candidate. Returns IOC instance or None.
    """
    raw = raw.strip()
    # URL
    if ioc_hint == "url":
        norm = normalize_url(raw)
        if norm:
            i = IOC(type="url", raw=raw, value=norm)
            i.metadata["source_hint"] = "url_regex"
            return i
        return None
    # domain
    if ioc_hint == "domain":
        norm = normalize_domain(raw)
        if norm:
            return IOC(type="domain", raw=raw, value=norm)
        return None
    # ip
    if ioc_hint == "ip":
        val = validate_ip(raw)
        if val:
            return IOC(type="ip", raw=raw, value=val)
        return None
    # email
    if ioc_hint == "email":
        val = normalize_email(raw)
        if val:
            return IOC(type="email", raw=raw, value=val)
        return None
    # hash
    if ioc_hint == "hash":
        res = normalize_hash(raw)
        if res:
            typ, val = res
            return IOC(type=typ, raw=raw, value=val)
        return None
    # filename context
    if ioc_hint == "filename":
        # normalize path
        v = raw.strip()
        return IOC(type="filename", raw=raw, value=v)
    if ioc_hint in ("bitcoin", "ethereum", "ssdeep"):
        return IOC(type=ioc_hint, raw=raw, value=raw)
    if ioc_hint == "noise":
        # produce low-confidence "noise" IOC for tracking but probably filtered out
        return IOC(type="noise", raw=raw, value=raw)
    if ioc_hint == "noise_base64":
        return IOC(type="noise_base64", raw=raw, value=raw)
    # fallback: attempt domain/url/email/hash detection from raw
    # Try hash
    res = normalize_hash(raw)
    if res:
        typ, val = res
        return IOC(type=typ, raw=raw, value=val)
    # Try url
    urlnorm = normalize_url(raw)
    if urlnorm:
        return IOC(type="url", raw=raw, value=urlnorm)
    # Try email
    em = normalize_email(raw)
    if em:
        return IOC(type="email", raw=raw, value=em)
    # Try domain
    dom = normalize_domain(raw)
    if dom:
        return IOC(type="domain", raw=raw, value=dom)
    # nothing validated
    return None


def score_ioc(ioc: IOC, context_field_name: Optional[str] = None, weights: Dict[str, int] = DEFAULT_WEIGHTS) -> IOC:
    """
    Compute a simple confidence score for an IOC based on heuristics and weights.
    """
    score = 0
    # validated format -> validated weight
    score += weights.get("validated", DEFAULT_WEIGHTS["validated"])
    # context field boost
    if context_field_name and any(k in context_field_name.lower() for k in HIGH_CONF_FIELDS):
        score += weights.get("context_indicator_field", DEFAULT_WEIGHTS["context_indicator_field"])
        ioc.metadata["found_in_json_path"] = context_field_name
    # noise detection
    if ioc.type.startswith("noise") or RE_BASE64_LIKE.search(ioc.raw):
        score += weights.get("noise_penalty", DEFAULT_WEIGHTS["noise_penalty"])
    ioc.confidence = max(0, min(100, score))
    return ioc


def add_provenance(ioc: IOC, src_path: Path, line_no: Optional[int], context: Optional[str]) -> None:
    ioc.sources.append(SourceReference(path=str(src_path), line=line_no, context=context))


def deduplicate_and_score(iocs: Iterable[IOC], weights: Dict[str, int], min_confidence: int) -> List[IOC]:
    """
    Deduplicate IOCs (type+value canonical) and aggregate sources.
    Apply scoring and filter by min_confidence.
    """
    aggregated: Dict[str, IOC] = {}
    for i in iocs:
        key = i.canonical()
        if key not in aggregated:
            # copy i
            aggregated[key] = IOC(type=i.type, raw=i.raw, value=i.value, confidence=0, first_seen=i.first_seen, sources=list(i.sources), metadata=dict(i.metadata))
        else:
            # merge sources and keep earliest first_seen
            existing = aggregated[key]
            existing.sources.extend(i.sources)
            if i.first_seen < existing.first_seen:
                existing.first_seen = i.first_seen
    # score each
    out: List[IOC] = []
    for i in aggregated.values():
        # find if any provenance contained JSON path with indicator keys
        json_paths = [s.context for s in i.sources if s.context and (s.context.startswith("$") or "." in (s.context or ""))]
        context_field = json_paths[0] if json_paths else None
        scored = score_ioc(i, context_field_name=context_field, weights=weights)
        # deduplicate sources
        unique_srcs = {}
        for s in scored.sources:
            key_s = (s.path, s.line, s.context)
            unique_srcs[key_s] = s
        scored.sources = list(unique_srcs.values())
        if scored.confidence >= min_confidence:
            out.append(scored)
    # sort by confidence desc then type
    out.sort(key=lambda x: (-x.confidence, x.type, x.value))
    return out


# ---------- Exports ----------
def export_json(iocs: List[IOC], out_path: Path, dry_run: bool = False) -> None:
    data = [ioc.to_dict() for ioc in iocs]
    if dry_run:
        logger.info("Dry-run: would write JSON to %s", out_path)
        print(json.dumps(data, indent=2)[:2000])
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def export_csv(iocs: List[IOC], out_path: Path, dry_run: bool = False) -> None:
    if dry_run:
        logger.info("Dry-run: would write CSV to %s", out_path)
        for i in iocs[:10]:
            print(i.type, i.value, i.confidence)
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["type", "value", "confidence", "first_seen", "sources_count"])
        for i in iocs:
            writer.writerow([i.type, i.value, i.confidence, i.first_seen, len(i.sources)])


def export_stix_like(iocs: List[IOC], out_path: Path, dry_run: bool = False) -> None:
    """
    Create a minimal STIX-like JSON structure suitable for ingestion by lightweight systems.
    Not a full STIX representation.
    """
    stix = {
        "type": "bundle",
        "spec_version": "2.0",
        "objects": [],
    }
    for i in iocs:
        stix_obj = {
            "type": "indicator",
            "id": f"indicator--{hash(i.canonical()) & 0xffffffff:x}",
            "created": i.first_seen,
            "modified": i.first_seen,
            "labels": [i.type],
            "pattern": f"[{i.type.upper()} = '{i.value}']",
            "confidence": i.confidence,
        }
        stix["objects"].append(stix_obj)
    if dry_run:
        logger.info("Dry-run: would write STIX-like JSON to %s", out_path)
        print(json.dumps(stix, indent=2)[:2000])
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(stix, fh, indent=2)


# ---------- Plugin hooks ----------
def load_custom_extractors(plugin_dir: Optional[Path]) -> List[Any]:
    """
    Load optional custom extractors from a directory. Each module must expose
    an `extract(text: str) -> Iterable[(type, raw, context)]` function.
    Plugins are loaded without executing untrusted code in the repo by name only.
    Use with caution (plugins are trusted).
    """
    extractors = []
    if not plugin_dir:
        return extractors
    plugin_dir = Path(plugin_dir)
    if not plugin_dir.exists() or not plugin_dir.is_dir():
        return extractors
    sys.path.insert(0, str(plugin_dir.resolve()))
    for p in plugin_dir.rglob("*.py"):
        try:
            name = p.stem
            mod = __import__(name)
            if hasattr(mod, "extract"):
                extractors.append(mod.extract)
        except Exception:
            logger.debug("Failed to load plugin %s: %s", p, traceback.format_exc())
    return extractors


# ---------- Runner for single file ----------
def process_file(
    path: Path,
    include_plugins: Optional[List[Any]],
) -> List[IOC]:
    """
    Process a single file, return list of IOC objects (unscored, raw).
    """
    results: List[IOC] = []
    try:
        if is_binary_file(path):
            logger.debug("Skipping binary file %s", path)
            return results
        suffix = path.suffix.lower()
        # JSON file special handling
        if suffix == ".json":
            try:
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    obj = json.load(fh)
                for typ, raw, ctx, jsonpath in extract_iocs_from_json(obj):
                    ioc = normalize_and_validate(typ, raw, jsonpath)
                    if ioc is not None:
                        add_provenance(ioc, path, None, jsonpath)
                        results.append(ioc)
                return results
            except Exception as e:
                logger.debug("JSON parse failed %s: %s", path, e)
                # fallback to text extraction
        # CSV: read textual content of fields
        if suffix == ".csv":
            try:
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    rdr = csv.reader(fh)
                    for i, row in enumerate(rdr, start=1):
                        for cell in row:
                            for typ, raw, ctx in extract_iocs_from_text(cell):
                                ioc = normalize_and_validate(typ, raw)
                                if ioc:
                                    add_provenance(ioc, path, i, cell)
                                    results.append(ioc)
                return results
            except Exception:
                logger.debug("CSV parse failed, falling back to text for %s", path)
        # HTML / XML: strip tags heuristically
        if suffix in {".html", ".htm", ".xml"}:
            text_chunks = []
            try:
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    data = fh.read(1000000)
                    # naive tag removal
                    text_only = re.sub(r"<[^>]+>", " ", data)
                    text_only = html.unescape(text_only)
                    text_chunks = [text_only]
            except Exception:
                pass
            for chunk in text_chunks:
                for typ, raw, ctx in extract_iocs_from_text(chunk):
                    ioc = normalize_and_validate(typ, raw)
                    if ioc:
                        add_provenance(ioc, path, None, None)
                        results.append(ioc)
            return results
        # Plain text fallback: stream lines
        for line_no, line in read_file_stream(path):
            for typ, raw, ctx in extract_iocs_from_text(line):
                ioc = normalize_and_validate(typ, raw)
                if ioc:
                    add_provenance(ioc, path, line_no, line.strip())
                    results.append(ioc)
        # Plugin extractors
        if include_plugins:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                content = fh.read(2000000)
            for plugin in include_plugins:
                try:
                    for typ, raw, ctx in plugin(content):
                        ioc = normalize_and_validate(typ, raw)
                        if ioc:
                            add_provenance(ioc, path, None, ctx)
                            results.append(ioc)
                except Exception:
                    logger.debug("Plugin extractor error: %s", traceback.format_exc())
    except ValueError as ve:
        # binary skip
        logger.debug("Skipping binary: %s", path)
    except Exception:
        logger.error("Failed to process %s: %s", path, traceback.format_exc())
    return results


# ---------- CLI wiring ----------
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="IOC Harvester: extract, normalize and export IOCs from files.")
    parser.add_argument("path", type=str, help="File or directory to scan")
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan directories recursively")
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE, help="Skip files larger than N bytes")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Number of worker threads")
    parser.add_argument("--out-json", type=str, default=None, help="Write normalized IOCs to JSON")
    parser.add_argument("--out-csv", type=str, default=None, help="Write normalized IOCs to CSV")
    parser.add_argument("--out-stix", type=str, default=None, help="Write STIX-like JSON")
    parser.add_argument("--min-confidence", type=int, default=DEFAULT_MIN_CONFIDENCE, help="Filter IOCs below confidence 0-100")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--quiet", action="store_true", help="Minimal logging")
    parser.add_argument("--dry-run", action="store_true", help="Parse and show summary; do not write outputs")
    parser.add_argument("--config", type=str, default=None, help="Optional JSON/YAML config for custom regexes/weights/excludes")
    parser.add_argument("--include", type=str, default=None, help="Glob pattern to include filenames")
    parser.add_argument("--exclude", type=str, default=None, help="Glob pattern to exclude filenames")
    parser.add_argument("--plugin-dir", type=str, default=None, help="Directory with custom extractor plugins")
    parser.add_argument("--version", action="version", version="ioc_harvester 1.0")
    args = parser.parse_args(argv)

    setup_logging(args.verbose, args.quiet)
    logger.info("Starting ioc_harvester on %s", args.path)

    # load config if provided
    config_weights = dict(DEFAULT_WEIGHTS)
    if args.config:
        cfgp = Path(args.config)
        if cfgp.exists():
            try:
                if cfgp.suffix in (".yaml", ".yml") and yaml is not None:
                    cfg = yaml.safe_load(cfgp.read_text(encoding="utf-8"))
                else:
                    cfg = json.loads(cfgp.read_text(encoding="utf-8"))
                if isinstance(cfg, dict) and cfg.get("weights"):
                    config_weights.update(cfg.get("weights", {}))
                    logger.debug("Loaded weights from config: %s", config_weights)
            except Exception as e:
                logger.warning("Failed to load config: %s", e)

    # prepare files list
    target = Path(args.path)
    if not target.exists():
        logger.error("Path does not exist: %s", target)
        return 2

    files = list(discover_files(target, recursive=args.recursive, include=args.include, exclude=args.exclude, max_size=args.max_size))
    logger.info("Discovered %d files to scan", len(files))
    if not files:
        logger.info("No files to scan.")
        return 0

    plugin_extractors = load_custom_extractors(Path(args.plugin_dir)) if args.plugin_dir else []

    # process files with ThreadPoolExecutor
    all_iocs: List[IOC] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(process_file, p, plugin_extractors): p for p in files}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                res = fut.result()
                logger.debug("Processed %s => found %d iocs", p, len(res))
                all_iocs.extend(res)
            except Exception:
                logger.error("Error processing %s: %s", p, traceback.format_exc())

    logger.info("Raw IOCs extracted: %d", len(all_iocs))
    # dedupe and score
    final_iocs = deduplicate_and_score(all_iocs, weights=config_weights, min_confidence=args.min_confidence)
    logger.info("Final IOCs after dedup & scoring: %d", len(final_iocs))

    # output summary
    types_count = defaultdict(int)
    for i in final_iocs:
        types_count[i.type] += 1
    print("IOC summary:")
    for t, c in types_count.items():
        print(f"  {t}: {c}")
    print(f"Total IOCs: {len(final_iocs)}")

    # Exports
    out_json_path = Path(args.out_json) if args.out_json else None
    out_csv_path = Path(args.out_csv) if args.out_csv else None
    out_stix_path = Path(args.out_stix) if args.out_stix else None

    if args.dry_run:
        logger.info("Dry-run enabled; not writing outputs.")
    else:
        try:
            if out_json_path:
                export_json(final_iocs, out_json_path, dry_run=args.dry_run)
                logger.info("Wrote JSON output to %s", out_json_path)
            if out_csv_path:
                export_csv(final_iocs, out_csv_path, dry_run=args.dry_run)
                logger.info("Wrote CSV output to %s", out_csv_path)
            if out_stix_path:
                export_stix_like(final_iocs, out_stix_path, dry_run=args.dry_run)
                logger.info("Wrote STIX-like output to %s", out_stix_path)
        except Exception:
            logger.error("Failed to write outputs: %s", traceback.format_exc())
            return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
