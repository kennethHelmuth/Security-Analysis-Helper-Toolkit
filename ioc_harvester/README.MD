# IOC Harvester

IOC Harvester is a production-quality Python 3.11 CLI tool for extracting, validating, normalizing, deduplicating, and exporting Indicators of Compromise (IOCs) from files and directories.

It is designed for **CTI, DFIR, and malware lab workflows** where you need fast, safe, repeatable IOC extraction without executing any suspicious content.

The tool reads files strictly as data and never runs or imports untrusted code.

---

# Features

- Extracts common IOC types:
  - IPv4 / IPv6
  - Domains & subdomains
  - URLs
  - Email addresses
  - Hashes (MD5, SHA1, SHA256, SHA512)
  - Suspicious filenames (.exe, .dll, .jar, .apk, etc.)
  - ssdeep-like patterns (heuristic)
  - Basic crypto wallet patterns (Bitcoin / Ethereum — heuristic)

- Validation & normalization:
  - IPs validated with `ipaddress`
  - Domains normalized to lowercase + optional punycode
  - URLs parsed and normalized
  - Hashes normalized to lowercase
  - Conservative domain/TLD checks

- Deduplication with provenance:
  - One canonical record per IOC
  - Tracks all source files and line numbers / JSON paths

- Confidence scoring:
  - Heuristic score (0–100)
  - Context-aware boosts and noise penalties
  - Filter with `--min-confidence`

- Safe & scalable:
  - Streaming file reads (no large memory loads)
  - Binary file detection and skip
  - File size limits
  - Threaded scanning for I/O performance

- Multiple export formats:
  - JSON
  - CSV
  - Minimal STIX-like JSON bundle

- Extensible:
  - Plugin extractor hook
  - Configurable weights via JSON/YAML config

---

# Installation

Python 3.11+ required.

Standard library is sufficient:

```bash
python3 ioc_harvester.py --version
