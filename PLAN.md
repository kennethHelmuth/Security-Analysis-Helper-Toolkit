# Security Analysis Helper Toolkit — Development Plan

> **Status:** Awaiting author review. No code has been written.  
> **Date:** 2026-06-25  
> **Scope:** Gap analysis of existing scripts → proposed additions, ordered by priority.

---

## 1. What the Existing Scripts Actually Do

Reading each file completely before forming any opinions:

| Script | Core job | CLI shape | Key conventions |
|--------|----------|-----------|-----------------|
| `mkcase.py` | Create a dated, permission-locked case directory tree (`samples/`, `static/`, `dynamic/`, `iocs/`, `notes/`, `output/`, `reports/`) | `mkcase.py CASE_NAME [--base-dir] [--dry-run]` | `run() → (exit_code, msg)`, named exit codes, `0o700` on root, sanitized folder names |
| `mkhash.py` | Stream-hash a file (MD5/SHA1/SHA256/SHA512) and optionally append to a dated `YYYY-MM-DD_hashes.txt` log | `mkhash.py FILE ALG [--out-dir] [--append] [--yes]` | Interactive confirm unless `--yes`, 64 KiB streaming, human-readable log line `[HH:MM:SS] alg  filename  hex` |
| `ioc_harvester.py` | Extract, validate, normalize, deduplicate, and export IOCs (IP/domain/URL/email/hash/filename/wallet/ssdeep) from files or directories | `ioc_harvester.py PATH [--recursive] [--out-json/csv/stix] [--min-confidence] [--config] [--plugin-dir] …` | `logging` module (not bare print), dataclasses, `ThreadPoolExecutor`, optional `tldextract`/`idna`/`yaml`, confidence scoring 0–100 |

### Shared Style DNA

All three scripts share conventions that new additions must match:

- `#!/usr/bin/env python3` shebang
- Module-level docstring with `Usage:` block
- `from __future__ import annotations`
- `argparse` + `pathlib.Path` for all CLI and filesystem work
- Full type hints throughout
- Small, single-purpose functions with docstrings
- `main(argv: list[str] | None = None)` signature
- `if __name__ == "__main__": main()` (or `raise SystemExit(main())`)
- Explicit, documented exit codes; errors go to `stderr`
- `--dry-run` wherever filesystem writes occur
- `--yes` / `-y` to skip interactive confirmation
- Streaming reads; never load a full file into memory when avoidable
- Default paths rooted under `~/malware_cases/`
- Zero required third-party deps; optional imports wrapped in `try/except`

---

## 2. Gaps Identified and Why They Matter

### 2.1 "Safe archive unpacking" — promised in README, completely absent

The root README lists "safe archive unpacking" as a supported workflow. Zero implementation exists. Analysts routinely receive malware samples inside password-protected zips (password: `infected`, `virus`, `malware`). Unpacking these manually with the system unzip tool is dangerous:

- **Path traversal attacks** (`../../../etc/cron.d/evil`) in crafted archives can write outside the target directory.
- **Zip bombs** can exhaust disk space and crash the host.
- **Symlink attacks** in tar archives can redirect writes to sensitive paths.
- No hash verification after extraction means silent corruption or tampering goes undetected.

Without a safe unpacker in the toolkit, analysts either skip these protections entirely or reach for ad-hoc shell one-liners that leave no audit trail.

### 2.2 Sample ingestion has no tooling

`mkcase.py` builds the folder skeleton but there is no way to formally add a sample to a case. Every analyst runs the same manual sequence for every sample: copy file → hash it → record the hash → note original filename → log where it came from. This sequence is error-prone and unaudited. An `addsample.py` would collapse that into a single logged, reproducible command and would be the single most used tool in daily workflow.

### 2.3 No file identification before analysis

Before doing anything with an unknown file, an analyst needs to know what it actually is — not what its extension claims. Magic byte inspection, MIME type guessing, entropy measurement (packed/encrypted files show near-8.0 bits/byte), and basic size metadata are the first four questions asked for every sample. Currently an analyst must leave the toolkit entirely and call `file(1)`, `ent`, and `stat` separately. There is no stdlib barrier to doing this in Python (`struct`, `mimetypes`, `math`).

### 2.4 String extraction is missing

Extracting printable ASCII and wide-character strings from a binary is almost always the second thing done after file ID. It catches obvious C2 domains, file paths, registry keys, and compile-time artifacts with no risk of execution. The system `strings(1)` binary is not always present in lab environments, and when it is, its output goes nowhere auditable. A Python equivalent that writes to the case's `static/` directory is a clear win.

### 2.5 No PE file inspection

The majority of malware samples analysts encounter are Windows PE files. Even without executing them, the PE header contains high-value static observables: architecture, compile timestamp (often meaningful for clustering), section names and characteristics, import table (DLLs and functions), exported functions, and debug path artifacts. All of this is accessible with only Python's `struct` module. This is a significant friction point currently requiring a separate tool.

### 2.6 No defang / refang utility

IOC defanging (`http://evil.com` → `hxxp://evil[.]com`) and refanging (the reverse) is something analysts do dozens of times per day when writing reports, pasting into emails, ingesting threat intel reports, and feeding IOCs into other tools. It is repetitive and rule-based. Critically, `ioc_harvester.py` does not handle defanged input, which means threat intel reports and analyst notes with defanged IOCs are not correctly parsed.

### 2.7 No local threat intel lookup

The toolkit is explicitly designed for offline/lab workflows. There is no way to check whether an extracted IOC appears in a known-bad list without leaving the toolkit. A tool that ingests flat-file or SQLite threat feeds (abuse.ch URLhaus CSV, Emerging Threats IP lists, MISP CSV exports) offline and answers "is this IOC known bad?" fills a critical gap. Online API support (VirusTotal, MalwareBazaar) can be optional.

### 2.8 No case-level reporting or audit trail

`mkhash.py` writes a dated hash log but it is isolated — there is no case-wide audit trail recording which tools were run, when, on what input, with what result. An analyst finishing an investigation has no automated way to produce even a skeleton case report. A `mkreport.py` generating a Markdown summary of everything inside a case directory (files, hashes, IOCs found, notes) would make closing a case significantly less manual.

### 2.9 No way to navigate existing cases

`mkcase.py` creates cases but there is no `lscases.py` to list them with metadata (creation date, sample count, case name). Small quality-of-life gap that becomes painful with many concurrent investigations.

### 2.10 No shared utility module — style drift will compound

Three scripts exist and already share logging setup, path expansion, confirmation prompts, and argument-parsing patterns duplicated by hand in each file. As the toolkit grows, these copies will diverge. A shared `lib/toolkit_common.py` is the foundation that keeps all tools feeling native to one another.

---

## 3. Proposed New Scripts — Grouped by Workflow Stage

### Stage 1 — Case Setup

| Script | Purpose |
|--------|---------|
| `lscases.py` | List all existing cases under the base directory with creation date, sample count, and size — a directory of your active investigations. |

### Stage 2 — Sample Ingestion

| Script | Purpose |
|--------|---------|
| `addsample.py` | Copy or move a file into a case's `samples/` directory, auto-hash it with SHA256, record an audit log entry, and print the registration summary — the missing "intake" step. |
| `unpack.py` | Safely extract zip/tar/gzip archives into a specified output directory with path-traversal protection, zip-bomb limits, symlink rejection, optional password support (`-p infected`), and hash verification of extracted files. |
| `quarantine.py` | Lock a file in-place: set permissions to `0o400`, optionally rename with `.quarantine` suffix, and log the action with hash — prevents accidental execution of live samples. |

### Stage 3 — Static Analysis

| Script | Purpose |
|--------|---------|
| `fileinfo.py` | Identify a file's true type via magic bytes, compute entropy (bits/byte), report size, MIME guess, and any embedded timestamps — all using only the standard library, with output written to a case's `static/` directory. |
| `mkstrings.py` | Extract printable ASCII strings (≥ N chars, configurable) and wide-char (UTF-16LE) strings from any file, write them to `static/`, and report a summary — a Python-native `strings(1)`. |
| `peinfo.py` | Parse PE/COFF headers using only `struct`: report architecture, compile timestamp, section table (name, VA, size, entropy per section), import table (DLLs + functions), exported symbols, and debug directory path artifacts. |

### Stage 4 — IOC Handling

| Script | Purpose |
|--------|---------|
| `defang.py` | Bidirectional defang/refang of IOC values (`http` ↔ `hxxp`, `.` ↔ `[.]`, `://` ↔ `[://]`) — accepts stdin, file, or bare argument; makes `ioc_harvester.py` work correctly on threat intel reports written with defanged IOCs. |

### Stage 5 — Threat Intel

| Script | Purpose |
|--------|---------|
| `ioclookup.py` | Look up one or more IOCs against local flat-file or SQLite threat intel feeds (abuse.ch, Emerging Threats, MISP CSV exports) with optional online API fallback (VirusTotal, MalwareBazaar) — offline-first, results appended to the case's `iocs/` directory. |

### Stage 6 — Reporting & Audit Trail

| Script | Purpose |
|--------|---------|
| `mkreport.py` | Generate a structured Markdown case report from a case directory: list samples with hashes, static analysis findings, IOCs extracted, timeline of actions from the audit log, and open notes — the closing step of any investigation. |

### Shared Infrastructure

| Module | Purpose |
|--------|---------|
| `lib/toolkit_common.py` | Shared helpers: `setup_logging(verbose, quiet)`, `confirm(prompt, default_no)`, `resolve_path(s)`, `human_size(n_bytes)`, `audit_log_append(case_root, event_type, detail_dict)`, and documented exit code constants — imported by all scripts, never run directly. |

---

## 4. Detailed Notes on Key Proposals

### `unpack.py` — Safe Archive Extraction

This is the single most security-critical addition. Implementation constraints:

- **Path traversal guard:** every extracted member's resolved path must be confirmed to be a child of the output directory before extraction. Reject any member whose path resolves outside it.
- **Zip bomb limit:** total uncompressed size tracked incrementally; abort if it exceeds a configurable threshold (default: 500 MB).
- **Symlink rejection:** by default, refuse to extract symlinks. `--allow-symlinks` opt-in only.
- **Permissions:** extracted files get `0o600` (owner read/write only), directories `0o700`.
- **Hash verification:** after extraction, SHA256 each extracted file and write a manifest to the output directory.
- **Formats:** zip (stdlib `zipfile`), gzip-compressed tar (stdlib `tarfile`), single gzip (stdlib `gzip`) — no third-party deps needed.
- **Password support:** zip password via `ZipFile.setpassword()`.
- **Dry-run:** list members and total sizes without extracting.

### `fileinfo.py` — File Identification and Entropy

Entropy calculation is pure math (`math.log2`, byte frequency histogram). Magic byte detection covers the most common formats analysts encounter:

| Magic bytes | Format |
|-------------|--------|
| `MZ` | PE (Windows executable) |
| `\x7fELF` | ELF (Linux executable) |
| `%PDF` | PDF document |
| `PK\x03\x04` | ZIP archive |
| `\xd0\xcf\x11\xe0` | OLE2 / compound document (Office 97–2003) |
| `\x1f\x8b` | GZIP |
| `Rar!` | RAR archive |
| `7z\xbc\xaf` | 7-Zip archive |
| `{\rtf` | RTF document |

Output structured as JSON (to case `static/`) and human-readable summary to stdout — pipe-friendly.

### `peinfo.py` — Stdlib-Only PE Parsing

No `pefile` dependency. Key fields accessible with pure `struct`:

- DOS header → `e_magic` (MZ check), `e_lfanew` (PE offset)
- COFF header → Machine (arch), TimeDateStamp, NumberOfSections, Characteristics
- Optional header → Subsystem, DLL characteristics, ImageBase, entry point
- Section table → Name, VirtualAddress, SizeOfRawData, Characteristics; entropy per section
- Import Directory → walk IMAGE_IMPORT_DESCRIPTOR chain for DLL names; thunk table for function names
- Export Directory → export name table
- Debug Directory → type 2 (CodeView) → PDB path extraction

Output: structured JSON to `static/` + human-readable summary. This is enough for triage and clustering.

### `lib/toolkit_common.py` — Case-Wide Audit Log

The audit log (`YYYY-MM-DD_audit.log` inside the case root) is the single most impactful cross-cutting feature. Every tool that modifies case state should write a structured line to it:

```
[2026-06-25T08:00:00Z] addsample  sample=evil.exe  sha256=abc123…  case=20260625_operation_darkweb  result=ok
```

Plain-text, one-event-per-line — readable with `grep`, `awk`, and `tail -f`. No binary formats; no databases; the log is itself auditable.

### `defang.py` — Bidirectional Rules

| Direction | Input | Output |
|-----------|-------|--------|
| Defang | `http` | `hxxp` |
| Defang | `ftp` | `fxp` |
| Defang | `.` (in domain/IP context) | `[.]` |
| Defang | `://` | `[://]` |
| Refang | `hxxp` | `http` |
| Refang | `fxp` | `ftp` |
| Refang | `[.]` | `.` |
| Refang | `[://]` | `://` |
| Refang | `(@)` | `@` |

Accepts: `--defang` (default), `--refang`; input from positional arg, `--file`, or stdin. Outputs to stdout. Integrates as a pre-processor pipe before `ioc_harvester.py`.

### `ioclookup.py` — Offline-First Design

Feed ingestion (`--import-feed` mode) reads a flat file and loads it into a local SQLite database at `~/malware_cases/intel/ioc_feeds.db`. The lookup mode queries that database. Lookups are fast (indexed) and completely offline.

Feed formats supported: abuse.ch URLhaus CSV, Emerging Threats IP list (one IP per line), generic CSV with `type,value,tags` columns, MISP CSV export.

Optional `--vt-key` / `--mb-key` flags enable live API lookups appended to local results — never required, always opt-in.

---

## 5. README Design Goals vs. Current Implementation Status

| Design Goal (from README) | Implemented? | Notes |
|--------------------------|-------------|-------|
| Structured case setup | ✅ `mkcase.py` | Complete |
| File hashing and logging | ✅ `mkhash.py` | Complete; per-day log, not per-case |
| **Safe archive unpacking** | ❌ **Missing** | Explicitly listed in README, zero implementation |
| **Sample organization** | ❌ **Missing** | Folders exist; no tooling to populate them |
| **Audit-friendly processing** | ⚠️ Partial | Only `mkhash.py` has a log; no case-wide audit trail |
| IOC extraction | ✅ `ioc_harvester.py` | Complete and polished |
| Minimal dependencies | ✅ All scripts | Maintained throughout |
| Standard library first | ✅ All scripts | Optional third-party in `ioc_harvester.py` only |
| Explicit CLI behavior | ✅ All scripts | `--help`, `--dry-run`, predictable exit codes |
| Safe-by-default file handling | ⚠️ Partial | `mkcase.py` has `0o700`; no quarantine/safe unpack tool |
| No automatic execution | ✅ All scripts | Strictly maintained |
| Readable and auditable code | ✅ All scripts | Small focused functions, type hints |
| Linux-friendly | ✅ All scripts | pathlib, no Windows-only APIs |
| Offline/lab support | ✅ All scripts | No network calls in existing scripts |
| Dry-run modes | ⚠️ Partial | `mkcase.py` + `ioc_harvester.py` only; `mkhash.py` missing |
| Scriptable in pipelines | ⚠️ Partial | Exit codes consistent; stdin passthrough only in `defang.py` (proposed) |

---

## 6. Suggested Implementation Order

Ordered by: (a) removes the most analyst friction, (b) unblocks other tools, (c) simplest first within a tier.

```
Phase 1 — Foundation
  1. lib/toolkit_common.py     shared logging, audit log, confirm(), path helpers, exit codes
                               (nothing else can be consistent without this)

Phase 2 — Sample Ingestion (highest daily-use; two tools explicitly promised in README)
  2. addsample.py              most-used daily tool; builds directly on mkcase.py conventions
  3. unpack.py                 promised in README; safety-critical; unblocks sample intake

Phase 3 — Static Analysis (removes the biggest external-tool dependency)
  4. fileinfo.py               first thing run on every sample; feeds context to all downstream tools
  5. mkstrings.py              second thing run; pure stdlib; low implementation complexity
  6. quarantine.py             simple, safety-focused; natural companion to addsample.py

Phase 4 — IOC Workflow
  7. defang.py                 small, high-value; fixes ioc_harvester.py input gap immediately

Phase 5 — Static Analysis Advanced
  8. peinfo.py                 higher complexity (struct parsing); high value for PE-heavy labs

Phase 6 — Navigation & Intel
  9. lscases.py                quality-of-life; easy implementation
 10. ioclookup.py              highest complexity; depends on feed data; SQLite integration

Phase 7 — Reporting (integrates everything)
 11. mkreport.py               last because it summarizes outputs of all other tools
```

---

## 7. Proposed Repository Layout After Implementation

```
Security-Analysis-Helper-Toolkit/
├── README.md
├── PLAN.md
├── LICENSE
│
├── lib/
│   └── toolkit_common.py            ← shared utilities; imported, not run directly
│
├── Automating Scripts/
│   ├── mkcase.py                    ← existing
│   ├── mkhash.py                    ← existing
│   ├── lscases.py                   ← new: list/search cases
│   ├── addsample.py                 ← new: register a sample into a case
│   └── quarantine.py                ← new: lock down a live sample file
│
├── Sample Handling/
│   └── unpack.py                    ← new: safe archive extraction
│
├── Static Analysis/
│   ├── fileinfo.py                  ← new: file ID, entropy, magic bytes
│   ├── mkstrings.py                 ← new: printable string extraction
│   └── peinfo.py                    ← new: PE header inspection (stdlib only)
│
├── IOC Tools/
│   ├── defang.py                    ← new: defang/refang IOC values
│   └── ioclookup.py                 ← new: local + optional API threat intel lookup
│
├── ioc_harvester/
│   ├── README.MD                    ← existing
│   └── ioc_harvester.py             ← existing
│
└── Reporting/
    └── mkreport.py                  ← new: generate case Markdown report
```

> **Note on `lib/`:** `toolkit_common.py` is designed so each tool can import it from a relative path when run from the repo, and each script remains usable standalone if the import fails gracefully (mirroring how `ioc_harvester.py` handles optional `tldextract`/`idna`/`yaml`).

---

## 8. Out of Scope (Explicitly Not Planned)

- **Dynamic analysis hooks** (`strace`, `ltrace`, sandbox submission) — these involve execution of processed files, which the safety philosophy forbids.
- **Disassembly / decompilation** — requires third-party dependencies (`capstone`, `radare2`) incompatible with the stdlib-first principle.
- **GUI or web interface** — contradicts the composable CLI design goal.
- **Automated threat hunting / correlation** — out of scope for a file-handling toolkit.
- **Network-based C2 detection** — would require executing or running suspicious content.

---

*Awaiting author review. Implementation begins only after this plan is approved.*
