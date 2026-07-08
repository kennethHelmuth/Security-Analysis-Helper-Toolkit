# Security Analysis Helper Toolkit

A collection of lightweight, standalone Python CLI utilities for safe file handling, static analysis, IOC extraction, and workflow automation in controlled security analysis and malware lab environments (DFIR, CTI, malware analysts).

---

## 🛠️ Safety & Design Philosophy

Every utility in this toolkit is built with strict rules to keep your analysis environment safe, predictable, and clean:

*   **Offline / Lab First:** Zero network requirements by default. All analysis, lookup, and processing can run in isolated, air-gapped systems.
*   **Standard Library First:** Avoids bloated third-party frameworks. Python 3.11+ standard library is sufficient for all core functions. Optional dependencies are wrapped in graceful fallbacks.
*   **No Automatic Execution:** Processing files never imports, evaluates, or runs untrusted code.
*   **Defensive File Handling:** Safe archive unpacking (path-traversal protection, zip bomb limits, symlink rejections) and sample quarantining (`0o400` owner-read-only locking).
*   **Audit-Friendly:** Actions that modify case state are recorded in a plain-text, grep-friendly `audit.log` inside the case root directory.
*   **Scriptable & Composable:** Follows Unix philosophy. Clean exit codes, standard streams, pipe support, `--dry-run` modes, and non-interactive `--yes` flags.

---

## 📁 Directory Structure

```text
Security-Analysis-Helper-Toolkit/
├── README.md                  # This file
├── PLAN.md                    # Development gap analysis & roadmap
├── LICENSE
│
├── lib/
│   └── toolkit_common.py      # Shared helpers: logging, paths, hash computation, audit logs
│
├── Automating Scripts/
│   ├── mkcase.py              # Create permission-locked (0o700) standardized case directories
│   ├── lscases.py             # List and search active investigations with metadata
│   ├── addsample.py           # Register and hash a sample inside a case
│   ├── quarantine.py          # Lock down file permissions to read-only (0o400)
│   └── mkhash.py              # Compute cryptographic hashes and write dated log
│
├── Sample Handling/
│   └── unpack.py              # Safe ZIP/TAR/GZIP unpacking (traversal/bomb/symlink guards)
│
├── Static Analysis/
│   ├── fileinfo.py            # File format magic bytes, Shannon entropy, MIME types, and metadata
│   ├── mkstrings.py           # Python-native strings(1) extractor (ASCII & Wide UTF-16LE via mmap)
│   └── peinfo.py              # Standard-library-only struct parser for Windows PE/COFF headers
│
├── IOC Tools/
│   ├── defang.py              # Bidirectional IOC defanger/refanger (hxxp, [.] bracketed domains)
│   └── ioclookup.py           # Local SQLite feed ingestion/lookup & API enrichment (VT/MB)
│
├── ioc_harvester/
│   ├── ioc_harvester.py       # High-performance threaded IOC extraction/confidence scoring
│   └── README.MD
│
└── Reporting/
    └── mkreport.py            # Compile case report, summaries, and audit logs into Markdown
```

---

## 🚀 Getting Started & Workflows

Ensure you have Python 3.11+ installed. The toolkit is fully functional using only the standard library.

### 1. Ingesting & Preparing a Sample

```bash
# Create a new structured case directory
python3 "Automating Scripts/mkcase.py" target_malware_q3

# List existing cases to confirm setup
python3 "Automating Scripts/lscases.py" --verbose

# Safely extract an incoming password-protected archive
python3 "Sample Handling/unpack.py" ~/Downloads/sample.zip -p infected -o ~/malware_cases/*_target_malware_q3/samples --yes

# Register a raw sample to the case (auto-hashes, sets 0o400, and logs)
python3 "Automating Scripts/addsample.py" ~/Downloads/malicious.bin ~/malware_cases/*_target_malware_q3 --yes
```

### 2. Static Analysis Triage

```bash
# Get file type magic bytes, Shannon entropy, and cryptographic hashes
python3 "Static Analysis/fileinfo.py" ~/malware_cases/*_target_malware_q3/samples/malicious.bin --case-dir ~/malware_cases/*_target_malware_q3

# Inspect PE headers (Machine, entry point, section details, PDB paths, imports, and exports)
python3 "Static Analysis/peinfo.py" ~/malware_cases/*_target_malware_q3/samples/malicious.bin --case-dir ~/malware_cases/*_target_malware_q3

# Extract ASCII & Wide strings
python3 "Static Analysis/mkstrings.py" ~/malware_cases/*_target_malware_q3/samples/malicious.bin --case-dir ~/malware_cases/*_target_malware_q3
```

### 3. Threat Intel & IOC Hunting

```bash
# Import an Emerging Threats or URLhaus list into the local SQLite threat DB
python3 "IOC Tools/ioclookup.py" --import-feed emerging_ips.txt --feed-type emerging-threats-ip

# Extract IOCs from the analysis artifacts
python3 ioc_harvester/ioc_harvester.py ~/malware_cases/*_target_malware_q3/static --out-json ~/malware_cases/*_target_malware_q3/iocs/extracted_iocs.json

# Defang extracted domains/URLs for report pasting
python3 "IOC Tools/defang.py" --file ~/malware_cases/*_target_malware_q3/iocs/extracted_iocs.json

# Look up indicators in local threat DB with optional VirusTotal/MalwareBazaar lookup
python3 "IOC Tools/ioclookup.py" "192.168.1.1" "http://bad.domain.com" --case-dir ~/malware_cases/*_target_malware_q3
```

### 4. Case Closure & Audit Reporting

```bash
# Lock the live malware sample so it cannot be accidentally executed
python3 "Automating Scripts/quarantine.py" ~/malware_cases/*_target_malware_q3/samples/malicious.bin --rename --case-dir ~/malware_cases/*_target_malware_q3 --yes

# Compile directory structures, registered hashes, tool logs, analyst notes, and audit trails into a single report
python3 "Reporting/mkreport.py" ~/malware_cases/*_target_malware_q3
```

---

## 🛡️ Safety Configurations

### Safe Unpacking Details (`unpack.py`)
*   **Path Traversal Prevention:** Resolves absolute paths of all archive members. If a member resolves to a path outside the destination directory, execution aborts immediately.
*   **Zip Bomb Mitigation:** Tracks total uncompressed byte limits and blocks extraction if it exceeds 500 MB (configurable).
*   **Symlink Protection:** Blocks links, symlinks, and device files to prevent target redirects, unless explicitly overridden via `--allow-symlinks`.

### Centralized Audit Trails (`lib/toolkit_common.py`)
Each case includes a centralized `audit.log` tracking modifications:
```text
[2026-07-08T15:30:00+00:00]  addsample  sample=malicious.bin  sha256=a8f...  action=copy  dest=...
[2026-07-08T15:32:00+00:00]  fileinfo   file=malicious.bin  report=..._fileinfo.json  sha256=a8f...
[2026-07-08T15:35:00+00:00]  quarantine file=malicious.bin  sha256=a8f...  renamed=yes  final_path=...quarantine
```

---

## 📝 License
Private use inside controlled analysis networks. Verify corporate/lab compliance guidelines before distributing or packaging.
