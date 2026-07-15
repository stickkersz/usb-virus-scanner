# USB Virus Scanner

Company-wide malware scanner for **USB drives and hard disks on Windows**.
Auto-scans any removable drive the moment it is plugged in, quarantines
infected files off the drive, and writes audit logs + reports for IT.

> 📖 Prefer plain-language, step-by-step instructions with screenshots-in-words?
> Read the **[Installation & User Guide (GUIDE.md)](GUIDE.md)**. This README is
> the quick reference + technical detail.

---

# Installation

Pick the one that fits you.

## 1. Employees — install from the one setup file (easiest)

Your IT team gives you **`USBVirusScannerSetup.exe`**. Nothing else needed.

1. **Double-click** `USBVirusScannerSetup.exe`.
2. If Windows shows "Windows protected your PC", click **More info → Run anyway**.
3. Click **Yes** at the admin prompt.
4. Tick the options you want (defaults are fine):
   - ☑ Create a desktop shortcut
   - ☑ Auto-scan every USB drive on insert (recommended)
5. Click **Install → Finish**.

Done. The scanner, the virus engine, and the virus database all install from
that single file. A **USB Virus Scanner** icon appears on your desktop.

## 2. IT — build the one setup file

Do this once on a Windows machine, then hand the result to everyone.

**Prerequisites:** [Python 3.9+](https://www.python.org/downloads/) (tick "Add
to PATH") and [Inno Setup 6](https://jrsoftware.org/isdl.php).

```powershell
git clone https://github.com/stickkersz/usb-virus-scanner.git
cd usb-virus-scanner

# Fully offline installer (employees need no internet) — recommended:
powershell -ExecutionPolicy Bypass -File build\build.ps1 -Offline

# ...or a smaller installer that downloads ClamAV during each install:
powershell -ExecutionPolicy Bypass -File build\build.ps1
```

Result: **`Output\USBVirusScannerSetup.exe`** — the single file to deploy.

Deploy silently across the fleet (SCCM / Intune / GPO):

```powershell
USBVirusScannerSetup.exe /VERYSILENT /NORESTART
```

## 3. Install from source (dev / quick try)

Runs on Windows, macOS, and Linux. Needs **Python 3.9+**.

```bash
git clone https://github.com/stickkersz/usb-virus-scanner.git
cd usb-virus-scanner
python -m pip install -r requirements.txt

python cli.py drives          # list removable drives
python cli.py scan <path>     # scan a folder/drive
python gui.py                 # launch the GUI
```

ClamAV is optional here — without it, the heuristic + hash + YARA layers still
run (you'll see a "ClamAV not found" notice). Install ClamAV for full signature
coverage. (Windows one-shot installer for the source layout:
`powershell -ExecutionPolicy Bypass -File install.ps1 -RegisterWatcher`.)

---

# Usage

## GUI (end users)

```powershell
python gui.py          # or double-click the desktop shortcut
```

Pick a drive (or **Browse…** a folder) → click **Scan** → read the colored
banner (green CLEAN / red THREATS). Infected files are quarantined
automatically; **Quarantine…** lists them and can restore. Tick **Report only**
to detect without moving anything.

## CLI (IT / fleet)

```powershell
usbscan drives                 # list attached removable drives
usbscan scan E:\               # scan a drive now (quarantines threats)
usbscan scan E:\ --no-quarantine   # report only, touch nothing
usbscan watch                  # auto-scan every USB as it is inserted
usbscan update                 # refresh ClamAV signatures (freshclam)
usbscan quarantine             # list quarantined files
usbscan quarantine --restore <ID> --to D:\recovered.bin
```

Exit code `0` = clean, `1` = threats found — usable in scripts / GPO. (From
source, use `python cli.py …` instead of `usbscan …`.)

## Prove it works (safe test)

```powershell
python tests\make_eicar.py C:\temp\eicartest    # writes harmless EICAR test file
usbscan scan C:\temp\eicartest                  # must report a detection
```

EICAR is the industry-standard harmless AV test string — every scanner flags
it, it does nothing.

---

# How it works

Four detection layers, each catching what the others miss:

| Layer | What it catches | Engine |
|-------|-----------------|--------|
| **ClamAV signatures** | Millions of known viruses/malware, inside archives too | `clamscan` / `clamdscan` |
| **Company hash blocklist** | Known-bad files from your own IR / threat intel | SHA-256 match |
| **YARA rules** | Behavior patterns, zero-days ClamAV misses | `yara-python` |
| **USB heuristics** | `autorun.inf` autostart, double extensions (`invoice.pdf.exe`), risky script droppers | built-in |

Two front-ends (`gui.py`, `cli.py`) drive one shared **`ScanEngine`**. A scan is
a pipeline:

```
   insert USB / pick target
            │
   ┌────────▼─────────┐
   │ 1. Walk the tree │  os.scandir, once. Collect path+size+mtime.
   │    (single pass) │  Apply max-file-size cap.
   └────────┬─────────┘
   ┌────────▼─────────┐
   │ 2. Cache filter  │  Drop files unchanged since last CLEAN scan
   │                  │  (path+size+mtime match) → candidate list.
   └────────┬─────────┘
   ┌────────▼─────────┐
   │ 3. ClamAV        │  Candidates handed to clamscan/clamdscan via
   │    signatures    │  --file-list (+ --multiscan). Parses "FOUND".
   └────────┬─────────┘
   ┌────────▼─────────┐
   │ 4. Heuristic     │  Thread pool. Per file: autorun.inf, double
   │    layer         │  extension, SHA-256 hash blocklist, YARA rules.
   │                  │  Deep read gated to risky/small files (fast mode).
   └────────┬─────────┘
   ┌────────▼─────────┐
   │ 5. Quarantine    │  INFECTED files moved off the drive, XOR-
   │                  │  neutralized, indexed for restore.
   └────────┬─────────┘
   ┌────────▼─────────┐
   │ 6. Log + report  │  Rotating log, JSONL for SIEM, text report.
   │    + cache clean │  Clean files recorded so next scan skips them.
   └──────────────────┘
```

A confirmed infection is moved to a neutralized quarantine (XOR-obfuscated so it
can't be double-clicked into execution), logged, and put in a per-scan report.
Everything is reversible via `quarantine --restore`.

**Removable-drive detection** uses the Win32 API (`GetLogicalDrives` /
`GetDriveType`) via `ctypes` — no service, no admin, works Windows 7→11. The
`watch` command polls for drive arrival and auto-scans on insert.

## Project layout

```
usb-virus-scanner/
├── cli.py               # CLI entry point (scan/watch/drives/quarantine/update)
├── gui.py               # Tkinter desktop GUI
├── config.yaml          # all tunables (paths, speed, detection knobs)
├── scanner/
│   ├── engine.py        # ScanEngine + ClamAV wrapper (the pipeline above)
│   ├── heuristics.py    # autorun/double-ext + hash blocklist + YARA
│   ├── quarantine.py    # move / neutralize / restore + index
│   ├── cache.py         # skip unchanged-clean files
│   ├── watcher.py       # USB insert detection (Win32 ctypes)
│   ├── reporter.py      # logging + JSONL + text reports
│   ├── paths.py         # source vs frozen-exe base dir
│   ├── config.py        # config load + defaults
│   └── models.py        # Detection / ScanResult types
├── signatures/
│   ├── hash_blocklist.txt   # your SHA-256 blocklist
│   └── yara/usb_threats.yar # starter YARA rules
├── tests/               # pytest suite + EICAR generator
└── build/               # PyInstaller spec + Inno Setup + icon → setup.exe
```

---

# Deployment & operations

## Fully-offline installer (zero downloads on the employee PC)

By default the installer fetches the ClamAV engine + virus database from the
internet (winget + freshclam) during setup. To bundle **everything** into the
one setup file so employees need **no internet at all**:

```powershell
# on the build machine, WITH internet, ONE time:
powershell -ExecutionPolicy Bypass -File build\fetch-vendor.ps1   # ClamAV + signatures -> vendor\
powershell -ExecutionPolicy Bypass -File build\build.ps1          # bundles them

# or both at once:
powershell -ExecutionPolicy Bypass -File build\build.ps1 -Offline
```

The build auto-detects `vendor\ClamAV\` at compile time: when present, ClamAV
and the full signature DB are packed inside `USBVirusScannerSetup.exe` and every
online step is removed. Re-run `fetch-vendor.ps1` to refresh the bundled
signatures. (`vendor\` is git-ignored — ~450 MB of Windows binaries, not
committed.)

The app icon (`build\app.ico`) is embedded into both exes and the shortcuts;
regenerate it with `python build\make_icon.py` (needs Pillow). Build artifacts
(`dist\`, `Output\`) are git-ignored.

## Fleet deployment

- **Recommended:** push `USBVirusScannerSetup.exe` via SCCM/Intune/GPO, install
  with `/VERYSILENT /NORESTART`. (Source alternative: push the folder + run
  `install.ps1 -RegisterWatcher`.)
- The watcher runs as a startup scheduled task under SYSTEM; every inserted USB
  is scanned automatically, no user action.
- Ship `events.jsonl` to your SIEM for company-wide visibility.
- Maintain `signatures/hash_blocklist.txt` centrally and sync it out; add hashes
  as incidents happen.
- Keep signatures fresh: schedule `usbscan update` (or `freshclam`).

---

# Configuration & tuning

All behavior lives in `config.yaml` (ClamAV paths, quarantine dir, suspicious
extensions, workers, poll interval, speed knobs). Defaults are built in, so the
tool runs even if the file is missing.

## Speed on slow laptops

- **Single tree walk** — the drive is enumerated once; ClamAV gets a file-list
  instead of re-walking the tree (was double disk IO).
- **Scan cache** (`use_cache`) — files unchanged since the last clean scan are
  skipped entirely. Re-scanning the same USB / hard disk is near-instant. Cache
  lives in `…\Logs\scan_cache.json`.
- **Fast mode** (`deep_scan_all: false`) — SHA-256 + YARA only run on risky-type
  files or files under `deep_scan_max_mb` (default 50). Big media isn't read
  byte-by-byte. Set `deep_scan_all: true` for max thoroughness.
- **Parallel** — `workers: auto` scales to CPU cores (capped so a single-disk
  laptop doesn't thrash); `multiscan: true` uses clamd's parallel engine.
- **Skip archives** for extra speed on weak hardware: `scan_archives: false`.

Cheatsheet — very slow laptop: `deep_scan_max_mb: 20`, `scan_archives: false`,
`use_cache: true`. Air-gapped high-security box: `deep_scan_all: true`,
`scan_archives: true`.

---

# Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q          # 45 tests: cache, quarantine, heuristics, engine, CLI, units
```

The suite covers detection correctness, quarantine round-trip (byte-exact
restore), cache invalidation, deep-scan gating, CLI exit codes, and config
merging. No ClamAV needed — the heuristic/hash/YARA layers are exercised
directly.

## Windows compatibility

Drive detection uses the Win32 API via `ctypes` — Windows 7 → 11 / Server, no
extra service. ClamAV and Python 3.9+ are the only prerequisites. On
Linux/macOS it falls back to mount-point polling so you can develop off Windows.

## Notes / limits

- Quarantine "neutralize" is XOR obfuscation to stop accidental execution — not
  cryptographic protection of the sample.
- Detection is only as good as the ClamAV DB — keep it fresh.
- Run the watcher elevated so it can read/quarantine files owned by other users.
