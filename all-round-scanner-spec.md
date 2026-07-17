# All-Round Malware Scanner — Full Spec & Agent Prompt

## Project identity
- Repo: `C:\Users\ITPvg\all-rounder-virus-scanner` (name stays for now; scope expands)
- Language: Python
- Packaging: PyInstaller → `dist\AllRounderVirusScanner.exe`, `dist\arvscan.exe`
- Installer: Inno Setup 6 via `build\build.ps1`
- New scope: scan **every local/removable disk**, monitor files **in real time**, and
  add **internet/web protection** (URL reputation + download scanning)

---

## 1. Module / folder layout

```
all-rounder-virus-scanner/
├── build/
│   └── build.ps1
├── installer/
│   └── setup.iss
├── scanner/
│   ├── __init__.py
│   ├── config.py            # scan targets, exclusions, feature flags
│   ├── engine/
│   │   ├── hashing.py        # MD5/SHA256 blocklist matching
│   │   ├── yara_rules.py     # yara-python integration + rule loading
│   │   ├── heuristics.py     # extension spoofing, autorun.inf, LNK abuse, entropy
│   │   └── pe_analysis.py    # PE header sanity checks for Windows binaries
│   ├── targets/
│   │   ├── drives.py         # enumerate fixed/removable/network drives
│   │   └── walker.py         # safe file-tree walking (symlinks, junctions, locks)
│   ├── realtime/
│   │   ├── watcher.py        # filesystem event monitoring (watchdog)
│   │   └── queue_worker.py   # debounced scan queue for changed files
│   ├── web/
│   │   ├── url_reputation.py # domain/URL blocklist + reputation lookups
│   │   └── download_hook.py  # intercept/scan files as they land in Downloads
│   ├── quarantine/
│   │   ├── store.py          # move+lock quarantined files, restore capability
│   │   └── policy.py         # quarantine vs delete vs report-only rules
│   ├── logging_/
│   │   └── logger.py         # unified scan/event log, shared by all modules
│   └── cli.py / gui.py       # existing entry points, generalized
├── tests/
│   ├── fixtures/              # EICAR string only — never real malware
│   ├── test_engine.py
│   ├── test_realtime.py
│   └── test_web.py
└── CLAUDE.md
```

---

## 2. Detection engine (core, mostly reused from USB-only version)

- **Hash matching**: SHA256 primary, MD5 fallback for legacy signature lists. Load
  blocklists from local files first (offline mode), optionally sync from a feed later.
- **YARA rules**: use `yara-python`; keep rules in `scanner/engine/rules/*.yar`,
  hot-reloadable without rebuilding the exe.
- **Heuristics**:
  - Double extensions (`invoice.pdf.exe`), extension/magic-byte mismatch
  - `autorun.inf` abuse on removable drives
  - Malicious `.lnk` target patterns
  - Shannon entropy check to flag packed/obfuscated binaries (flag only, don't
    auto-quarantine on entropy alone — high false-positive rate)
- **PE analysis**: basic header sanity (suspicious section names, unusual entry
  point, missing digital signature on system-looking binaries)

Severity should be a weighted score, not a single boolean — combine signals so one
weak heuristic alone doesn't trigger quarantine.

---

## 3. Full-disk scanning (generalizing from USB-only)

- Replace hardcoded USB-drive detection with a generic `targets/drives.py` that
  enumerates: fixed drives, removable drives, and (optionally, opt-in) mapped
  network drives.
- Add scan profiles: **Quick** (common malware drop locations — Downloads, Temp,
  AppData, Startup folders), **Full** (every selected drive), **Custom** (user-picked
  paths).
- Respect exclusions (config-driven) for large media/dev folders to keep scan times
  reasonable — surface this as a setting, not a hardcoded skip list.

---

## 4. Real-time monitoring

- Use `watchdog` to observe filesystem events on in-scope drives.
- New/modified files go into a debounced queue (`queue_worker.py`) so rapid writes
  (e.g. a big download) don't trigger dozens of redundant scans.
- Real-time scans should reuse the same detection engine as full scans — no
  duplicated logic.
- Surface real-time alerts through the same notification path as manual scans.

---

## 5. Internet/web protection

- **URL reputation**: check outbound URLs (via browser extension hook or DNS-layer
  hook — pick one, don't try to build both at once) against a reputation list before
  allowing navigation/download. Use a real, licensed/public threat-intel source you
  actually have access to — don't fabricate a data feed.
- **Download scanning**: hook the OS Downloads folder (or browser download event, if
  going the extension route) and scan files the moment they land, before the user
  opens them.
- Keep this module optional/toggleable — some environments will only want local
  disk protection.

---

## 6. Quarantine, logging, config

- One shared quarantine store used by disk scans, real-time monitoring, and web
  protection — don't build three separate quarantine systems.
- Quarantine = move to a restricted-permission folder + record original path/hash/
  reason, with a restore function.
- Config file (`config.py` + a user-editable JSON/YAML) controls: scan targets,
  exclusions, real-time on/off, web protection on/off, quarantine vs report-only.
- Logging should be structured (JSON lines) so the GUI can render history without
  re-parsing free text.

---

## 7. Testing strategy

- Unit tests per engine module (hashing, YARA, heuristics) using the **EICAR test
  string** as the only "malicious" fixture — never real malware samples.
- Mock filesystem/drive enumeration so tests don't depend on real USB hardware.
- Mock the web-reputation lookup so web tests don't depend on live network calls.
- Add a regression test that a known-clean file set produces zero false positives.

---

## 8. Build/packaging updates

- Update `build.ps1` for any new dependencies (`watchdog`, `yara-python`, whatever
  web-reputation client library is chosen) — make sure PyInstaller picks up hidden
  imports and any data files (YARA rule files, blocklists).
- Update `installer/setup.iss` if new background services (real-time watcher) need
  to register as a Windows service or startup task.
- Keep the two existing entry points (GUI/CLI) working throughout — don't break the
  USB-only flow while adding the rest.

---

## 9. Suggested phased rollout (so nothing breaks mid-upgrade)

1. Generalize drive enumeration (USB → any disk), keep everything else the same.
2. Add scan profiles (Quick/Full/Custom) on top of the generalized scanning.
3. Add real-time monitoring using the existing engine.
4. Add web protection as an optional module.
5. Consolidate logging/quarantine across all four scan types.

---

## 10. Guardrails (apply to every phase)

- Defensive tooling only. Never generate, embed, or test against real malicious
  payloads, exploit code, or live malicious URLs — EICAR string and known-safe
  fixtures only.
- Use publicly documented detection techniques. No techniques designed to evade or
  interfere with other AV/EDR products.
- Any new external data feed (hash lists, URL reputation, YARA rule sets) must be a
  real source you have access/rights to use — flag it before wiring it in.
- Explain the false-positive tradeoff of every new heuristic before enabling it by
  default.
