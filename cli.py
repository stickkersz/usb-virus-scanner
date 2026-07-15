#!/usr/bin/env python3
"""USB Virus Scanner - command-line entry point.

Commands:
  scan <path>       Scan a drive/folder/file now.
  watch             Auto-scan every removable drive as it is inserted.
  drives            List currently attached removable drives.
  quarantine        List or restore quarantined files.
  update            Update ClamAV signatures via freshclam.
  version           Print version.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

from scanner import __version__
from scanner.config import Config
from scanner.engine import ScanEngine
from scanner.paths import app_base_dir
from scanner.reporter import log_result, setup_logging, write_report
from scanner.watcher import DriveWatcher, list_removable

BASE_DIR = app_base_dir()


def _load(args) -> tuple[Config, ScanEngine, object]:
    cfg = Config.load(args.config)
    logger = setup_logging(cfg["logging"])
    engine = ScanEngine(cfg, BASE_DIR)
    if not engine.clam.available:
        logger.warning("ClamAV not found - running heuristic/hash/YARA layer only. "
                       "Install ClamAV for full signature coverage.")
    return cfg, engine, logger


def _print_summary(result, report_path: str) -> None:
    verdict = "CLEAN" if result.clean else "THREATS FOUND"
    print("-" * 60)
    print(f"Target   : {result.target}")
    print(f"Scanned  : {result.files_scanned} files "
          f"({result.files_skipped} skipped)")
    print(f"Infected : {len(result.infected)}   "
          f"Suspicious: {len(result.suspicious)}")
    print(f"Verdict  : {verdict}")
    for d in result.infected:
        moved = f"  -> quarantined: {d.quarantined_to}" if d.quarantined_to else ""
        print(f"  [INFECTED]   {d.threat}  {d.path}{moved}")
    for d in result.suspicious:
        print(f"  [SUSPICIOUS] {d.threat}  {d.path}")
    print(f"Report   : {report_path}")
    print("-" * 60)


def _fmt_progress(ev) -> str:
    if ev.phase == "scanning" and ev.total:
        return f"  [{ev.current}/{ev.total}] {ev.message}"
    return f"  {ev.message}"


def cmd_scan(args) -> int:
    cfg, engine, logger = _load(args)
    result = engine.scan(
        args.path,
        progress=(lambda ev: print(_fmt_progress(ev))) if args.verbose else None,
        quarantine=not args.no_quarantine,
    )
    log_result(logger, result)
    report = write_report(cfg["reporting"], result)
    _print_summary(result, report)
    return 1 if result.infected else 0


def cmd_watch(args) -> int:
    cfg, engine, logger = _load(args)
    poll = cfg["watcher"].get("poll_interval", 3)
    quarantine = not args.no_quarantine

    def on_insert(root: str) -> None:
        logger.info("Removable drive inserted: %s - auto-scanning", root)
        print(f"\n[+] Drive inserted: {root} - scanning...")
        result = engine.scan(root, quarantine=quarantine)
        log_result(logger, result)
        report = write_report(cfg["reporting"], result)
        _print_summary(result, report)
        if result.infected:
            print(f"\n  !!! {len(result.infected)} THREAT(S) on {root} - quarantined.")

    print(f"USB Virus Scanner watcher running (poll {poll}s). Ctrl+C to stop.")
    print(f"Currently attached removable drives: {list_removable() or 'none'}")
    watcher = DriveWatcher(on_insert, poll_interval=poll)
    try:
        watcher.run_forever()
    except KeyboardInterrupt:
        print("\nWatcher stopped.")
    return 0


def cmd_drives(args) -> int:
    drives = list_removable(include_fixed=args.all)
    if not drives:
        print("No removable drives detected.")
    for d in drives:
        print(d)
    return 0


def cmd_quarantine(args) -> int:
    cfg = Config.load(args.config)
    from scanner.quarantine import Quarantine
    q = Quarantine(cfg["quarantine"])
    if args.restore:
        dest = q.restore(args.restore, to=args.to)
        print(f"Restored to: {dest}" if dest else "Restore failed (unknown id?).")
        return 0 if dest else 1
    if args.delete:
        ok = q.delete(args.delete)
        print("Deleted permanently." if ok else "Delete failed (unknown id?).")
        return 0 if ok else 1
    if args.purge:
        pending = len(q.list_entries())
        if pending == 0:
            print("Quarantine already empty.")
            return 0
        if not args.yes:
            reply = input(f"Permanently delete all {pending} quarantined file(s)? "
                          "This cannot be undone [y/N]: ").strip().lower()
            if reply not in ("y", "yes"):
                print("Aborted.")
                return 1
        n = q.delete_all()
        print(f"Permanently deleted {n} file(s).")
        return 0
    entries = q.list_entries()
    if not entries:
        print("Quarantine empty.")
        return 0
    print(f"{'ID':34}  {'THREAT':30}  ORIGINAL")
    for e in entries:
        print(f"{e['id']:34}  {e.get('threat','')[:30]:30}  {e.get('original','')}")
    return 0


def cmd_update(args) -> int:
    fresh = shutil.which("freshclam") or r"C:\Program Files\ClamAV\freshclam.exe"
    if not (os.path.isfile(fresh) or shutil.which("freshclam")):
        print("freshclam not found. Install ClamAV first.")
        return 1
    print("Updating ClamAV signatures...")
    cmd = [fresh]
    # freshclam needs a config file; a winget/portable ClamAV may ship only a
    # .sample. Point it at a real freshclam.conf if we can find one next to the
    # binary so the update doesn't fail with "Can't parse the config file".
    clam_dir = os.path.dirname(fresh) if os.path.isabs(fresh) else \
        r"C:\Program Files\ClamAV"
    conf = os.path.join(clam_dir, "freshclam.conf")
    if os.path.isfile(conf):
        cmd.append(f"--config-file={conf}")
    return subprocess.call(cmd)


def cmd_version(args) -> int:
    print(f"USB Virus Scanner {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="usb-virus-scanner",
                                description="Company USB/disk malware scanner for Windows.")
    p.add_argument("-c", "--config", default=os.path.join(BASE_DIR, "config.yaml"),
                   help="Path to config.yaml")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a drive/folder/file")
    s.add_argument("path", help="Drive root (E:\\), folder, or file")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--no-quarantine", action="store_true",
                   help="Detect and report only; never move files")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="Auto-scan removable drives on insert")
    w.add_argument("--no-quarantine", action="store_true")
    w.set_defaults(func=cmd_watch)

    d = sub.add_parser("drives", help="List removable drives")
    d.add_argument("--all", action="store_true", help="Include fixed disks")
    d.set_defaults(func=cmd_drives)

    q = sub.add_parser("quarantine",
                       help="List, restore, or permanently delete quarantined files")
    q.add_argument("--restore", metavar="ID", help="Restore a quarantined file by id")
    q.add_argument("--to", help="Restore destination path (default: original)")
    q.add_argument("--delete", metavar="ID",
                   help="Permanently delete one quarantined file (irreversible)")
    q.add_argument("--purge", action="store_true",
                   help="Permanently delete ALL quarantined files (irreversible)")
    q.add_argument("--yes", action="store_true",
                   help="Skip the confirmation prompt for --purge")
    q.set_defaults(func=cmd_quarantine)

    u = sub.add_parser("update", help="Update ClamAV signatures (freshclam)")
    u.set_defaults(func=cmd_update)

    v = sub.add_parser("version")
    v.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
