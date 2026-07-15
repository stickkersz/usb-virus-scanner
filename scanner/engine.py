"""Scan engine: orchestrates ClamAV + the heuristic layer, then quarantines hits.

ClamAV does the heavy signature lifting (multi-million malware DB, archive
unpacking). The heuristic layer adds USB-specific detections and a company
hash/YARA blocklist. Results are merged and infected files are quarantined.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable, List, Optional

from .cache import ScanCache
from .heuristics import HeuristicEngine, sha256_of
from .models import Detection, ProgressEvent, ScanResult, Severity
from .quarantine import Quarantine


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(path: str) -> str:
    """Normalize a path for reliable matching between ClamAV's echoed paths and
    our own list (case-fold + separators on Windows, no-op on POSIX)."""
    return os.path.normcase(os.path.normpath(path))


class ClamAV:
    """Thin wrapper over clamscan/clamdscan. Degrades gracefully if absent."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.prefer_daemon = cfg.get("prefer_daemon", True)
        self.clamscan = self._resolve(cfg.get("clamscan_path"), "clamscan")
        self.clamdscan = self._resolve(cfg.get("clamdscan_path"), "clamdscan")
        self.max_mb = cfg.get("max_file_size_mb", 200)
        self.scan_archives = cfg.get("scan_archives", True)
        # clamdscan --multiscan uses all daemon threads in parallel — big win on
        # multi-core machines. Ignored by plain clamscan.
        self.multiscan = cfg.get("multiscan", True)
        # PUA = Potentially Unwanted Applications (adware, bundleware, PUPs).
        # Part of the "1.56B samples" are PUPs; ClamAV flags them only when asked.
        self.detect_pua = cfg.get("detect_pua", True)
        # ClamAV's own heuristics (broken-PE, packed, macro, phishing structure).
        self.heuristic_alerts = cfg.get("heuristic_alerts", True)
        # Optional explicit virus-DB directory. Needed for a bundled/portable
        # ClamAV so clamscan finds main.cvd/daily.cvd next to the exe. Passed
        # only when the directory actually exists (ignored on dev/mac).
        db = cfg.get("database_path")
        self.database_path = db if db and os.path.isdir(db) else None

    @staticmethod
    def _resolve(configured: Optional[str], name: str) -> Optional[str]:
        # Prefer the configured absolute path; fall back to PATH lookup so the
        # same config works on Linux/macOS test boxes and Windows prod.
        if configured and os.path.isfile(configured):
            return configured
        return shutil.which(name)

    @property
    def available(self) -> bool:
        return bool(self.clamscan or self.clamdscan)

    def _binary(self) -> Optional[tuple[str, bool]]:
        if self.prefer_daemon and self.clamdscan:
            return self.clamdscan, True
        if self.clamscan:
            return self.clamscan, False
        if self.clamdscan:
            return self.clamdscan, True
        return None

    def scan_filelist(self, list_path: str) -> tuple[List[Detection], List[str]]:
        """Scan exactly the files named in `list_path` (one path per line).

        Feeding ClamAV a precomputed list avoids a second full tree walk (the
        Python side already walked it) and lets the cache exclude unchanged
        files from the signature scan too.

        Prefers the resident daemon (fast: signature DB stays in RAM). If the
        daemon isn't running, transparently falls back to one-shot clamscan so a
        stopped clamd service never blocks scanning.
        """
        chosen = self._binary()
        if not chosen:
            return [], ["ClamAV binary not found; signature scan skipped."]
        binary, is_daemon = chosen

        dets, errs = self._run(binary, is_daemon, list_path)
        if is_daemon and errs and self.clamscan:
            # Daemon likely down (couldn't connect). Retry with plain clamscan.
            return self._run(self.clamscan, False, list_path)
        return dets, errs

    def _run(self, binary: str, is_daemon: bool,
             list_path: str) -> tuple[List[Detection], List[str]]:
        cmd = [binary, "--no-summary", "--infected", f"--file-list={list_path}"]
        # Detect adware / potentially-unwanted programs (works for clamscan and
        # clamdscan). Directly covers the "adware / PUP" threat category.
        if self.detect_pua:
            cmd.append("--detect-pua=yes")
        if not is_daemon:
            cmd += [f"--max-filesize={self.max_mb}M",
                    f"--max-scansize={self.max_mb}M"]
            cmd.append("--scan-archive=yes" if self.scan_archives
                       else "--scan-archive=no")
            # Turn on ClamAV's own heuristics (packed/broken PE, macros, etc.)
            # for better zero-day / novel-variant coverage.
            if self.heuristic_alerts:
                cmd += ["--heuristic-alerts=yes", "--alert-broken=yes"]
            # Point a portable/bundled clamscan at its bundled signature DB.
            if self.database_path:
                cmd.append(f"--database={self.database_path}")
        if is_daemon:
            # --fdpass lets clamd (running as another user) read the files.
            cmd.append("--fdpass")
            if self.multiscan:
                cmd.append("--multiscan")

        detections: List[Detection] = []
        errors: List[str] = []
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=3600)
        except FileNotFoundError:
            return [], [f"ClamAV binary missing: {binary}"]
        except subprocess.TimeoutExpired:
            return [], ["ClamAV scan timed out (>1h)."]

        # Exit codes: 0=clean, 1=virus found, 2=error.
        for line in proc.stdout.splitlines():
            if line.endswith(" FOUND"):
                # format: "<path>: <SignatureName> FOUND"
                try:
                    path, rest = line.rsplit(": ", 1)
                    sig = rest[: -len(" FOUND")].strip()
                except ValueError:
                    continue
                detections.append(Detection(path, Severity.INFECTED, sig,
                                            "clamav"))
        if proc.returncode == 2 and proc.stderr:
            errors.append(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "ClamAV error")
        return detections, errors


def _auto_workers(configured) -> int:
    """Resolve worker count. 'auto' -> scale to cores but stay modest so slow
    single-disk laptops don't thrash on seeks."""
    if isinstance(configured, int) and configured > 0:
        return configured
    cpu = os.cpu_count() or 2
    return max(2, min(8, cpu))


class ScanEngine:
    def __init__(self, config, base_dir: str):
        self.config = config
        self.base_dir = base_dir
        self.clam = ClamAV(config["scanner"])
        self.heur = HeuristicEngine(config["heuristics"], base_dir)
        self.quar = Quarantine(config["quarantine"])
        self.workers = _auto_workers(config["scanner"].get("workers", "auto"))
        self.max_bytes = config["scanner"].get("max_file_size_mb", 200) * 1024 * 1024
        cache_path = os.path.join(config["logging"].get("path", "."), "scan_cache.json")
        self.cache = ScanCache(cache_path,
                               enabled=config["scanner"].get("use_cache", True))

    def scan(self, target: str,
             progress: Optional[Callable[[ProgressEvent], None]] = None,
             quarantine: bool = True) -> ScanResult:
        result = ScanResult(target=target, started=_now())

        def emit(phase, message="", current=0, total=0):
            if progress:
                progress(ProgressEvent(phase, message, current, total))

        if not os.path.exists(target):
            result.errors.append(f"Target does not exist: {target}")
            result.finished = _now()
            return result

        # 1. Single tree walk. Collect (path, size, mtime_ns); apply size cap;
        #    skip files already scanned clean (unchanged) via the cache.
        emit("indexing", f"Indexing {target}")
        # (path, size, mtime_ns) -- mtime kept so caching reuses it (no re-stat).
        files: List[tuple[str, int, int]] = []
        cached_clean = 0
        for path, size, mtime in self._walk(target, result):
            if self.cache.is_clean(path, size, mtime):
                cached_clean += 1
                continue
            files.append((path, size, mtime))
        result.files_scanned = len(files)
        result.files_skipped += cached_clean
        total = len(files)

        if not files:
            emit("done", "Nothing new to scan (all cached clean)")
            result.finished = _now()
            return result

        # 2. ClamAV signature scan over just the candidate files (file-list).
        list_path = None
        scan_complete = True
        try:
            list_path = self._write_file_list(files)
            emit("clamav", f"ClamAV signature scan ({total} files)", 0, total)
            clam_hits, clam_errs = self.clam.scan_filelist(list_path)
            result.detections.extend(clam_hits)
            result.errors.extend(clam_errs)
            # Only distrust the scan when ClamAV is present but errored (a
            # partial/failed signature pass). ClamAV simply being absent is a
            # supported mode -- the heuristic/hash/YARA layer is authoritative
            # there -- so caching stays enabled.
            if self.clam.available and clam_errs:
                scan_complete = False
        finally:
            if list_path:
                try:
                    os.remove(list_path)
                except OSError:
                    pass

        # 3. Heuristic/hash/YARA layer, parallel across candidate files.
        #    Progress is throttled to ~30 events/sec so a huge drive can't flood
        #    the UI's event queue (the old per-file firehose caused the lag).
        if self.heur.enabled:
            done_n = 0
            last_emit = 0.0
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futures = {pool.submit(self.heur.scan_file, p, s): p
                           for p, s, _mt in files}
                for fut in as_completed(futures):
                    p = futures[fut]
                    done_n += 1
                    now = time.monotonic()
                    if progress and (now - last_emit >= 0.03 or done_n == total):
                        last_emit = now
                        emit("scanning", p, done_n, total)
                    try:
                        result.detections.extend(fut.result())
                    except Exception as exc:  # never let one file kill the scan
                        result.errors.append(f"{p}: {exc}")

        # 4. Quarantine confirmed infections. Dedup by path first so a file hit
        #    by two layers isn't "quarantined" twice (2nd attempt would find it
        #    already moved and record a misleading quarantined_to=None).
        if quarantine:
            done: dict[str, Optional[str]] = {}
            for det in result.infected:
                key = _norm(det.path)
                if key not in done:
                    if not det.sha256:
                        det.sha256 = sha256_of(det.path)
                    done[key] = self.quar.store(det.path, det.threat, det.sha256)
                det.quarantined_to = done[key]

        # 5. Cache files that came back clean so next scan skips them. Match
        #    detections by normalized path (ClamAV may echo a path in different
        #    case/slash form than we listed), and never cache when the signature
        #    scan was incomplete -- both would let malware be skipped later.
        flagged = {_norm(d.path) for d in result.detections}
        if scan_complete:
            for path, size, mtime in files:
                if _norm(path) not in flagged:
                    # reuse size/mtime from the walk -- no extra os.stat per file
                    self.cache.mark_clean(path, size, mtime)
            self.cache.save()

        result.finished = _now()
        return result

    def _walk(self, target: str, result: ScanResult):
        """Yield (path, size, mtime_ns) for every file under target, honoring
        the size cap. Uses os.scandir (faster than os.walk on big trees)."""
        if os.path.isfile(target):
            try:
                st = os.stat(target)
                if st.st_size <= self.max_bytes:
                    yield target, st.st_size, st.st_mtime_ns
                else:
                    result.files_skipped += 1
            except OSError:
                result.files_skipped += 1
            return
        stack = [target]
        while stack:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            st = entry.stat(follow_symlinks=False)
                            if st.st_size > self.max_bytes:
                                result.files_skipped += 1
                                continue
                            yield entry.path, st.st_size, st.st_mtime_ns
                        except OSError:
                            result.files_skipped += 1
            except OSError:
                continue

    @staticmethod
    def _write_file_list(files: List[tuple]) -> str:
        # UTF-8 is correct for ClamAV 1.x (the version we bundle) on every
        # platform. ASCII paths work with any build; any file ClamAV can't
        # reopen is still fully covered by the hash/YARA layer, which uses
        # Python's native path handling.
        fd, path = tempfile.mkstemp(prefix="usbscan_list_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for p, *_rest in files:
                fh.write(p + "\n")
        return path
