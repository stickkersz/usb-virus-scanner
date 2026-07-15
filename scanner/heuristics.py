"""Heuristic + hash + YARA detection layer.

Runs alongside ClamAV. Catches USB-specific tricks (autorun.inf, double
extensions, LNK droppers) and matches against a company hash blocklist and
optional YARA rules — useful for zero-days ClamAV has no signature for yet.
"""

from __future__ import annotations

import hashlib
import math
import os
from typing import List, Optional, Set

from .models import Detection, Severity

try:
    import yara  # type: ignore
    _HAS_YARA = True
except Exception:  # pragma: no cover - optional dependency
    yara = None
    _HAS_YARA = False


# Built-in fallback so double-extension detection and the risky-file deep-scan
# gate still work even if a partial config omits `suspicious_extensions`.
DEFAULT_SUSPICIOUS_EXT = frozenset({
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".ps1", ".lnk", ".pif", ".com", ".hta", ".jar",
})

# File extensions overwhelmingly used by ransomware to mark encrypted files.
RANSOM_EXTENSIONS = frozenset({
    ".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".locky", ".cerber",
    ".wannacry", ".wncry", ".wcry", ".zepto", ".cryptolocker", ".cryptowall",
    ".ryuk", ".conti", ".lockbit", ".makop", ".phobos", ".djvu", ".stop",
    ".basta", ".akira", ".royal", ".hive", ".medusa", ".abcd", ".pay",
})

# Substrings/full names of typical ransom-note files dropped on the drive.
RANSOM_NOTE_SUBSTRINGS = (
    "readme", "decrypt", "how_to", "how to", "recover", "restore",
    "unlock", "your files", "ransom", "@", "_help_", "important",
)
RANSOM_NOTE_KEYWORDS = ("decrypt", "recover", "restore", "unlock", "ransom")

# High Shannon entropy in an executable strongly implies packing/obfuscation,
# the norm for fresh trojan/malware variants that evade signatures.
PACKED_ENTROPY_THRESHOLD = 7.2
_ENTROPY_SAMPLE_BYTES = 256 * 1024
# Files at or below this are read once into memory and shared across the hash,
# YARA and entropy checks. Larger files stream instead, so we never OOM.
_IN_MEMORY_CAP = 64 * 1024 * 1024


def shannon_entropy(data: bytes) -> float:
    """Bits-per-byte entropy (0-8). ~8 = random/encrypted/packed."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def head_sample(path: str, n: int = _ENTROPY_SAMPLE_BYTES) -> Optional[bytes]:
    """Read up to n leading bytes once (for magic + entropy checks)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except (OSError, PermissionError):
        return None


def sha256_of(path: str, chunk: int = 1 << 20) -> Optional[str]:
    """Streamed SHA-256 so multi-GB files don't blow up memory."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(chunk), b""):
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


class HeuristicEngine:
    def __init__(self, cfg: dict, base_dir: str):
        self.cfg = cfg
        self.base_dir = base_dir
        self.enabled = cfg.get("enabled", True)
        configured_ext = cfg.get("suspicious_extensions")
        self.suspicious_ext: Set[str] = (
            {e.lower() for e in configured_ext} if configured_ext
            else set(DEFAULT_SUSPICIOUS_EXT)
        )
        self.flag_autorun = cfg.get("flag_autorun_inf", True)
        self.flag_double = cfg.get("flag_double_extension", True)
        # Behavior-based layers for zero-day / novel malware categories.
        self.flag_ransomware = cfg.get("flag_ransomware", True)
        self.flag_packed_exe = cfg.get("flag_packed_exe", True)
        # Fast-mode gating: only read+hash+YARA files that are either a risky
        # type or small. Skips the expensive content read on big media/data
        # files that are extremely unlikely to be executable malware.
        self.deep_scan_all = cfg.get("deep_scan_all", False)
        self.deep_scan_max_bytes = int(cfg.get("deep_scan_max_mb", 50)) * 1024 * 1024
        self._hashes: Set[str] = self._load_hashes(cfg.get("hash_blocklist"))
        self._yara_rules = self._load_yara(cfg.get("yara_rules_dir"))

    # ---- loading -------------------------------------------------------
    def _resolve(self, rel: Optional[str]) -> Optional[str]:
        if not rel:
            return None
        return rel if os.path.isabs(rel) else os.path.join(self.base_dir, rel)

    def _load_hashes(self, rel: Optional[str]) -> Set[str]:
        path = self._resolve(rel)
        hashes: Set[str] = set()
        if not path or not os.path.isfile(path):
            return hashes
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                token = line.split("#", 1)[0].strip().lower()
                if len(token) == 64 and all(c in "0123456789abcdef" for c in token):
                    hashes.add(token)
        return hashes

    def _load_yara(self, rel: Optional[str]):
        if not _HAS_YARA:
            return None
        path = self._resolve(rel)
        if not path or not os.path.isdir(path):
            return None
        filepaths = {}
        for name in os.listdir(path):
            if name.lower().endswith((".yar", ".yara")):
                filepaths[name] = os.path.join(path, name)
        if not filepaths:
            return None
        try:
            return yara.compile(filepaths=filepaths)
        except yara.Error:
            return None

    def _needs_deep_scan(self, ext: str, size: int) -> bool:
        """Whether to read file bytes for hash/YARA. Risky types always; other
        files only if small enough (fast mode) or if deep_scan_all is set."""
        if self.deep_scan_all:
            return True
        if ext in self.suspicious_ext:
            return True
        return size <= self.deep_scan_max_bytes

    # ---- scanning ------------------------------------------------------
    def scan_file(self, path: str, size: int = 0) -> List[Detection]:
        if not self.enabled:
            return []
        out: List[Detection] = []
        name = os.path.basename(path)
        lower = name.lower()
        ext = os.path.splitext(lower)[1]

        # autorun.inf on removable media = classic worm autostart vector
        if self.flag_autorun and lower == "autorun.inf":
            out.append(Detection(path, Severity.SUSPICIOUS,
                                 "autorun.inf present (USB autostart vector)",
                                 "heuristic"))

        # double extension e.g. invoice.pdf.exe
        if self.flag_double and ext in self.suspicious_ext:
            stem = os.path.splitext(lower)[0]
            inner_ext = os.path.splitext(stem)[1]
            benign = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg",
                      ".png", ".txt", ".zip", ".rar"}
            if inner_ext in benign:
                out.append(Detection(path, Severity.SUSPICIOUS,
                                     f"double extension '{inner_ext}{ext}'",
                                     "heuristic"))

        # ransomware indicators (name-based, no I/O): encrypted-file extensions
        # and dropped ransom notes. Early warning that a drive was hit.
        if self.flag_ransomware:
            if ext in RANSOM_EXTENSIONS:
                out.append(Detection(path, Severity.SUSPICIOUS,
                                     f"ransomware-encrypted file extension '{ext}'",
                                     "heuristic"))
            elif ext in (".txt", ".html", ".hta") and any(
                    k in lower for k in RANSOM_NOTE_KEYWORDS) and any(
                    s in lower for s in RANSOM_NOTE_SUBSTRINGS):
                out.append(Detection(path, Severity.SUSPICIOUS,
                                     "possible ransom note", "heuristic"))

        # Deep layers need the file bytes -- the expensive part. Skip on big
        # non-risky files so slow disks aren't hammered reading movies/backups.
        wants_deep = self._hashes or self._yara_rules or self.flag_packed_exe
        if not (wants_deep and self._needs_deep_scan(ext, size)):
            return out

        # Read the file ONCE and feed all three deep checks (hash, YARA, entropy)
        # from the same buffer -- avoids re-reading the file 2-3x on slow disks.
        # Files above the in-memory cap fall back to streaming so we never OOM.
        digest = None
        buf = None
        if size and size <= _IN_MEMORY_CAP:
            buf = head_sample(path, size)          # whole small file, one read
        if buf is not None:
            digest = hashlib.sha256(buf).hexdigest() if self._hashes else None
            yara_target = {"data": buf}
            head = buf[:_ENTROPY_SAMPLE_BYTES]
        else:                                       # large file: stream, don't buffer
            digest = sha256_of(path) if self._hashes else None
            yara_target = {"filepath": path}
            head = head_sample(path)

        if digest and digest in self._hashes:
            out.append(Detection(path, Severity.INFECTED,
                                 "matched company hash blocklist",
                                 "hash", sha256=digest))

        if self._yara_rules is not None:
            try:
                for m in self._yara_rules.match(**yara_target):
                    out.append(Detection(path, Severity.INFECTED,
                                         f"YARA:{m.rule}", "yara", sha256=digest))
            except Exception:
                pass

        # Packed/obfuscated executable: high entropy in a PE (MZ) file. Catches
        # fresh trojan variants that no signature covers yet.
        if self.flag_packed_exe and head and head[:2] == b"MZ" and \
                shannon_entropy(head) >= PACKED_ENTROPY_THRESHOLD:
            out.append(Detection(path, Severity.SUSPICIOUS,
                                 "packed/high-entropy executable "
                                 "(possible obfuscated malware)", "heuristic"))

        return out
