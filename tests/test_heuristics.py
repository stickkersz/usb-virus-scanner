"""HeuristicEngine: USB heuristics + hash blocklist + YARA + deep-scan gating."""

import os

from scanner.heuristics import HeuristicEngine, sha256_of
from scanner.models import Severity


def _engine(signatures, **over):
    cfg = {
        "enabled": True,
        "hash_blocklist": str(signatures / "hash_blocklist.txt"),
        "yara_rules_dir": str(signatures / "yara"),
        "flag_autorun_inf": True, "flag_double_extension": True,
        "flag_ransomware": True, "flag_packed_exe": True,
        "deep_scan_all": False, "deep_scan_max_mb": 50,
    }
    cfg.update(over)
    return HeuristicEngine(cfg, base_dir=str(signatures.parent))


def test_sha256_of(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"abc")
    assert sha256_of(str(f)) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


def test_autorun_flagged(signatures, tmp_path):
    e = _engine(signatures)
    f = tmp_path / "autorun.inf"
    f.write_text("[autorun]\nopen=x.exe\n")
    dets = e.scan_file(str(f), f.stat().st_size)
    assert any("autorun" in d.threat.lower() for d in dets)


def test_double_extension_flagged(signatures, tmp_path):
    e = _engine(signatures)
    f = tmp_path / "invoice.pdf.exe"
    f.write_bytes(b"MZ")
    dets = e.scan_file(str(f), f.stat().st_size)
    assert any(d.severity == Severity.SUSPICIOUS and "double" in d.threat
               for d in dets)


def test_hash_blocklist_match(signatures, tmp_path, fake_usb):
    e = _engine(signatures)
    mal = fake_usb["dir"] / "mal.bin"
    dets = e.scan_file(str(mal), mal.stat().st_size)
    assert any(d.severity == Severity.INFECTED and d.source == "hash"
               for d in dets)


def test_yara_powershell_downloader(signatures, fake_usb):
    e = _engine(signatures)
    ps = fake_usb["dir"] / "dl.ps1"
    dets = e.scan_file(str(ps), ps.stat().st_size)
    assert any(d.source == "yara" for d in dets)


def test_clean_file_no_detections(signatures, tmp_path):
    e = _engine(signatures)
    f = tmp_path / "notes.txt"
    f.write_text("nothing to see")
    assert e.scan_file(str(f), f.stat().st_size) == []


def test_deep_scan_gating_skips_big_nonrisky(signatures, tmp_path, fake_usb):
    """A big non-risky file with a blocklisted hash is NOT read in fast mode."""
    e = _engine(signatures, deep_scan_max_mb=1)
    big = tmp_path / "big.dat"
    # same bytes as the blocklisted mal.bin, but 2MB > 1MB gate and .dat is safe
    payload = (fake_usb["dir"] / "mal.bin").read_bytes()
    big.write_bytes(payload + b"\0" * (2 * 1024 * 1024))
    # different hash anyway; the point is it must not even hash it -> no infected
    dets = e.scan_file(str(big), big.stat().st_size)
    assert all(d.source not in ("hash", "yara") for d in dets)


def test_deep_scan_all_reads_everything(signatures, tmp_path, fake_usb):
    e = _engine(signatures, deep_scan_all=True)
    mal = fake_usb["dir"] / "mal.bin"
    dets = e.scan_file(str(mal), mal.stat().st_size)
    assert any(d.source == "hash" for d in dets)


def test_disabled_engine_returns_empty(signatures, fake_usb):
    e = _engine(signatures, enabled=False)
    mal = fake_usb["dir"] / "mal.bin"
    assert e.scan_file(str(mal), mal.stat().st_size) == []


# ---- new threat-category coverage --------------------------------------
def test_ransomware_encrypted_extension(signatures, tmp_path):
    e = _engine(signatures)
    f = tmp_path / "budget.xlsx.locked"
    f.write_bytes(b"\x00\x01")
    dets = e.scan_file(str(f), f.stat().st_size)
    assert any("ransomware-encrypted" in d.threat for d in dets)


def test_ransom_note_filename(signatures, tmp_path):
    e = _engine(signatures)
    f = tmp_path / "HOW_TO_DECRYPT_readme.txt"
    f.write_text("pay to recover your files")
    dets = e.scan_file(str(f), f.stat().st_size)
    assert any("ransom note" in d.threat for d in dets)


def test_packed_executable_high_entropy(signatures, tmp_path):
    """A PE (MZ) file full of random bytes = packed/obfuscated -> suspicious."""
    e = _engine(signatures)
    f = tmp_path / "packed.exe"
    f.write_bytes(b"MZ" + os.urandom(4096))
    dets = e.scan_file(str(f), f.stat().st_size)
    assert any("packed" in d.threat for d in dets)


def test_low_entropy_exe_not_flagged_packed(signatures, tmp_path):
    e = _engine(signatures)
    f = tmp_path / "normal.exe"
    f.write_bytes(b"MZ" + b"\x00" * 4096)          # low entropy
    dets = e.scan_file(str(f), f.stat().st_size)
    assert not any("packed" in d.threat for d in dets)


def test_streaming_path_still_detects(signatures, fake_usb):
    """size=0 forces the large-file streaming branch (no in-memory buffer);
    hash blocklist + YARA must still fire identically to the buffered path."""
    e = _engine(signatures)
    mal = fake_usb["dir"] / "mal.bin"
    dets = e.scan_file(str(mal), size=0)           # 0 -> streaming branch
    assert any(d.source == "hash" for d in dets)
    ps = fake_usb["dir"] / "dl.ps1"
    assert any(d.source == "yara" for d in e.scan_file(str(ps), size=0))


def test_ransomware_yara_note(signatures, tmp_path):
    e = _engine(signatures)
    f = tmp_path / "help.txt"
    f.write_text("Your files have been encrypted. Pay bitcoin. onion evil@x")
    dets = e.scan_file(str(f), f.stat().st_size)
    assert any(d.source == "yara" and "Ransomware" in d.threat for d in dets)


# ---- false-positive reducers -------------------------------------------
import hashlib as _hashlib


def test_allowlisted_hash_suppresses_yara_and_entropy(signatures, tmp_path):
    # a packed PE that would normally trip the entropy heuristic
    import os as _os
    f = tmp_path / "trusted_tool.exe"
    payload = b"MZ" + _os.urandom(8192)
    f.write_bytes(payload)
    allow = tmp_path / "allow.txt"
    allow.write_text(_hashlib.sha256(payload).hexdigest() + "\n")
    e = _engine(signatures, hash_allowlist=str(allow), trust_signed=False)
    dets = e.scan_file(str(f), f.stat().st_size)
    assert not any("packed" in d.threat for d in dets)   # entropy suppressed
    assert not any(d.source == "yara" for d in dets)      # YARA suppressed


def test_blocklist_wins_over_allowlist(signatures, tmp_path, fake_usb):
    """A file that is somehow in both lists is treated as INFECTED (bad wins)."""
    mal = fake_usb["dir"] / "mal.bin"
    h = _hashlib.sha256(mal.read_bytes()).hexdigest()
    allow = tmp_path / "allow.txt"
    allow.write_text(h + "\n")                             # allowlist the bad hash
    e = _engine(signatures, hash_allowlist=str(allow))     # blocklist already has h
    dets = e.scan_file(str(mal), mal.stat().st_size)
    assert any(d.severity == Severity.INFECTED and d.source == "hash"
               for d in dets)


def test_trusted_path_suppresses_entropy(signatures, tmp_path):
    import os as _os
    f = tmp_path / "packed.exe"
    f.write_bytes(b"MZ" + _os.urandom(8192))
    e = _engine(signatures, trust_signed=False,
                trusted_paths=[str(tmp_path)])            # whole tmp dir trusted
    dets = e.scan_file(str(f), f.stat().st_size)
    assert not any("packed" in d.threat for d in dets)


def test_authenticode_false_off_windows(tmp_path):
    from scanner.heuristics import authenticode_valid
    import sys
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ")
    if sys.platform != "win32":
        assert authenticode_valid(str(f)) is False
