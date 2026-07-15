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
