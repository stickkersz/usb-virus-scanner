"""ScanEngine end-to-end (heuristic/hash/YARA layers; ClamAV absent in CI)."""

import os

from scanner.engine import ScanEngine, _auto_workers
from scanner.models import Severity


def _engine(config, tmp_path):
    return ScanEngine(config, base_dir=str(tmp_path))


def test_auto_workers():
    assert _auto_workers(4) == 4
    assert 2 <= _auto_workers("auto") <= 8
    assert 2 <= _auto_workers(0) <= 8      # invalid -> auto


def test_scan_detects_threats(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert not res.clean
    assert len(res.infected) >= 2          # hash + yara at least
    assert len(res.suspicious) >= 1        # autorun / double-ext
    threats = {d.source for d in res.detections}
    assert "hash" in threats and "yara" in threats and "heuristic" in threats


def test_report_only_leaves_files(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert (fake_usb["dir"] / "mal.bin").exists()      # untouched


def test_quarantine_removes_infected(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=True)
    assert not (fake_usb["dir"] / "mal.bin").exists()  # moved to quarantine
    assert (fake_usb["dir"] / "notes.txt").exists()    # clean file kept
    assert all(d.quarantined_to for d in res.infected)


def test_cache_skips_unchanged_on_rescan(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    eng.scan(str(fake_usb["dir"]), quarantine=False)
    res2 = eng.scan(str(fake_usb["dir"]), quarantine=False)
    # clean files (notes.txt) cached -> skipped on 2nd pass
    assert res2.files_skipped >= 1


def test_nonexistent_target(config, tmp_path):
    eng = _engine(config, tmp_path)
    res = eng.scan(str(tmp_path / "ghost"))
    assert res.errors and res.clean


def test_size_cap_skips_large(config, fake_usb, tmp_path):
    config.data["scanner"]["max_file_size_mb"] = 0     # everything too big
    eng = _engine(config, tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert res.files_scanned == 0
    assert res.files_skipped >= 4


def test_scan_single_file(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    res = eng.scan(str(fake_usb["dir"] / "dl.ps1"), quarantine=False)
    assert res.files_scanned == 1
    assert any(d.source == "yara" for d in res.detections)
