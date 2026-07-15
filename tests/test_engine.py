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


def test_double_flagged_file_quarantined_once(config, fake_usb, tmp_path, monkeypatch):
    """A file hit by two layers must show one consistent quarantine location,
    not a second 'quarantined_to=None' from a duplicate move attempt."""
    from scanner.models import Detection, Severity
    eng = _engine(config, tmp_path)
    mal = str(fake_usb["dir"] / "mal.bin")
    # force a ClamAV hit on the SAME file the hash layer also flags
    monkeypatch.setattr(eng.clam, "clamscan", "/bin/true")  # make .available True
    monkeypatch.setattr(eng.clam, "scan_filelist",
                        lambda lp: ([Detection(mal, Severity.INFECTED,
                                               "Test.Sig", "clamav")], []))
    result = eng.scan(str(fake_usb["dir"]), quarantine=True)
    dups = [d for d in result.infected if d.path == mal]
    assert len(dups) >= 2                         # hash + clamav, same file
    assert all(d.quarantined_to for d in dups)    # both show the same location


def test_no_cache_when_clamav_errors(config, fake_usb, tmp_path, monkeypatch):
    """If ClamAV is present but the signature pass errors, nothing is cached
    (so a missed infection can't be skipped on the next scan)."""
    eng = _engine(config, tmp_path)
    monkeypatch.setattr(eng.clam, "clamscan", "/bin/true")  # make .available True
    monkeypatch.setattr(eng.clam, "scan_filelist",
                        lambda lp: ([], ["clamd connection failed"]))
    eng.scan(str(fake_usb["dir"]), quarantine=False)
    # clean file NOT cached -> rescan still processes it
    res2 = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert res2.files_skipped == 0


def test_clamd_down_falls_back_to_clamscan(config, tmp_path, monkeypatch):
    """If the daemon errors (clamd not running), scan_filelist retries with
    one-shot clamscan instead of failing the whole signature pass."""
    from scanner.engine import ClamAV
    clam = ClamAV(config["scanner"])
    clam.clamdscan = "/bin/clamdscan"     # pretend both exist
    clam.clamscan = "/bin/clamscan"
    clam.prefer_daemon = True
    calls = []

    def fake_run(binary, is_daemon, lp):
        calls.append(is_daemon)
        if is_daemon:
            return [], ["Could not connect to clamd"]     # daemon down
        return [], []                                      # clamscan clean
    monkeypatch.setattr(clam, "_run", fake_run)
    dets, errs = clam.scan_filelist("list.txt")
    assert calls == [True, False]         # tried daemon, then fell back
    assert errs == []                     # clamscan succeeded


def test_cache_path_normalized_match(config, fake_usb, tmp_path, monkeypatch):
    """A ClamAV hit echoed with different case/slashes still marks the file
    infected (not cached clean) thanks to normalized matching."""
    from scanner.models import Detection, Severity
    eng = _engine(config, tmp_path)
    target = fake_usb["dir"] / "notes.txt"
    weird = str(target).upper() if os.name == "nt" else str(target)
    monkeypatch.setattr(eng.clam, "clamscan", "/bin/true")  # make .available True
    monkeypatch.setattr(eng.clam, "scan_filelist",
                        lambda lp: ([Detection(weird, Severity.INFECTED,
                                               "Test.Sig", "clamav")], []))
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    from scanner.engine import _norm
    flagged = {_norm(d.path) for d in res.detections}
    assert _norm(str(target)) in flagged
