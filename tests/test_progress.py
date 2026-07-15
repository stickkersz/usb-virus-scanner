"""ProgressEvent emission from the engine + heuristic entropy math."""

import os

from scanner.engine import ScanEngine
from scanner.heuristics import shannon_entropy
from scanner.models import ProgressEvent


def test_progress_events_have_phases_and_counts(config, fake_usb, tmp_path):
    eng = ScanEngine(config, base_dir=str(tmp_path))
    events = []
    eng.scan(str(fake_usb["dir"]), progress=events.append, quarantine=False)

    assert all(isinstance(e, ProgressEvent) for e in events)
    phases = {e.phase for e in events}
    assert "indexing" in phases
    # heuristic phase reports monotonic counts bounded by total
    scanning = [e for e in events if e.phase == "scanning"]
    if scanning:                              # present unless everything cached
        total = scanning[-1].total
        assert total == 5                     # 5 files in fake_usb
        assert all(0 < e.current <= e.total for e in scanning)
        assert scanning[-1].current == total  # final event reports completion


def test_progress_none_callback_is_safe(config, fake_usb, tmp_path):
    eng = ScanEngine(config, base_dir=str(tmp_path))
    # must not raise when no progress callback is supplied
    res = eng.scan(str(fake_usb["dir"]), progress=None, quarantine=False)
    assert res.files_scanned == 5


def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 4096) < 0.01        # uniform -> ~0
    assert shannon_entropy(os.urandom(65536)) > 7.5      # random -> ~8


def test_streaming_branch_by_cap(signatures, fake_usb, monkeypatch):
    """Force the >cap streaming branch on a small file by lowering the in-memory
    cap; hash detection must still fire identically to the buffered branch."""
    import scanner.heuristics as H
    monkeypatch.setattr(H, "_IN_MEMORY_CAP", 4)          # 4 bytes -> everything streams
    cfg = {"enabled": True,
           "hash_blocklist": str(signatures / "hash_blocklist.txt"),
           "yara_rules_dir": str(signatures / "yara"),
           "deep_scan_all": True}
    e = H.HeuristicEngine(cfg, base_dir=str(signatures.parent))
    mal = fake_usb["dir"] / "mal.bin"
    dets = e.scan_file(str(mal), mal.stat().st_size)     # size > 4 -> streaming
    assert any(d.source == "hash" for d in dets)
