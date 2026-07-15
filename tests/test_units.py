"""Config, models, reporter, watcher, paths."""

import os

from scanner.config import Config, DEFAULTS
from scanner.models import Detection, ScanResult, Severity
from scanner import paths, watcher, reporter


# ---- config -------------------------------------------------------------
def test_config_defaults_when_missing():
    c = Config.load(None)
    assert c["scanner"]["prefer_daemon"] is True
    assert c.get("heuristics", "deep_scan_max_mb") == 50


def test_config_merge_overrides(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("scanner:\n  workers: 3\n")
    c = Config.load(str(p))
    assert c["scanner"]["workers"] == 3          # overridden
    assert c["scanner"]["prefer_daemon"] is True  # default kept


def test_config_has_database_path_default():
    assert "database_path" in DEFAULTS["scanner"]


# ---- models -------------------------------------------------------------
def test_scanresult_filters():
    r = ScanResult(target="t", started="s")
    r.detections = [
        Detection("a", Severity.INFECTED, "x", "hash"),
        Detection("b", Severity.SUSPICIOUS, "y", "heuristic"),
        Detection("c", Severity.INFECTED, "z", "yara"),
    ]
    assert len(r.infected) == 2
    assert len(r.suspicious) == 1
    assert not r.clean


def test_scanresult_clean():
    r = ScanResult(target="t", started="s")
    assert r.clean
    assert r.to_dict()["target"] == "t"


def test_detection_to_dict():
    d = Detection("p", Severity.INFECTED, "sig", "clamav", sha256="ab")
    assert d.to_dict()["severity"] == "infected"


# ---- reporter -----------------------------------------------------------
def test_reporter_writes_log_and_report(tmp_path):
    log = reporter.setup_logging({"path": str(tmp_path / "logs"), "jsonl": True})
    r = ScanResult(target="t", started="s", finished="f", files_scanned=3)
    r.detections = [Detection("p", Severity.INFECTED, "sig", "hash")]
    reporter.log_result(log, r)
    assert (tmp_path / "logs" / "events.jsonl").exists()
    rep = reporter.write_report({"path": str(tmp_path / "rep")}, r)
    assert os.path.isfile(rep)
    assert "THREATS FOUND" in open(rep).read()


# ---- watcher ------------------------------------------------------------
def test_list_removable_returns_list():
    assert isinstance(watcher.list_removable(), list)


def test_drivewatcher_fires_on_new(monkeypatch):
    seen = []
    fake = {"drives": ["A"]}
    monkeypatch.setattr(watcher, "list_removable", lambda *a, **k: fake["drives"])
    w = watcher.DriveWatcher(lambda root: seen.append(root), poll_interval=0)
    fake["drives"] = ["A", "B"]
    monkeypatch.setattr(os.path, "isdir", lambda p: True)
    monkeypatch.setattr(watcher.time, "sleep", lambda s: None)
    w._tick()
    assert "B" in seen and "A" not in seen       # only the NEW drive fires


# ---- paths --------------------------------------------------------------
def test_app_base_dir_source_run():
    base = paths.app_base_dir()
    assert os.path.isdir(base)
    assert os.path.isfile(os.path.join(base, "cli.py"))
