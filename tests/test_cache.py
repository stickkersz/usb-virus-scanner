"""ScanCache: clean-file memory + invalidation."""

import os

from scanner.cache import ScanCache


def test_mark_and_is_clean(tmp_path):
    c = ScanCache(str(tmp_path / "c.json"))
    assert not c.is_clean("/f", 10, 100)
    c.mark_clean("/f", 10, 100)
    assert c.is_clean("/f", 10, 100)


def test_invalidates_on_size_change(tmp_path):
    c = ScanCache(str(tmp_path / "c.json"))
    c.mark_clean("/f", 10, 100)
    assert not c.is_clean("/f", 11, 100)   # size changed
    assert not c.is_clean("/f", 10, 101)   # mtime changed


def test_persists_across_instances(tmp_path):
    p = str(tmp_path / "c.json")
    c = ScanCache(p)
    c.mark_clean("/f", 10, 100)
    c.save()
    c2 = ScanCache(p)
    assert c2.is_clean("/f", 10, 100)


def test_disabled_never_clean(tmp_path):
    c = ScanCache(str(tmp_path / "c.json"), enabled=False)
    c.mark_clean("/f", 10, 100)
    assert not c.is_clean("/f", 10, 100)


def test_corrupt_cache_does_not_crash(tmp_path):
    p = tmp_path / "c.json"
    p.write_text("{ not valid json ]")
    c = ScanCache(str(p))       # must not raise
    assert not c.is_clean("/f", 1, 1)


def test_forget(tmp_path):
    c = ScanCache(str(tmp_path / "c.json"))
    c.mark_clean("/f", 10, 100)
    c.forget("/f")
    assert not c.is_clean("/f", 10, 100)


def test_save_creates_missing_dir(tmp_path):
    p = tmp_path / "deep" / "nested" / "c.json"
    c = ScanCache(str(p))
    c.mark_clean("/f", 1, 1)
    c.save()
    assert os.path.isfile(p)
