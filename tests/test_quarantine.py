"""Quarantine: store/neutralize/restore + index integrity."""

import os

from scanner.quarantine import Quarantine


def test_store_removes_original_and_neutralizes(tmp_path):
    src = tmp_path / "mal.exe"
    payload = b"MZ" + b"\x90" * 100
    src.write_bytes(payload)
    q = Quarantine({"path": str(tmp_path / "q"), "neutralize": True})
    dest = q.store(str(src), "EICAR-Test")
    assert dest and os.path.isfile(dest)
    assert not src.exists()                       # moved off drive
    assert open(dest, "rb").read() != payload     # neutralized (not runnable)


def test_restore_is_byte_exact(tmp_path):
    src = tmp_path / "mal.bin"
    payload = os.urandom(5000)
    src.write_bytes(payload)
    q = Quarantine({"path": str(tmp_path / "q"), "neutralize": True})
    q.store(str(src), "threat")
    qid = q.list_entries()[0]["id"]
    out = tmp_path / "restored.bin"
    restored = q.restore(qid, to=str(out))
    assert restored == str(out)
    assert out.read_bytes() == payload            # perfect round-trip


def test_list_entries_reflects_state(tmp_path):
    q = Quarantine({"path": str(tmp_path / "q"), "neutralize": True})
    for i in range(3):
        f = tmp_path / f"m{i}.bin"
        f.write_bytes(b"x" * (i + 1))
        q.store(str(f), f"t{i}")
    assert len(q.list_entries()) == 3
    qid = q.list_entries()[0]["id"]
    q.restore(qid, to=str(tmp_path / "r.bin"))
    assert len(q.list_entries()) == 2             # restored one drops out


def test_restore_unknown_id_returns_none(tmp_path):
    q = Quarantine({"path": str(tmp_path / "q"), "neutralize": True})
    assert q.restore("does-not-exist") is None


def test_store_missing_file_returns_none(tmp_path):
    q = Quarantine({"path": str(tmp_path / "q"), "neutralize": True})
    assert q.store(str(tmp_path / "nope.bin"), "t") is None


def test_non_neutralize_moves_file(tmp_path):
    src = tmp_path / "m.bin"
    payload = b"hello-world"
    src.write_bytes(payload)
    q = Quarantine({"path": str(tmp_path / "q"), "neutralize": False})
    dest = q.store(str(src), "t")
    assert not src.exists()
    assert open(dest, "rb").read() == payload     # plain move, not XORed
