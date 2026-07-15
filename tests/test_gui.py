"""GUI event-loop behavior (headless). Skips where Tk has no display."""

import pytest

from scanner.models import ProgressEvent


def _app(monkeypatch, config):
    import gui
    # Force the GUI to use the temp-dir config (never touch C:\ProgramData).
    monkeypatch.setattr(gui.Config, "load", staticmethod(lambda p: config))
    try:
        app = gui.ScannerGUI()
    except Exception as exc:                     # no display in CI
        pytest.skip(f"Tk unavailable: {exc}")
    return app


def test_progress_events_are_coalesced(monkeypatch, config):
    """The whole point of the anti-lag fix: many queued progress events collapse
    into ONE render per drain (the last one wins)."""
    app = _app(monkeypatch, config)
    try:
        renders = []
        monkeypatch.setattr(app, "_render_progress", lambda ev: renders.append(ev))
        for i in range(500):
            app._events.put(("progress", ProgressEvent("scanning", f"f{i}", i, 500)))
        app._drain_events()
        assert len(renders) == 1                 # 500 events -> 1 redraw
        assert renders[0].current == 499         # latest event kept
    finally:
        app.destroy()


def test_render_progress_switches_bar_modes(monkeypatch, config):
    app = _app(monkeypatch, config)
    try:
        app._render_progress(ProgressEvent("indexing", "Indexing"))
        assert app._bar_mode == "indeterminate"
        app._render_progress(ProgressEvent("scanning", "f", 5, 10))
        assert app._bar_mode == "determinate"
        assert "50%" in app.count_var.get()
    finally:
        app.destroy()


def test_truncate_middle():
    import gui
    assert gui._truncate_middle("short") == "short"
    out = gui._truncate_middle("x" * 200, width=40)
    assert len(out) <= 40 and "..." in out
