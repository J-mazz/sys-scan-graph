from pathlib import Path
import os
from sys_scan_agent.config import get_model_path, MODEL_FILENAME


def test_get_model_path_finds_user_override(tmp_path, monkeypatch):
    # Create a fake HOME and model file under ~/.local/share/sys-scan-agent/models
    fake_home = tmp_path / "home"
    model_dir = fake_home / ".local" / "share" / "sys-scan-agent" / "models"
    model_dir.mkdir(parents=True)
    model_file = model_dir / MODEL_FILENAME
    model_file.write_text("dummy")

    monkeypatch.setenv("HOME", str(fake_home))

    p = get_model_path()
    assert p is not None
    assert p == model_file


def test_get_model_path_none_when_missing(monkeypatch):
    # Ensure no model exists in HOME and /usr/share
    monkeypatch.delenv("HOME", raising=False)
    # Also ensure /usr/share path doesn't exist in test environment by pointing to tmp
    # We can't remove /usr/share, so ensure HOME is empty and rely on absence in HOME
    p = get_model_path()
    assert p is None
