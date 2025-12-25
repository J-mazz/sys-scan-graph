from pathlib import Path
import tempfile
import os
from sys_scan_agent.providers.local_qwen_provider import LocalQwenLLMProvider
from sys_scan_agent.config import MODEL_FILENAME, get_model_path


def test_get_model_path_env_override(tmp_path, monkeypatch):
    fake_file = tmp_path / MODEL_FILENAME
    fake_file.write_text('dummy')
    monkeypatch.setenv('AGENT_LOCAL_QWEN_MODEL_FILE', str(fake_file))

    p = get_model_path()
    assert p == fake_file


def test_reassemble_if_needed_creates_cached_model(tmp_path, monkeypatch):
    # Use a fake HOME to redirect cache
    monkeypatch.setenv('HOME', str(tmp_path))

    model_dir = tmp_path / 'pkg'
    shards_dir = model_dir / 'shards'
    shards_dir.mkdir(parents=True)

    # Create shards named like: <MODEL_FILENAME>.part.0, .part.1
    parts = []
    data_parts = [b'abc', b'def', b'ghi']
    for i, d in enumerate(data_parts):
        p = shards_dir / f"{MODEL_FILENAME}.part.{i:03d}"
        p.write_bytes(d)
        parts.append(p)

    from pathlib import Path
    provider = LocalQwenLLMProvider(model_dir=str(model_dir))
    target = Path(model_dir) / MODEL_FILENAME

    cached = provider._reassemble_if_needed(target)
    assert cached.exists()
    assert cached.read_bytes() == b''.join(data_parts)

    # Calling again should hit the cache fast (no exception)
    cached2 = provider._reassemble_if_needed(target)
    assert cached2 == cached
