from pathlib import Path
import tempfile
import os
from sys_scan_agent.providers.local_qwen_provider import LocalQwenLLMProvider
from sys_scan_agent.config import MODEL_FILENAME


def _run_reassemble_with_shards(tmp_path, shard_names, chunk_data):
    # Set up fake package directory with shards
    model_dir = tmp_path / 'pkg'
    shards_dir = model_dir / 'shards'
    shards_dir.mkdir(parents=True, exist_ok=True)

    for name, data in zip(shard_names, chunk_data):
        p = shards_dir / name
        p.write_bytes(data)

    provider = LocalQwenLLMProvider(model_dir=str(model_dir))
    target = Path(model_dir) / MODEL_FILENAME
    return provider._reassemble_if_needed(target)


def test_reassemble_with_alphabetic_suffix(tmp_path, monkeypatch):
    # Simulate split default: suffixes 'aa', 'ab', 'ac'
    names = [f"{MODEL_FILENAME}.part.aa", f"{MODEL_FILENAME}.part.ab", f"{MODEL_FILENAME}.part.ac"]
    data = [b'A', b'B', b'C']
    cached = _run_reassemble_with_shards(tmp_path, names, data)
    assert cached.exists()
    assert cached.read_bytes() == b'ABC'


def test_reassemble_with_numeric_suffix(tmp_path, monkeypatch):
    names = [f"{MODEL_FILENAME}.part.001", f"{MODEL_FILENAME}.part.002", f"{MODEL_FILENAME}.part.010"]
    data = [b'1', b'2', b'10']
    cached = _run_reassemble_with_shards(tmp_path, names, data)
    assert cached.exists()
    assert cached.read_bytes() == b'12' + b'10'
