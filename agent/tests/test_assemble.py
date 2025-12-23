from pathlib import Path
import tempfile
from sys_scan_agent.models.assemble import assemble_shards


def test_assemble_shards_creates_file():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        # Create three small shard files
        parts = []
        for i, data in enumerate([b'hello', b' ', b'world']):
            p = d / f'shard.{i}.part'
            p.write_bytes(data)
            parts.append(p)
        out = d / 'model.gguf'
        assembled = assemble_shards(parts, out)
        assert assembled.exists()
        assert assembled.read_bytes() == b'hello world'
