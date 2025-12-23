from __future__ import annotations
from pathlib import Path
import shutil
import logging
from typing import Iterable

logger = logging.getLogger(__name__)


def assemble_shards(shard_paths: Iterable[Path], out_path: Path, buffer_size: int = 4 * 1024 * 1024) -> Path:
    """Concatenate ordered shard files into out_path and return it.

    This function does not delete shards. It writes atomically by writing to a
    temporary file and renaming on success.

    For large shards the default buffer_size is 4 MiB to reduce syscall overhead
    and improve throughput compared with the default small buffer.
    """
    shard_list = list(shard_paths)
    if not shard_list:
        raise FileNotFoundError("No shard files provided")

    tmp = out_path.with_suffix(out_path.suffix + ".part_tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"Assembling {len(shard_list)} shards -> {out_path}")
    try:
        with open(tmp, 'wb') as w:
            for s in shard_list:
                with open(s, 'rb') as r:
                    # use a larger buffer to reduce system call overhead
                    shutil.copyfileobj(r, w, length=buffer_size)
        # atomic replace
        tmp.replace(out_path)
        logger.info(f"Assembled model -> {out_path}")
        return out_path
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise


def find_shards_in_dir(dirpath: Path) -> list[Path]:
    shards_dir = Path(dirpath)
    if not shards_dir.exists():
        return []
    return sorted(shards_dir.glob('*.part.*'))


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Reassemble GGUF shards into a single model file')
    parser.add_argument('--shards-dir', type=Path, required=True, help='Directory containing shards')
    parser.add_argument('--out', type=Path, required=True, help='Output GGUF path')
    args = parser.parse_args()

    shards = find_shards_in_dir(args.shards_dir)
    if not shards:
        print('No shards found')
        raise SystemExit(2)
    assemble_shards(shards, args.out)
    print(f'Assembled -> {args.out}')


if __name__ == '__main__':
    main()
