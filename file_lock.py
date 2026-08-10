"""Small cross-platform advisory file lock for append-only local stores."""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def locked_file(lock_path: str | Path) -> Iterator[None]:
    raw = str(lock_path)
    if not raw.strip() or "\x00" in raw or raw.lower().startswith("file:"):
        raise ValueError("lock path must be a non-empty local filesystem path")
    path = Path(lock_path).expanduser().resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+")
    try:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
