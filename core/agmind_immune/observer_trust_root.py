"""Independent immutable observer trust-root loading for Core."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from agmind_immune.contracts import ObserverTrustRootV1, decode_strict

MAX_TRUST_ROOT_BYTES = 4_096


def load_observer_trust_root(path: Path) -> ObserverTrustRootV1:
    """Open and strictly validate one root-owned, regular, single-link pin."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError("observer trust-root path is unsafe") from error
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_nlink != 1
            or file_stat.st_uid != 0
            or file_stat.st_size < 1
            or file_stat.st_size > MAX_TRUST_ROOT_BYTES
        ):
            raise ValueError("observer trust root must be a root-owned single-link regular file")
        chunks: list[bytes] = []
        remaining = MAX_TRUST_ROOT_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_TRUST_ROOT_BYTES:
            raise ValueError("observer trust root exceeds 4 KiB")
    finally:
        os.close(descriptor)
    return decode_strict(raw, ObserverTrustRootV1, MAX_TRUST_ROOT_BYTES)
