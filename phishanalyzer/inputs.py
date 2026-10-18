"""Find messages to analyse: .eml files, directories of them, and mbox files. Read-only."""
from __future__ import annotations

import os
from typing import Iterator, List, Tuple

from .mime import iter_mbox


def is_mbox(path: str) -> bool:
    if path.lower().endswith(".mbox"):
        return True
    try:
        with open(path, "rb") as fh:
            return fh.read(5) == b"From "
    except OSError:
        return False


def collect(paths: List[str]) -> List[Tuple[str, bytes]]:
    """Return [(label, raw bytes)] in a stable order. Raises FileNotFoundError for a missing path."""
    out: List[Tuple[str, bytes]] = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs.sort()
                for f in sorted(files):
                    if f.lower().endswith(".eml"):
                        out.append(_read_eml(os.path.join(root, f)))
                    elif f.lower().endswith(".mbox"):
                        out.extend(iter_mbox(os.path.join(root, f)))
        elif os.path.isfile(p):
            if is_mbox(p):
                out.extend(iter_mbox(p))
            else:
                out.append(_read_eml(p))
        else:
            raise FileNotFoundError(p)
    return out


def _read_eml(path: str) -> Tuple[str, bytes]:
    with open(path, "rb") as fh:
        data = fh.read()
    stem = os.path.splitext(os.path.basename(path))[0]
    return stem, data
