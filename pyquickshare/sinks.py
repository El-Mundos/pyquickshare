"""Destinations for incoming payload data.

Payloads used to be accumulated in a single :class:`io.BytesIO` per payload and
handed over only once complete. That made peak memory scale with the size of the
transfer, and left no observable state between "nothing" and "done", so progress
could not be reported at all.

A sink decouples *where* payload bytes go from the transport loop that reads
them. Control frames, text and Wi-Fi credentials are small and are parsed as a
whole, so they keep using :class:`MemorySink`. Files stream straight to disk via
:class:`FileSink`, which keeps memory flat regardless of file size.
"""

from __future__ import annotations

import asyncio
import io
import os
from logging import getLogger
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pathlib import Path

logger = getLogger(__name__)

__all__ = (
    "FileSink",
    "MemorySink",
    "PayloadSink",
    "safe_file_name",
)


@runtime_checkable
class PayloadSink(Protocol):
    """Somewhere the bytes of a single payload can be written.

    Chunks carry an explicit offset and are not guaranteed to arrive in order,
    so writes are positional rather than sequential.
    """

    received: int
    """Bytes written so far, for progress reporting."""

    async def write(self, offset: int, data: bytes) -> None:
        """Write ``data`` at ``offset``."""
        ...

    async def finish(self) -> bytes | None:
        """Close the sink. Returns the payload for in-memory sinks, else ``None``."""
        ...

    async def abort(self) -> None:
        """Close the sink, discarding a partially written payload."""
        ...


class MemorySink:
    """Accumulates a payload in memory. For small payloads parsed as a whole."""

    def __init__(self) -> None:
        self._buf = io.BytesIO()
        self.received = 0

    async def write(self, offset: int, data: bytes) -> None:
        self._buf.seek(offset)
        self._buf.write(data)
        self.received += len(data)

    async def finish(self) -> bytes:
        self._buf.seek(0)
        payload = self._buf.read()
        self._buf.close()
        return payload

    async def abort(self) -> None:
        self._buf.close()


class FileSink:
    """Streams a payload to disk, keeping memory flat.

    Writes go to a sibling ``.part`` file and are moved into place only once the
    payload completes, so an interrupted transfer can never be mistaken for a
    finished one. Positional :func:`os.pwrite` avoids a seek/write race and
    handles out-of-order chunks; it runs in a worker thread so a slow disk cannot
    stall the event loop.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.partial_path = path.with_name(path.name + ".part")
        self.received = 0
        self.partial_path.parent.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(self.partial_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

    async def write(self, offset: int, data: bytes) -> None:
        await asyncio.to_thread(os.pwrite, self._fd, data, offset)
        self.received += len(data)

    async def finish(self) -> None:
        await asyncio.to_thread(os.close, self._fd)
        self.partial_path.replace(self.path)
        logger.debug("Payload complete, moved into place: %s", self.path)

    async def abort(self) -> None:
        await asyncio.to_thread(os.close, self._fd)
        await _handle_partial_file(self.partial_path, self.received)


def safe_file_name(name: str) -> str:
    """Reduce a remote-supplied file name to a single, safe path component.

    ``file_name`` arrives from the sending device and was previously interpolated
    straight into a path, so a name like ``../../.bashrc`` would escape the
    download directory. Everything but the final component is discarded and
    traversal is neutralised.
    """
    # Both separators, because the sender may not be POSIX.
    candidate = name.replace("\\", "/").rsplit("/", maxsplit=1)[-1]
    candidate = candidate.strip().lstrip(".")

    if not candidate or candidate in {".", ".."}:
        return "unnamed"

    return candidate


def unique_path(directory: Path, name: str) -> Path:
    """Return a path under ``directory`` that does not collide with an existing file.

    Quick Share sends whatever the file is called on the other device, so
    repeated sends of ``IMG_0001.jpg`` would otherwise overwrite each other.
    """
    path = directory / name
    if not path.exists():
        return path

    stem, suffix = path.stem, path.suffix
    for counter in range(1, 10_000):
        candidate = directory / f"{stem} ({counter}){suffix}"
        if not candidate.exists():
            return candidate

    msg = f"could not find a free filename for {name!r} in {directory}"
    raise RuntimeError(msg)


async def _handle_partial_file(partial_path: Path, received: int) -> None:
    """Discard a partially written file after an interrupted transfer.

    Keeping the remnant would only pay off if a later transfer could resume from
    it, and the Quick Share protocol has no way to express that: ``FileMetadata``
    carries ``name``, ``type``, ``payload_id``, ``size``, ``mime_type``, ``id``,
    ``parent_folder`` and ``attachment_hash``, but **no start offset**, and there
    is no resume or continuation frame anywhere in the wire format. A sending
    phone therefore always retransmits from byte zero. Retaining 4 GB of a failed
    5 GB transfer would consume disk that nothing can ever reclaim.

    ``attachment_hash`` is documented as "a stable identifier for the attachment,
    used for receiver to identify same attachment from different transfers", so
    it is the hook to build on if we ever implement resume between two instances
    we control on both ends. That needs an offset negotiated outside the standard
    protocol, so it is deliberately out of scope here.

    Runs on the failure path, so it must not raise: a cleanup error would mask
    the original transfer error, which is the more useful one.
    """
    try:
        partial_path.unlink(missing_ok=True)
        logger.debug("Discarded %d incomplete bytes at %s", received, partial_path)
    except OSError:
        logger.warning("Could not remove partial file %s", partial_path, exc_info=True)
