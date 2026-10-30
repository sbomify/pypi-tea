"""Read selected members out of a remote wheel with HTTP range requests.

Only the ZIP central directory and the wanted members cross the wire. The
stdlib `zipfile` does the parsing against a sparse in-memory view of the
remote file: whenever it reads bytes we haven't fetched, the view raises
`_MissingRange`, we fetch that range, and parsing restarts. Everything runs
on the event loop — no thread pool, no blocking HTTP client.
"""

import io
import tempfile
import zipfile
from collections.abc import Callable

import httpx

TAIL_BYTES = 64 * 1024
# Fallback for hosts that ignore Range: download whole wheels up to this size.
MAX_FULL_DOWNLOAD_BYTES = 50 * 1024 * 1024
# Members larger than this (uncompressed) are skipped rather than inflated.
MAX_MEMBER_BYTES = 20 * 1024 * 1024
_MAX_ROUNDS = 16


class WheelError(Exception):
    """The wheel can't be read and retrying won't help (corrupt, oversized, unsupported)."""


class _RangeNotSupported(Exception):
    pass


class _MissingRange(Exception):
    def __init__(self, offset: int, length: int) -> None:
        super().__init__(offset, length)
        self.offset = offset
        self.length = length


class _SparseFile(io.RawIOBase):
    """Seekable read-only view over the byte ranges fetched so far."""

    def __init__(self, size: int) -> None:
        self._size = size
        self._pos = 0
        self._chunks: list[tuple[int, bytes]] = []

    def add(self, offset: int, data: bytes) -> None:
        self._chunks.append((offset, data))

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            pos = offset
        elif whence == io.SEEK_CUR:
            pos = self._pos + offset
        else:
            pos = self._size + offset
        if pos < 0:
            raise OSError("negative seek position")
        self._pos = pos
        return pos

    def read(self, size: int | None = -1) -> bytes:
        start = self._pos
        if size is None or size < 0:
            size = self._size - start
        end = min(start + size, self._size)
        if end <= start:
            return b""
        for offset, data in self._chunks:
            if offset <= start and end <= offset + len(data):
                self._pos = end
                return data[start - offset : end - offset]
        raise _MissingRange(start, end - start)

    def readinto(self, buffer: memoryview) -> int:  # type: ignore[override]
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


async def _fetch_range(client: httpx.AsyncClient, url: str, start: int, end: int) -> bytes:
    async with client.stream("GET", url, headers={"Range": f"bytes={start}-{end}"}) as resp:
        if resp.status_code == 200:
            raise _RangeNotSupported
        resp.raise_for_status()
        if resp.status_code != 206:
            raise _RangeNotSupported
        body = await resp.aread()
    if len(body) != end - start + 1:
        raise WheelError(f"short range read: wanted {end - start + 1} bytes, got {len(body)}")
    return body


async def _content_length(client: httpx.AsyncClient, url: str) -> int:
    resp = await client.head(url, follow_redirects=True)
    resp.raise_for_status()
    length = resp.headers.get("content-length")
    if length is None:
        raise _RangeNotSupported
    return int(length)


async def _read_with_ranges(
    client: httpx.AsyncClient, url: str, size: int, want: Callable[[str], bool]
) -> dict[str, bytes]:
    sparse = _SparseFile(size)
    tail_start = max(0, size - TAIL_BYTES)
    sparse.add(tail_start, await _fetch_range(client, url, tail_start, size - 1))

    async def fill(missing: _MissingRange, slack: int) -> None:
        start = missing.offset
        end = min(size - 1, missing.offset + max(missing.length, slack) - 1)
        sparse.add(start, await _fetch_range(client, url, start, end))

    zf: zipfile.ZipFile | None = None
    for _ in range(_MAX_ROUNDS):
        try:
            sparse.seek(0)
            zf = zipfile.ZipFile(sparse)
            break
        except _MissingRange as missing:
            await fill(missing, TAIL_BYTES)
        except zipfile.BadZipFile as e:
            raise WheelError(f"bad zip: {e}") from e
    if zf is None:
        raise WheelError("central directory did not fit in the fetch budget")

    out: dict[str, bytes] = {}
    for info in zf.infolist():
        if not want(info.filename) or info.is_dir():
            continue
        if info.file_size > MAX_MEMBER_BYTES:
            continue
        # Local header (30 bytes) + name + extra, then the compressed data. The
        # local extra field can differ from the central one; the retry loop
        # below covers any shortfall.
        span = 30 + len(info.orig_filename.encode()) + len(info.extra) + info.compress_size + 1024
        await fill(_MissingRange(info.header_offset, span), 0)
        for _ in range(_MAX_ROUNDS):
            try:
                out[info.filename] = zf.read(info)
                break
            except _MissingRange as missing:
                await fill(missing, 64 * 1024)
            except (zipfile.BadZipFile, NotImplementedError, OSError, ValueError) as e:
                raise WheelError(f"cannot read {info.filename}: {e}") from e
    return out


async def _read_full_download(client: httpx.AsyncClient, url: str, want: Callable[[str], bool]) -> dict[str, bytes]:
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as tmp:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            total = 0
            async for chunk in resp.aiter_bytes(256 * 1024):
                total += len(chunk)
                if total > MAX_FULL_DOWNLOAD_BYTES:
                    raise WheelError("host ignores Range and wheel exceeds the full-download limit")
                tmp.write(chunk)
        tmp.seek(0)
        try:
            with zipfile.ZipFile(tmp) as zf:
                return {
                    i.filename: zf.read(i)
                    for i in zf.infolist()
                    if want(i.filename) and not i.is_dir() and i.file_size <= MAX_MEMBER_BYTES
                }
        except zipfile.BadZipFile as e:
            raise WheelError(f"bad zip: {e}") from e


async def read_members(
    client: httpx.AsyncClient, url: str, size: int | None, want: Callable[[str], bool]
) -> dict[str, bytes]:
    """Return {member name: bytes} for every member `want` accepts.

    Raises WheelError for permanent failures; httpx errors propagate so the
    caller can retry transient network problems.
    """
    try:
        if size is None:
            size = await _content_length(client, url)
        if size == 0:
            raise WheelError("empty file")
        return await _read_with_ranges(client, url, size, want)
    except _RangeNotSupported:
        return await _read_full_download(client, url, want)
