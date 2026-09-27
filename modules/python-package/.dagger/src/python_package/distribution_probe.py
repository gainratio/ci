"""Bounded static inspection of wheel and source-distribution archives."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import stat
import struct
import sys
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Final, Protocol, cast

from .distributions import (
    MAX_DISTRIBUTION_BYTES,
    MAX_DISTRIBUTION_MEMBERS,
    DistributionObservation,
)

MAX_METADATA_BYTES: Final = 262_144
MAX_UNCOMPRESSED_BYTES: Final = 64 * 1_024 * 1_024
MAX_TAR_STREAM_BYTES: Final = MAX_UNCOMPRESSED_BYTES
MAX_TAR_EXTENSION_BYTES: Final = MAX_METADATA_BYTES
MAX_ZIP_DIRECTORY_BYTES: Final = 8 * 1_024 * 1_024
TAR_BLOCK_BYTES: Final = 512
TAR_CHUNK_BYTES: Final = 64 * 1_024
TAR_EXTENSION_TYPES: Final = frozenset((b"x", b"g", b"L", b"K"))
TAR_ALLOWED_TYPES: Final = TAR_EXTENSION_TYPES | frozenset((b"\0", b"0", b"5"))
PRODUCT_COUNTS: Final = (2, 1, 1)
CLI_ARGUMENT_COUNT: Final = 2
ZIP_DISK_NUMBER_INDEX: Final = 1
ZIP_DISK_START_INDEX: Final = 2
ZIP_DISK_ENTRIES_INDEX: Final = 3
ZIP_TOTAL_ENTRIES_INDEX: Final = 4
ZIP_DIRECTORY_SIZE_INDEX: Final = 5
ZIP_DIRECTORY_OFFSET_INDEX: Final = 6
ZIP_COMMENT_SIZE_INDEX: Final = 7
ZIP_COMMENT_INDEX: Final = 8
ZIP_END_LOCATION_INDEX: Final = 9
ZIP_END_RECORD_BYTES: Final = 22
ZIP_END_SIGNATURE: Final = b"PK\x05\x06"
ZIP_CENTRAL_HEADER_BYTES: Final = 46
ZIP_CENTRAL_LENGTHS_OFFSET: Final = 28
ZIP_CENTRAL_LOCAL_OFFSET: Final = 42
ZIP_CENTRAL_SIGNATURE: Final = b"PK\x01\x02"
ZIP_CRC_OFFSET: Final = 16
ZIP_COMPRESSED_SIZE_OFFSET: Final = 20
ZIP_UNCOMPRESSED_SIZE_OFFSET: Final = 24
ZIP_COMPRESSION_OFFSET: Final = 10
ZIP_LOCAL_HEADER_BYTES: Final = 30
ZIP_LOCAL_LENGTHS_OFFSET: Final = 26
ZIP_LOCAL_SIGNATURE: Final = b"PK\x03\x04"
ZIP_FLAG_BITS_OFFSET: Final = 8
ZIP_LOCAL_FLAG_BITS_OFFSET: Final = 6
ZIP_LOCAL_COMPRESSION_OFFSET: Final = 8
ZIP_UTF8_FLAG: Final = 0x800
ZIP_DATA_DESCRIPTOR_FLAG: Final = 0x8
ZIP_DATA_DESCRIPTOR_SIGNATURE: Final = b"PK\x07\x08"
ZIP32_SENTINEL: Final = 0xFFFF_FFFF
ZIP64_EXTRA_IDENTIFIER: Final = 0x0001
ZIP64_VALUE_BYTES: Final = 8
ZIP_EXTRA_HEADER_BYTES: Final = 4
ZIP64_END_SIGNATURE: Final = b"PK\x06\x06"
ZIP64_TRAILER_BYTES: Final = 76


class ProbeError(ValueError):
    """Raised when an archive cannot yield safe, bounded distribution evidence."""


class _GzipDecoder(Protocol):
    @property
    def unused_data(self) -> bytes: ...


class _BoundedTarReader(io.RawIOBase):
    """Cap bytes decompressed before tarfile can process hidden extension records."""

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._consumed = 0

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        remaining = MAX_TAR_STREAM_BYTES - self._consumed
        requested = _bounded_read_size(size, remaining)
        value = self._stream.read(requested)
        self._consumed += len(value)
        if self._consumed > MAX_TAR_STREAM_BYTES:
            raise ProbeError("sdist exceeds its decompressed byte bound")
        return value


@dataclass(frozen=True)
class _TarScanState:
    records: int = 0
    payload_bytes: int = 0
    extension_bytes: int = 0


@dataclass(frozen=True)
class _ZipRecord:
    raw_name: bytes
    name: str
    flags: int
    compression: int
    crc: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int


def inspect_directory(path: Path) -> tuple[DistributionObservation, DistributionObservation]:
    """Inspect exactly one wheel and one sdist without extracting either archive."""
    files = tuple(path.iterdir())
    if len(files) != PRODUCT_COUNTS[0] or not all(_is_file(item) for item in files):
        raise ProbeError("dist directory must contain exactly two regular files")
    wheels = tuple(filter(_is_wheel, files))
    sdists = tuple(filter(_is_sdist, files))
    if (len(files), len(wheels), len(sdists)) != PRODUCT_COUNTS:
        raise ProbeError("dist directory must contain exactly one wheel and one sdist")
    return _inspect_wheel(wheels[0]), _inspect_sdist(sdists[0])


def _is_file(path: Path) -> bool:
    return stat.S_ISREG(path.lstat().st_mode)


def _is_wheel(path: Path) -> bool:
    return path.name.endswith(".whl")


def _is_sdist(path: Path) -> bool:
    return path.name.endswith(".tar.gz")


def _inspect_wheel(path: Path) -> DistributionObservation:
    _require_archive_size(path)
    _require_zip_preflight(path)
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        _require_member_inventory(tuple(item.filename for item in members), len(members))
        _require_zip_bounds(members)
        metadata = _one_zip_record(archive, members, ".dist-info/METADATA")
        wheel = _one_zip_record(archive, members, ".dist-info/WHEEL")
    _require_pure_wheel(wheel)
    project, version = _core_metadata(metadata)
    return _observation(path, "wheel", project, version, len(members))


def _inspect_sdist(path: Path) -> DistributionObservation:
    _require_archive_size(path)
    _require_single_gzip_member(path)
    raw_count = _preflight_sdist(path)
    with gzip.GzipFile(filename=path, mode="rb") as decompressed:
        reader = _BoundedTarReader(cast(BinaryIO, decompressed))
        with tarfile.open(fileobj=reader, mode="r|") as archive:
            yielded_count, metadata, roots = _stream_tar(archive)
    if yielded_count > raw_count:
        raise ProbeError("sdist raw member inventory differs")
    project, version = _core_metadata(metadata)
    _require_sdist_root(path, roots, project, version)
    return _observation(path, "sdist", project, version, raw_count)


def _require_single_gzip_member(path: Path) -> None:
    try:
        with path.open("rb") as stream:
            _scan_single_gzip(stream)
    except zlib.error:
        raise ProbeError("sdist gzip framing differs") from None


def _scan_single_gzip(stream: BinaryIO) -> None:
    decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    total, pending = 0, b""
    while not decoder.eof:
        pending = _gzip_input(stream, pending)
        value = decoder.decompress(pending, MAX_TAR_STREAM_BYTES - total + 1)
        total, pending = _bounded_gzip_total(total, len(value)), decoder.unconsumed_tail
    _require_gzip_end(stream, decoder, pending)


def _gzip_input(stream: BinaryIO, pending: bytes) -> bytes:
    result = pending or stream.read(TAR_CHUNK_BYTES)
    if not result:
        raise ProbeError("sdist gzip framing differs")
    return result


def _require_gzip_end(stream: BinaryIO, decoder: _GzipDecoder, pending: bytes) -> None:
    if decoder.unused_data or pending or stream.read(1):
        raise ProbeError("sdist must contain a single gzip member")


def _bounded_gzip_total(total: int, size: int) -> int:
    result = total + size
    if result > MAX_TAR_STREAM_BYTES:
        raise ProbeError("sdist exceeds its decompressed byte bound")
    return result


def _preflight_sdist(path: Path) -> int:
    with gzip.GzipFile(filename=path, mode="rb") as decompressed:
        reader = _BoundedTarReader(cast(BinaryIO, decompressed))
        return _scan_raw_tar(reader)


def _scan_raw_tar(reader: _BoundedTarReader) -> int:
    state = _TarScanState()
    while True:
        header = _read_tar_block(reader)
        if not any(header):
            _require_tar_end(reader)
            return state.records
        state = _observe_raw_tar_header(state, header)
        _skip_tar_payload(reader, _raw_tar_size(header))


def _observe_raw_tar_header(state: _TarScanState, header: bytes) -> _TarScanState:
    _require_tar_checksum(header)
    name = _raw_tar_name(header)
    if not _safe_member(name):
        raise ProbeError("distribution archive has duplicate or unsafe members")
    kind, size = header[156:157], _raw_tar_size(header)
    if kind not in TAR_ALLOWED_TYPES:
        raise ProbeError("sdist contains an unsupported archive member")
    _require_tar_extension_name(kind, name)
    extensions = state.extension_bytes + (size if kind in TAR_EXTENSION_TYPES else 0)
    result = _TarScanState(state.records + 1, state.payload_bytes + size, extensions)
    _require_raw_tar_bounds(result)
    return result


def _require_tar_extension_name(kind: bytes, name: str) -> None:
    expected: str | None = None
    if kind in (b"x", b"g"):
        expected = "././@PaxHeader"
    if kind in (b"L", b"K"):
        expected = "././@LongLink"
    if expected is not None and name != expected:
        raise ProbeError("sdist extension header name differs")


def _require_raw_tar_bounds(state: _TarScanState) -> None:
    if state.records > MAX_DISTRIBUTION_MEMBERS:
        raise ProbeError("distribution archive exceeds its member bound")
    if state.payload_bytes > MAX_UNCOMPRESSED_BYTES:
        raise ProbeError("sdist exceeds its uncompressed byte bound")
    if state.extension_bytes > MAX_TAR_EXTENSION_BYTES:
        raise ProbeError("sdist exceeds its extension byte bound")


def _read_tar_block(reader: _BoundedTarReader) -> bytes:
    value = reader.read(TAR_BLOCK_BYTES)
    if len(value) != TAR_BLOCK_BYTES:
        raise ProbeError("sdist tar record is truncated")
    return value


def _require_tar_end(reader: _BoundedTarReader) -> None:
    if any(_read_tar_block(reader)):
        raise ProbeError("sdist tar terminator differs")
    trailing = 0
    while value := reader.read(TAR_CHUNK_BYTES):
        if any(value):
            raise ProbeError("sdist has trailing archive data")
        trailing += len(value)
    if trailing % TAR_BLOCK_BYTES:
        raise ProbeError("sdist trailer alignment differs")


def _skip_tar_payload(reader: _BoundedTarReader, size: int) -> None:
    remaining = size + (-size % TAR_BLOCK_BYTES)
    while remaining:
        value = reader.read(min(remaining, TAR_CHUNK_BYTES))
        if not value:
            raise ProbeError("sdist member payload is truncated")
        remaining -= len(value)


def _raw_tar_size(header: bytes) -> int:
    return _tar_octal(header[124:136])


def _tar_octal(value: bytes) -> int:
    stripped = value.strip(b"\0 ")
    if not stripped or any(item not in range(ord("0"), ord("7") + 1) for item in stripped):
        raise ProbeError("sdist tar numeric field differs")
    return int(stripped, 8)


def _raw_tar_name(header: bytes) -> str:
    name = _tar_text(header[0:100])
    prefix = _tar_text(header[345:500])
    return f"{prefix}/{name}" if prefix else name


def _tar_text(value: bytes) -> str:
    try:
        return value.split(b"\0", maxsplit=1)[0].decode("utf-8")
    except UnicodeDecodeError:
        raise ProbeError("sdist tar text field differs") from None


def _require_tar_checksum(header: bytes) -> None:
    expected = _tar_octal(header[148:156])
    actual = sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
    if actual != expected:
        raise ProbeError("sdist tar checksum differs")


def _bounded_read_size(size: int, remaining: int) -> int:
    if remaining < 0:
        return 1
    if size < 0:
        return remaining + 1
    return min(size, remaining + 1)


def _require_zip_preflight(path: Path) -> None:
    record = _zip_end_record(path)
    _require_zip_physical_end(path, record)
    count = _zip_field(record, ZIP_TOTAL_ENTRIES_INDEX)
    size = _zip_field(record, ZIP_DIRECTORY_SIZE_INDEX)
    if not 0 < count <= MAX_DISTRIBUTION_MEMBERS:
        raise ProbeError("distribution archive exceeds its member bound")
    if not 0 < size <= MAX_ZIP_DIRECTORY_BYTES:
        raise ProbeError("wheel exceeds its central-directory byte bound")
    _require_single_disk_zip(record, count)
    _scan_zip_directory(path, record, count, size)


def _require_zip_physical_end(path: Path, record: list[object]) -> None:
    location = _zip_field(record, ZIP_END_LOCATION_INDEX)
    comment_size = _zip_field(record, ZIP_COMMENT_SIZE_INDEX)
    comment = record[ZIP_COMMENT_INDEX]
    expected = location + ZIP_END_RECORD_BYTES + comment_size
    if not isinstance(comment, bytes) or len(comment) != comment_size:
        raise ProbeError("wheel end-record comment differs")
    with path.open("rb") as stream:
        stream.seek(location)
        signature = stream.read(len(ZIP_END_SIGNATURE))
    if signature != ZIP_END_SIGNATURE or path.stat().st_size != expected:
        raise ProbeError("wheel physical EOF differs")


def _zip_end_record(path: Path) -> list[object]:
    with path.open("rb") as stream:
        raw: object = zipfile._EndRecData(stream)  # type: ignore[attr-defined]
    if not isinstance(raw, list):
        raise ProbeError("wheel end record differs")
    return _with_classic_end_location(path, cast(list[object], raw))


def _with_classic_end_location(path: Path, record: list[object]) -> list[object]:
    # For ZIP64 archives zipfile reports the classic end record's offset on CPython <= 3.13.5
    # but the ZIP64 end record's offset on 3.13.14. The classic record ends the file, so
    # derive its offset from EOF; the physical-EOF check then verifies its signature there.
    comment_size = _zip_field(record, ZIP_COMMENT_SIZE_INDEX)
    location = path.stat().st_size - ZIP_END_RECORD_BYTES - comment_size
    return [*record[:ZIP_END_LOCATION_INDEX], location, *record[ZIP_END_LOCATION_INDEX + 1 :]]


def _zip_field(record: list[object], index: int) -> int:
    value = record[index]
    if not isinstance(value, int):
        raise ProbeError("wheel end record differs")
    return value


def _require_single_disk_zip(record: list[object], count: int) -> None:
    disk = _zip_field(record, ZIP_DISK_NUMBER_INDEX)
    start = _zip_field(record, ZIP_DISK_START_INDEX)
    disk_count = _zip_field(record, ZIP_DISK_ENTRIES_INDEX)
    if (disk, start, disk_count) != (0, 0, count):
        raise ProbeError("wheel multipart archives are unsupported")


def _scan_zip_directory(path: Path, record: list[object], expected: int, size: int) -> None:
    records: list[_ZipRecord] = []
    start = _zip_directory_start(record, size)
    with path.open("rb") as stream:
        stream.seek(start)
        remaining = size
        while remaining:
            remaining, current = _consume_zip_record(stream, remaining)
            records.append(current)
            if len(records) > MAX_DISTRIBUTION_MEMBERS:
                raise ProbeError("distribution archive exceeds its member bound")
    _require_raw_zip_inventory(tuple(records), expected)
    _require_zip_local_records(path, start, tuple(records))


def _zip_directory_start(record: list[object], size: int) -> int:
    offset = _zip_field(record, ZIP_DIRECTORY_OFFSET_INDEX)
    location = _zip_field(record, ZIP_END_LOCATION_INDEX)
    trailer = ZIP64_TRAILER_BYTES if record[0] == ZIP64_END_SIGNATURE else 0
    if location - size - offset != trailer:
        raise ProbeError("wheel concatenated archives are unsupported")
    return offset


def _consume_zip_record(stream: BinaryIO, remaining: int) -> tuple[int, _ZipRecord]:
    header = stream.read(ZIP_CENTRAL_HEADER_BYTES)
    if len(header) != ZIP_CENTRAL_HEADER_BYTES or header[:4] != ZIP_CENTRAL_SIGNATURE:
        raise ProbeError("wheel central-directory record differs")
    lengths = _zip_lengths(header, ZIP_CENTRAL_LENGTHS_OFFSET)
    consumed = ZIP_CENTRAL_HEADER_BYTES + sum(lengths)
    if consumed > remaining:
        raise ProbeError("wheel central-directory record is truncated")
    raw_name = _read_zip_name(stream, lengths[0])
    extra = _read_zip_extra(stream, lengths[1])
    stream.seek(lengths[2], io.SEEK_CUR)
    return remaining - consumed, _zip_record(header, raw_name, extra)


def _zip_record(header: bytes, raw_name: bytes, extra: bytes) -> _ZipRecord:
    flags = _zip_u16(header, ZIP_FLAG_BITS_OFFSET)
    sizes = _resolve_zip64_fields(_zip_raw_fields(header), extra)
    return _ZipRecord(
        raw_name,
        _zip_name(raw_name, flags),
        flags,
        _zip_u16(header, ZIP_COMPRESSION_OFFSET),
        _zip_u32(header, ZIP_CRC_OFFSET),
        sizes[1],
        sizes[0],
        sizes[2],
    )


def _zip_raw_fields(header: bytes) -> tuple[int, int, int]:
    return (
        _zip_u32(header, ZIP_UNCOMPRESSED_SIZE_OFFSET),
        _zip_u32(header, ZIP_COMPRESSED_SIZE_OFFSET),
        _zip_u32(header, ZIP_CENTRAL_LOCAL_OFFSET),
    )


def _resolve_zip64_fields(values: tuple[int, int, int], extra: bytes) -> tuple[int, int, int]:
    if ZIP32_SENTINEL not in values:
        return values
    payload = _zip_extra_value(extra, ZIP64_EXTRA_IDENTIFIER)
    resolved: list[int] = []
    for value in values:
        current, payload = _resolve_zip64_value(value, payload)
        resolved.append(current)
    return cast(tuple[int, int, int], tuple(resolved))


def _resolve_zip64_value(value: int, payload: bytes) -> tuple[int, bytes]:
    if value != ZIP32_SENTINEL:
        return value, payload
    if len(payload) < ZIP64_VALUE_BYTES:
        raise ProbeError("wheel ZIP64 extra field is truncated")
    return int.from_bytes(payload[:ZIP64_VALUE_BYTES], "little"), payload[ZIP64_VALUE_BYTES:]


def _zip_extra_value(extra: bytes, identifier: int) -> bytes:
    position = 0
    while position < len(extra):
        if len(extra) - position < ZIP_EXTRA_HEADER_BYTES:
            raise ProbeError("wheel extra field is truncated")
        current = int.from_bytes(extra[position : position + 2], "little")
        size = int.from_bytes(extra[position + 2 : position + 4], "little")
        position += 4
        if position + size > len(extra):
            raise ProbeError("wheel extra field is truncated")
        if current == identifier:
            return extra[position : position + size]
        position += size
    raise ProbeError("wheel ZIP64 extra field differs")


def _require_raw_zip_inventory(records: tuple[_ZipRecord, ...], expected: int) -> None:
    if len(records) != expected:
        raise ProbeError("wheel central-directory inventory differs")
    _require_member_inventory(tuple(item.name for item in records), len(records))


def _require_zip_local_records(path: Path, start: int, records: tuple[_ZipRecord, ...]) -> None:
    ordered = tuple(sorted(records, key=lambda item: item.local_offset))
    if ordered[0].local_offset != 0:
        raise ProbeError("wheel has a leading payload")
    with path.open("rb") as stream:
        for index, record in enumerate(ordered):
            boundary = ordered[index + 1].local_offset if index + 1 < len(ordered) else start
            _require_zip_local_record(stream, boundary, record)


def _require_zip_local_record(stream: BinaryIO, boundary: int, record: _ZipRecord) -> None:
    if not 0 <= record.local_offset <= boundary - ZIP_LOCAL_HEADER_BYTES:
        raise ProbeError("wheel local record offset differs")
    stream.seek(record.local_offset)
    header = stream.read(ZIP_LOCAL_HEADER_BYTES)
    if len(header) != ZIP_LOCAL_HEADER_BYTES or header[:4] != ZIP_LOCAL_SIGNATURE:
        raise ProbeError("wheel local record differs")
    name_length, extra_length = _zip_local_lengths(header)
    payload = record.local_offset + ZIP_LOCAL_HEADER_BYTES + name_length + extra_length
    if payload + record.compressed_size > boundary:
        raise ProbeError("wheel local record is truncated")
    _require_zip_local_name(stream, header, name_length, record)
    _require_zip_record_coverage(stream, payload + record.compressed_size, boundary, record)


def _require_zip_local_name(
    stream: BinaryIO, header: bytes, length: int, record: _ZipRecord
) -> None:
    raw_name = _read_zip_name(stream, length)
    flags = _zip_u16(header, ZIP_LOCAL_FLAG_BITS_OFFSET)
    compression = _zip_u16(header, ZIP_LOCAL_COMPRESSION_OFFSET)
    if (flags, compression, raw_name) != (record.flags, record.compression, record.raw_name):
        raise ProbeError("wheel local filename differs")


def _require_zip_record_coverage(
    stream: BinaryIO, payload_end: int, boundary: int, record: _ZipRecord
) -> None:
    if not record.flags & ZIP_DATA_DESCRIPTOR_FLAG:
        if payload_end != boundary:
            raise ProbeError("wheel local record coverage differs")
        return
    stream.seek(payload_end)
    descriptor = stream.read(boundary - payload_end)
    if descriptor not in _zip_descriptors(record):
        raise ProbeError("wheel data descriptor differs")


def _zip_descriptors(record: _ZipRecord) -> tuple[bytes, ...]:
    standard = struct.pack("<LLL", record.crc, record.compressed_size, record.uncompressed_size)
    wide = struct.pack("<LQQ", record.crc, record.compressed_size, record.uncompressed_size)
    return (
        standard,
        ZIP_DATA_DESCRIPTOR_SIGNATURE + standard,
        wide,
        ZIP_DATA_DESCRIPTOR_SIGNATURE + wide,
    )


def _read_zip_name(stream: BinaryIO, length: int) -> bytes:
    value = stream.read(length)
    if len(value) != length:
        raise ProbeError("wheel filename is truncated")
    return value


def _read_zip_extra(stream: BinaryIO, length: int) -> bytes:
    value = stream.read(length)
    if len(value) != length:
        raise ProbeError("wheel extra field is truncated")
    return value


def _zip_name(value: bytes, flags: int) -> str:
    encoding = "utf-8" if flags & ZIP_UTF8_FLAG else "ascii"
    try:
        name = value.decode(encoding)
    except UnicodeDecodeError:
        raise ProbeError("wheel filename encoding differs") from None
    if not _safe_member(name):
        raise ProbeError("distribution archive has duplicate or unsafe members")
    return name


def _zip_lengths(header: bytes, offset: int) -> tuple[int, int, int]:
    return cast(tuple[int, int, int], struct.unpack_from("<HHH", header, offset))


def _zip_local_lengths(header: bytes) -> tuple[int, int]:
    return cast(tuple[int, int], struct.unpack_from("<HH", header, ZIP_LOCAL_LENGTHS_OFFSET))


def _zip_u16(header: bytes, offset: int) -> int:
    return cast(int, struct.unpack_from("<H", header, offset)[0])


def _zip_u32(header: bytes, offset: int) -> int:
    return cast(int, struct.unpack_from("<L", header, offset)[0])


def _stream_tar(archive: tarfile.TarFile) -> tuple[int, bytes, tuple[str, ...]]:
    count, total = 0, 0
    names, roots = set[str](), set[str]()
    metadata: bytes | None = None
    for member in archive:
        count += 1
        _require_tar_header(member, names, count)
        roots.add(_member_root(member.name))
        total = _bounded_tar_total(total, member.size)
        if _is_root_metadata(member):
            metadata = _tar_metadata(archive, member, metadata)
    return _finish_tar_stream(count, names, roots, metadata)


def _finish_tar_stream(
    count: int, names: set[str], roots: set[str], metadata: bytes | None
) -> tuple[int, bytes, tuple[str, ...]]:
    _require_member_inventory(tuple(names), count)
    _require_pkg_info_inventory(names)
    if metadata is None:
        raise ProbeError("sdist metadata inventory differs")
    return count, metadata, tuple(sorted(roots))


def _require_pkg_info_inventory(names: set[str]) -> None:
    matching = tuple(name for name in names if PurePosixPath(name).name == "PKG-INFO")
    if len(matching) != 1 or matching[0].count("/") != 1:
        raise ProbeError("sdist metadata inventory differs")


def _member_root(name: str) -> str:
    return PurePosixPath(name).parts[0]


def _require_sdist_root(path: Path, roots: tuple[str, ...], project: str, version: str) -> None:
    suffix = f"-{version}.tar.gz"
    if not path.name.endswith(suffix):
        raise ProbeError("sdist root differs from filename and metadata")
    filename_project = path.name[: -len(suffix)]
    expected = path.name.removesuffix(".tar.gz")
    if _canonical_project(filename_project) != project or roots != (expected,):
        raise ProbeError("sdist root differs from filename and metadata")


def _require_tar_header(member: tarfile.TarInfo, names: set[str], count: int) -> None:
    if count > MAX_DISTRIBUTION_MEMBERS:
        raise ProbeError("distribution archive exceeds its member bound")
    if member.name in names or not _safe_member(member.name):
        raise ProbeError("distribution archive has duplicate or unsafe members")
    if _unsupported_tar_member(member):
        raise ProbeError("sdist contains an unsupported archive member")
    names.add(member.name)


def _bounded_tar_total(total: int, size: int) -> int:
    result = total + size
    if result > MAX_UNCOMPRESSED_BYTES:
        raise ProbeError("sdist exceeds its uncompressed byte bound")
    return result


def _tar_metadata(
    archive: tarfile.TarFile, member: tarfile.TarInfo, current: bytes | None
) -> bytes:
    if current is not None or member.size > MAX_METADATA_BYTES:
        raise ProbeError("sdist metadata inventory differs")
    value = _read_tar_record(archive, member)
    if len(value) > MAX_METADATA_BYTES:
        raise ProbeError("sdist metadata inventory differs")
    return value


def _require_archive_size(path: Path) -> None:
    size = path.stat().st_size
    if not 0 < size <= MAX_DISTRIBUTION_BYTES:
        raise ProbeError("distribution archive exceeds its byte bound")


def _require_member_inventory(names: tuple[str, ...], count: int) -> None:
    if not 0 < count <= MAX_DISTRIBUTION_MEMBERS:
        raise ProbeError("distribution archive exceeds its member bound")
    if len(set(names)) != count or not all(_safe_member(name) for name in names):
        raise ProbeError("distribution archive has duplicate or unsafe members")


def _safe_member(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and "\x00" not in value


def _require_zip_bounds(members: list[zipfile.ZipInfo]) -> None:
    if sum(item.file_size for item in members) > MAX_UNCOMPRESSED_BYTES:
        raise ProbeError("wheel exceeds its uncompressed byte bound")
    if any(_unsafe_zip_member(item) for item in members):
        raise ProbeError("wheel contains an unsupported archive member")


def _unsafe_zip_member(item: zipfile.ZipInfo) -> bool:
    mode = item.external_attr >> 16
    kind = stat.S_IFMT(mode)
    unsupported_kind = kind not in (0, stat.S_IFREG, stat.S_IFDIR)
    return bool(item.flag_bits & 0x1) or unsupported_kind


def _one_zip_record(archive: zipfile.ZipFile, members: list[zipfile.ZipInfo], suffix: str) -> bytes:
    matching = tuple(item for item in members if item.filename.endswith(suffix))
    if len(matching) != 1 or matching[0].file_size > MAX_METADATA_BYTES:
        raise ProbeError("wheel metadata inventory differs")
    return archive.read(matching[0])


def _require_pure_wheel(value: bytes) -> None:
    metadata = BytesParser(policy=policy.default).parsebytes(value)
    pure = metadata.get_all("Root-Is-Purelib", failobj=[])
    tags = metadata.get_all("Tag", failobj=[])
    if pure != ["true"] or tags != ["py3-none-any"]:
        raise ProbeError("wheel must be a pure-Python py3-none-any product")


def _require_tar_bounds(members: list[tarfile.TarInfo]) -> None:
    if sum(item.size for item in members) > MAX_UNCOMPRESSED_BYTES:
        raise ProbeError("sdist exceeds its uncompressed byte bound")
    if any(_unsupported_tar_member(item) for item in members):
        raise ProbeError("sdist contains an unsupported archive member")


def _unsupported_tar_member(item: tarfile.TarInfo) -> bool:
    return not any((item.isfile(), item.isdir()))


def _one_tar_record(archive: tarfile.TarFile, members: list[tarfile.TarInfo]) -> bytes:
    matching = tuple(filter(_is_root_metadata, members))
    if len(matching) != 1 or matching[0].size > MAX_METADATA_BYTES:
        raise ProbeError("sdist metadata inventory differs")
    return _read_tar_record(archive, matching[0])


def _is_root_metadata(item: tarfile.TarInfo) -> bool:
    return item.name.count("/") == 1 and item.name.endswith("/PKG-INFO")


def _read_tar_record(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    stream = archive.extractfile(member)
    if stream is None:
        raise ProbeError("sdist metadata could not be read")
    return stream.read(MAX_METADATA_BYTES + 1)


def _core_metadata(value: bytes) -> tuple[str, str]:
    metadata = BytesParser(policy=policy.default).parsebytes(value)
    names = metadata.get_all("Name", failobj=[])
    versions = metadata.get_all("Version", failobj=[])
    if len(names) != 1 or len(versions) != 1:
        raise ProbeError("distribution core metadata differs")
    return _canonical_project(names[0]), versions[0]


def _canonical_project(value: str) -> str:
    result = re.sub(r"[-_.]+", "-", value).lower()
    if not result or result != value.lower().replace("_", "-").replace(".", "-"):
        raise ProbeError("distribution project metadata is not canonicalizable")
    return result


def _observation(
    path: Path, kind: str, project: str, version: str, count: int
) -> DistributionObservation:
    return DistributionObservation(
        path.name,
        _digest(path),
        "wheel" if kind == "wheel" else "sdist",
        project,
        version,
        count,
        path.stat().st_size,
    )


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _payload(items: tuple[DistributionObservation, ...]) -> str:
    values = tuple(item.__dict__ for item in items)
    return json.dumps(values, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def main() -> None:
    """Emit one canonical observation payload for the Dagger adapter."""
    if len(sys.argv) != CLI_ARGUMENT_COUNT:
        raise SystemExit("usage: distribution-probe DIST_DIRECTORY")
    try:
        print(_payload(inspect_directory(Path(sys.argv[1]))))
    except (OSError, tarfile.TarError, zipfile.BadZipFile, ProbeError) as error:
        raise SystemExit(f"distribution probe failed: {error}") from None


if __name__ == "__main__":
    main()
