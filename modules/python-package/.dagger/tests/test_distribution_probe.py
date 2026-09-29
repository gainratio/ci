from __future__ import annotations

import gzip
import io
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

from python_package import distribution_probe as probe
from python_package.distribution_probe import ProbeError, inspect_directory


class _UnseekableBuffer(io.BytesIO):
    def seekable(self) -> bool:
        return False

    def seek(self, *_args: object, **_kwargs: object) -> int:
        raise io.UnsupportedOperation


def test_should_observe_real_pure_wheel_and_sdist_metadata(tmp_path: Path) -> None:
    # Given a built wheel and source distribution with matching core metadata
    _write_wheel(tmp_path, member_count=4)
    _write_sdist(tmp_path, member_count=4)

    # When the bounded static probe inspects the dist directory
    observed = inspect_directory(tmp_path)

    # Then it reports exact package metadata, member counts, sizes, and digests
    assert tuple(item.kind for item in observed) == ("wheel", "sdist")
    assert all(item.project == "probe-package" for item in observed)
    assert all(item.version == "1.2.3" for item in observed)
    assert all(len(item.sha256) == 64 for item in observed)
    assert tuple(item.member_count for item in observed) == (4, 4)


def test_should_stream_sdist_inventory_without_materializing_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given valid products and a guard against the allocating tar API
    _write_wheel(tmp_path, member_count=4)
    _write_sdist(tmp_path, member_count=4)
    monkeypatch.setattr(tarfile.TarFile, "getmembers", _fail_getmembers)

    # When the bounded static probe inspects the source distribution
    observed = inspect_directory(tmp_path)

    # Then it consumes the tar stream incrementally
    assert observed[1].member_count == 4


def test_should_reject_oversized_sdist_member_before_payload_read(tmp_path: Path) -> None:
    # Given a tiny compressed archive declaring a payload beyond the expansion bound
    _write_wheel(tmp_path, member_count=4)
    target = tmp_path / "probe_package-1.2.3.tar.gz"
    info = tarfile.TarInfo("probe_package-1.2.3/huge.bin")
    info.size = 64 * 1_024 * 1_024 + 1
    with gzip.open(target, "wb") as stream:
        stream.write(info.tobuf())

    # When / Then the declared size fails before the payload is decompressed
    with pytest.raises(ProbeError, match="uncompressed byte"):
        inspect_directory(tmp_path)


def test_should_bound_hidden_pax_decompression_before_member_yield(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given a tiny gzip whose hidden PAX record expands beyond the test stream bound
    _write_wheel(tmp_path, member_count=4)
    _write_pax_sdist(tmp_path, hidden_bytes=32 * 1_024)
    monkeypatch.setattr(probe, "MAX_TAR_STREAM_BYTES", 16 * 1_024, raising=False)

    # When / Then tarfile cannot consume the hidden record before our policy sees it
    with pytest.raises(ProbeError, match="decompressed byte"):
        inspect_directory(tmp_path)


def test_should_reject_excess_wheel_count_before_materializing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given a sub-32MiB wheel with more entries than the public bound
    _write_wheel(tmp_path, member_count=4_097)
    _write_sdist(tmp_path, member_count=4)
    monkeypatch.setattr(zipfile.ZipFile, "_RealGetContents", _fail_zip_materialization)

    # When / Then the EOCD count fails before ZipInfo allocation
    with pytest.raises(ProbeError, match="member bound"):
        inspect_directory(tmp_path)


def test_should_reject_forged_wheel_count_before_materializing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given a central directory with 4,097 entries but an EOCD claiming one
    _write_wheel(tmp_path, member_count=4_097)
    _write_sdist(tmp_path, member_count=4)
    _forge_wheel_counts(tmp_path, count=1)
    monkeypatch.setattr(zipfile.ZipFile, "_RealGetContents", _fail_zip_materialization)

    # When / Then raw directory scanning defeats the forged count before allocation
    with pytest.raises(ProbeError, match="member bound"):
        inspect_directory(tmp_path)


def test_should_reject_rebased_leading_wheel_payload(tmp_path: Path) -> None:
    # Given an otherwise valid wheel with an executable-like prefix and rebased offsets
    _write_wheel(tmp_path, member_count=4)
    _write_sdist(tmp_path, member_count=4)
    _prefix_and_rebase_wheel(tmp_path, b"MZ" + bytes(4_094))

    # When / Then every accepted wheel must begin at its first referenced local record
    with pytest.raises(ProbeError, match="leading payload"):
        inspect_directory(tmp_path)


def test_should_reject_bytes_after_wheel_end_record(tmp_path: Path) -> None:
    # Given a valid wheel followed by bytes outside the declared EOCD comment
    _write_wheel(tmp_path, member_count=4)
    _write_sdist(tmp_path, member_count=4)
    target = tmp_path / "probe_package-1.2.3-py3-none-any.whl"
    target.write_bytes(target.read_bytes() + b"MZ" + bytes(4_094))

    # When / Then the physical wheel ends exactly at its declared ZIP framing
    with pytest.raises(ProbeError, match="physical EOF"):
        inspect_directory(tmp_path)


def test_should_reject_unreferenced_bytes_between_wheel_records(tmp_path: Path) -> None:
    # Given unmanifested executable-like bytes inserted between valid local records
    _write_wheel(tmp_path, member_count=4)
    _write_sdist(tmp_path, member_count=4)
    _insert_and_rebase_wheel_gap(tmp_path, b"MZ" + bytes(4_094))

    # When / Then referenced record/data ranges must cover the local archive contiguously
    with pytest.raises(ProbeError, match="local record coverage"):
        inspect_directory(tmp_path)


@pytest.mark.parametrize("location", ("central", "local"))
def test_should_reject_raw_nul_wheel_filename(tmp_path: Path, location: str) -> None:
    # Given a NUL that ZipInfo would silently truncate in one raw filename
    _write_wheel(tmp_path, member_count=4)
    _write_sdist(tmp_path, member_count=4)
    _nul_first_wheel_name(tmp_path, location)

    # When / Then raw central and local names both fail before semantic parsing
    with pytest.raises(ProbeError, match=r"unsafe|local filename"):
        inspect_directory(tmp_path)


def test_should_reject_non_block_aligned_sdist_trailer(tmp_path: Path) -> None:
    # Given a valid tar stream with one extra zero byte after its block-aligned trailer
    _write_wheel(tmp_path, member_count=4)
    _write_sdist(tmp_path, member_count=4)
    target = tmp_path / "probe_package-1.2.3.tar.gz"
    target.write_bytes(gzip.compress(gzip.decompress(target.read_bytes()) + b"\0"))

    # When / Then zero padding still has to preserve tar block framing
    with pytest.raises(ProbeError, match="trailer alignment"):
        inspect_directory(tmp_path)


def test_should_reject_second_empty_gzip_member_with_large_extra(tmp_path: Path) -> None:
    # Given a valid sdist followed by an empty gzip member carrying 4 KiB of hidden header bytes
    _write_wheel(tmp_path, member_count=4)
    _write_sdist(tmp_path, member_count=4)
    target = tmp_path / "probe_package-1.2.3.tar.gz"
    target.write_bytes(target.read_bytes() + _empty_gzip_member(b"MZ" + bytes(4_094)))

    # When / Then one source distribution is exactly one bounded gzip member
    with pytest.raises(ProbeError, match="single gzip member"):
        inspect_directory(tmp_path)


def test_should_reject_mixed_or_unexpected_sdist_roots(tmp_path: Path) -> None:
    # Given canonical metadata beneath the wrong root plus payload beneath a second root
    _write_wheel(tmp_path, member_count=4)
    target = tmp_path / "probe_package-1.2.3.tar.gz"
    with tarfile.open(target, "w:gz") as archive:
        _tar_file(archive, "evil-root/PKG-INFO", _metadata())
        _tar_file(archive, "different-root/module.py", b"")

    # When / Then filename, metadata identity, and every member share one exact root
    with pytest.raises(ProbeError, match="sdist root"):
        inspect_directory(tmp_path)


def test_should_reject_renamed_raw_pax_header(tmp_path: Path) -> None:
    # Given a canonical effective PKG-INFO preceded by a renamed local PAX pseudo-header
    _write_wheel(tmp_path, member_count=4)
    _write_pax_sdist(tmp_path, hidden_bytes=16)
    _rename_first_tar_header(tmp_path, "evil-root/PaxHeader")

    # When / Then hidden extension records use one explicit canonical pseudo-name
    with pytest.raises(ProbeError, match="extension header name"):
        inspect_directory(tmp_path)


def test_should_reject_nested_extra_pkg_info(tmp_path: Path) -> None:
    # Given one canonical root PKG-INFO plus another nested metadata record
    _write_wheel(tmp_path, member_count=4)
    target = tmp_path / "probe_package-1.2.3.tar.gz"
    with tarfile.open(target, "w:gz") as archive:
        _tar_file(archive, "probe_package-1.2.3/PKG-INFO", _metadata())
        _tar_file(archive, "probe_package-1.2.3/vendor/PKG-INFO", _metadata())

    # When / Then the entire sdist has exactly one root-level PKG-INFO basename
    with pytest.raises(ProbeError, match="sdist metadata inventory"):
        inspect_directory(tmp_path)


def test_should_reject_large_wheel_directory_before_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given a valid product whose central directory exceeds a reduced test bound
    _write_wheel(tmp_path, member_count=4)
    _write_sdist(tmp_path, member_count=4)
    monkeypatch.setattr(probe, "MAX_ZIP_DIRECTORY_BYTES", 128, raising=False)
    monkeypatch.setattr(zipfile.ZipFile, "_RealGetContents", _fail_zip_materialization)

    # When / Then the bounded EOCD preflight fails before ZipInfo allocation
    with pytest.raises(ProbeError, match="central-directory byte"):
        inspect_directory(tmp_path)


def test_should_handle_bounded_distribution_scale(tmp_path: Path) -> None:
    # Given archives materially larger than current 101-member production packages
    _write_wheel(tmp_path, member_count=2_048)
    _write_sdist(tmp_path, member_count=2_048)

    # When they remain within the explicit 4,096-member ingress bound
    observed = inspect_directory(tmp_path)

    # Then verification stays streaming and accepts the bounded inventory
    assert tuple(item.member_count for item in observed) == (2_048, 2_048)


def test_should_observe_bounded_forced_zip64_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given Python's valid forced-ZIP64 shape with sentinel sizes and local offsets
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 1)
    _write_forced_zip64_wheel(tmp_path)
    _write_sdist(tmp_path, member_count=4)

    # When / Then ZIP64 extras resolve the same closed wheel inventory
    observed = inspect_directory(tmp_path)
    assert observed[0].member_count == 4


def test_should_reject_bytes_after_forced_zip64_wheel_end_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given a valid forced-ZIP64 wheel followed by bytes outside its framing
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 1)
    _write_forced_zip64_wheel(tmp_path)
    _write_sdist(tmp_path, member_count=4)
    target = tmp_path / "probe_package-1.2.3-py3-none-any.whl"
    target.write_bytes(target.read_bytes() + b"MZ" + bytes(62))

    # When / Then trailing bytes still fail closed
    with pytest.raises(ProbeError, match=r"physical EOF|end record"):
        inspect_directory(tmp_path)


def test_should_observe_bounded_data_descriptor_wheel(tmp_path: Path) -> None:
    # Given a valid wheel written to an unseekable stream with data descriptors
    _write_data_descriptor_wheel(tmp_path)
    _write_sdist(tmp_path, member_count=4)

    # When / Then exact descriptor bytes close every local record range
    observed = inspect_directory(tmp_path)
    assert observed[0].member_count == 4


def test_should_reject_unsafe_archive_member_before_metadata_acceptance(tmp_path: Path) -> None:
    # Given an sdist containing a traversal member
    _write_wheel(tmp_path, member_count=4)
    target = tmp_path / "probe_package-1.2.3.tar.gz"
    with tarfile.open(target, "w:gz") as archive:
        _tar_file(archive, "../PKG-INFO", _metadata())

    # When / Then the archive cannot cross its logical product root
    with pytest.raises(ProbeError, match="unsafe"):
        inspect_directory(tmp_path)


def test_should_reject_platform_wheel_contract(tmp_path: Path) -> None:
    # Given a wheel that claims a native platform tag
    _write_wheel(tmp_path, member_count=4, tag="cp313-cp313-manylinux_2_28_x86_64")
    _write_sdist(tmp_path, member_count=4)

    # When / Then v1 accepts only portable pure-Python products
    with pytest.raises(ProbeError, match="pure-Python"):
        inspect_directory(tmp_path)


def _write_wheel(path: Path, *, member_count: int, tag: str = "py3-none-any") -> None:
    target = path / "probe_package-1.2.3-py3-none-any.whl"
    wheel = f"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n"
    members = {
        "probe_package/__init__.py": b"",
        "probe_package-1.2.3.dist-info/METADATA": _metadata(),
        "probe_package-1.2.3.dist-info/WHEEL": wheel.encode(),
    }
    for index in range(member_count - len(members)):
        members[f"probe_package/data/{index:04d}.txt"] = b"x"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def _write_forced_zip64_wheel(path: Path) -> None:
    target = path / "probe_package-1.2.3-py3-none-any.whl"
    members = {
        "probe_package/__init__.py": b"",
        "probe_package-1.2.3.dist-info/METADATA": _metadata(),
        "probe_package-1.2.3.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "probe_package/data.txt": b"x",
    }
    with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as archive:
        for name, content in members.items():
            info = zipfile.ZipInfo(name)
            with archive.open(info, "w", force_zip64=True) as stream:
                stream.write(content)


def _write_data_descriptor_wheel(path: Path) -> None:
    target = path / "probe_package-1.2.3-py3-none-any.whl"
    output = _UnseekableBuffer()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("probe_package/__init__.py", b"")
        archive.writestr("probe_package-1.2.3.dist-info/METADATA", _metadata())
        archive.writestr(
            "probe_package-1.2.3.dist-info/WHEEL",
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr("probe_package/data.txt", b"x")
    target.write_bytes(output.getvalue())


def _write_sdist(path: Path, *, member_count: int) -> None:
    target = path / "probe_package-1.2.3.tar.gz"
    members = {"probe_package-1.2.3/PKG-INFO": _metadata()}
    for index in range(member_count - len(members)):
        members[f"probe_package-1.2.3/src/{index:04d}.py"] = b""
    with tarfile.open(target, "w:gz") as archive:
        for name, content in members.items():
            _tar_file(archive, name, content)


def _forge_wheel_counts(path: Path, *, count: int) -> None:
    target = path / "probe_package-1.2.3-py3-none-any.whl"
    value = bytearray(target.read_bytes())
    end = value.rfind(b"PK\x05\x06")
    assert end >= 0
    struct.pack_into("<HH", value, end + 8, count, count)
    target.write_bytes(value)


def _prefix_and_rebase_wheel(path: Path, prefix: bytes) -> None:
    target = path / "probe_package-1.2.3-py3-none-any.whl"
    value = bytearray(target.read_bytes())
    end = value.rfind(b"PK\x05\x06")
    directory = struct.unpack_from("<L", value, end + 16)[0]
    for header in _central_headers(value, directory, end):
        offset = struct.unpack_from("<L", value, header + 42)[0]
        struct.pack_into("<L", value, header + 42, offset + len(prefix))
    struct.pack_into("<L", value, end + 16, directory + len(prefix))
    target.write_bytes(prefix + value)


def _insert_and_rebase_wheel_gap(path: Path, gap: bytes) -> None:
    target = path / "probe_package-1.2.3-py3-none-any.whl"
    value = bytearray(target.read_bytes())
    end = value.rfind(b"PK\x05\x06")
    directory = struct.unpack_from("<L", value, end + 16)[0]
    headers = _central_headers(value, directory, end)
    gap_at = struct.unpack_from("<L", value, headers[1] + 42)[0]
    for header in headers[1:]:
        offset = struct.unpack_from("<L", value, header + 42)[0]
        struct.pack_into("<L", value, header + 42, offset + len(gap))
    struct.pack_into("<L", value, end + 16, directory + len(gap))
    target.write_bytes(value[:gap_at] + gap + value[gap_at:])


def _nul_first_wheel_name(path: Path, location: str) -> None:
    target = path / "probe_package-1.2.3-py3-none-any.whl"
    value = bytearray(target.read_bytes())
    end = value.rfind(b"PK\x05\x06")
    directory = struct.unpack_from("<L", value, end + 16)[0]
    name = directory + 46 if location == "central" else _first_local_name(value, directory)
    value[name + 13] = 0
    target.write_bytes(value)


def _first_local_name(value: bytearray, directory: int) -> int:
    offset = int.from_bytes(value[directory + 42 : directory + 46], "little")
    return offset + 30


def _central_headers(value: bytearray, start: int, end: int) -> tuple[int, ...]:
    headers: list[int] = []
    while start < end:
        headers.append(start)
        lengths = struct.unpack_from("<HHH", value, start + 28)
        start += 46 + sum(lengths)
    return tuple(headers)


def _empty_gzip_member(extra: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    payload = compressor.compress(b"") + compressor.flush()
    header = b"\x1f\x8b\x08\x04" + bytes(6) + struct.pack("<H", len(extra)) + extra
    return header + payload + struct.pack("<LL", 0, 0)


def _rename_first_tar_header(path: Path, name: str) -> None:
    target = path / "probe_package-1.2.3.tar.gz"
    value = bytearray(gzip.decompress(target.read_bytes()))
    encoded = name.encode()
    value[:100] = encoded + bytes(100 - len(encoded))
    value[148:156] = b" " * 8
    value[148:156] = f"{sum(value[:512]):06o}\0 ".encode()
    target.write_bytes(gzip.compress(value))


def _write_pax_sdist(path: Path, *, hidden_bytes: int) -> None:
    target = path / "probe_package-1.2.3.tar.gz"
    info = tarfile.TarInfo("probe_package-1.2.3/PKG-INFO")
    info.pax_headers = {"comment": "x" * hidden_bytes}
    info.size = len(_metadata())
    with tarfile.open(target, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(_metadata()))


def _tar_file(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = 0o644
    archive.addfile(info, io.BytesIO(content))


def _metadata() -> bytes:
    return b"Metadata-Version: 2.4\nName: probe-package\nVersion: 1.2.3\n"


def _fail_getmembers(_archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    raise AssertionError("getmembers materializes the full tar inventory")


def _fail_zip_materialization(_archive: zipfile.ZipFile) -> None:
    raise AssertionError("ZipFile materialized the central directory before policy")
