"""Bounded VPK parsing, independent of the permissive third-party index reader."""
import hashlib
import os
import struct
import zlib
from dataclasses import dataclass, field

from .vpk_reader import _path_encodings


@dataclass
class Entry:
    extension: bytes
    directory: bytes
    name: bytes
    path: str
    crc: int
    preload_offset: int
    preload_size: int
    data_offset: int
    data_size: int


@dataclass
class Inspection:
    entries: list[Entry] = field(default_factory=list)
    repairs: list[str] = field(default_factory=list)


def _fail(reason):
    raise ValueError(f"地图有问题，无法部署：{reason}")


def _read(source, length, end):
    if length < 0 or source.tell() + length > end:
        _fail("VPK 目录或文件内容被截断")
    value = source.read(length)
    if len(value) != length:
        _fail("VPK 文件内容不完整")
    return value


def _cstring(source, end):
    value = bytearray()
    while True:
        byte = _read(source, 1, end)
        if byte == b"\0":
            return bytes(value)
        value.extend(byte)
        if len(value) > 4096:
            _fail("VPK 目录路径过长")


def _decode_path(raw):
    for encoding in _path_encodings():
        try:
            path = raw.decode(encoding).replace("\\", "/")
            break
        except UnicodeDecodeError:
            continue
    else:
        _fail("VPK 路径编码无法识别")
    if path.startswith("/") or ".." in path.split("/") or ":" in path:
        _fail("VPK 内部路径不安全")
    return path


def _chunks(source, offset, length):
    source.seek(offset)
    while length:
        block = source.read(min(length, 1024 * 1024))
        if not block:
            _fail("VPK 文件内容不完整")
        length -= len(block)
        yield block


def _md5(source, offset, length):
    digest = hashlib.md5()
    for block in _chunks(source, offset, length):
        digest.update(block)
    return digest.digest()


def inspect_vpk(path, *, allow_repair=False, max_content_bytes=1024 * 1024 * 1024):
    """Check structure and every payload; tolerate only unambiguous index repairs.

    EOF is never a string terminator. Only a missing outermost tree terminator,
    after all inner lists have closed, can be reconstructed without guessing.
    Payload corruption, unsafe/duplicate paths and missing chunks are rejected.
    """
    result = Inspection()
    size = os.path.getsize(path)
    if size > max_content_bytes:
        _fail("VPK 超过单文件大小限制")
    with open(path, "rb") as source:
        magic, version, tree_size = struct.unpack("<III", _read(source, 12, size))
        if magic != 0x55AA1234 or version not in (1, 2):
            _fail("不是受支持的 VPK v1/v2 文件")
        if version == 2:
            data_size, archive_hash_size, self_hash_size, signature_size = struct.unpack(
                "<IIII", _read(source, 16, size)
            )
            if archive_hash_size % 28 or self_hash_size != 48:
                _fail("VPK v2 校验区长度错误")
            if 28 + tree_size + data_size + archive_hash_size + self_hash_size + signature_size != size:
                _fail("VPK v2 数据区或校验区长度不符")
        header_size = source.tell()
        tree_end = header_size + tree_size
        if not tree_size or tree_end > size:
            _fail("VPK 目录长度错误或目录被截断")
        data_end = tree_end + data_size if version == 2 else size
        paths = set()
        content_bytes = 0
        while True:
            if source.tell() == tree_end and result.entries:
                result.repairs.append("补全 VPK 目录最外层结束标记")
                break
            extension = _cstring(source, tree_end)
            if not extension:
                if source.tell() < tree_end:
                    # Only zero padding can be discarded; unknown records are not guessed away.
                    for block in _chunks(source, source.tell(), tree_end - source.tell()):
                        if block.strip(b"\0"):
                            _fail("VPK 目录结束后含无法识别的数据")
                    result.repairs.append("移除 VPK 目录结束后的多余空字节")
                break
            if b"/" in extension or b"\\" in extension:
                _fail("VPK 扩展名含路径分隔符")
            while True:
                directory = _cstring(source, tree_end)
                if not directory:
                    break
                while True:
                    name = _cstring(source, tree_end)
                    if not name:
                        break
                    if b"/" in name or b"\\" in name:
                        _fail("VPK 文件名含路径分隔符")
                    raw_path = (directory + b"/" if directory != b" " else b"") + name
                    if extension != b" ":
                        raw_path += b"." + extension
                    entry_path = _decode_path(raw_path)
                    normalized = "/".join(p for p in entry_path.lower().split("/") if p not in ("", "."))
                    if not normalized or normalized in paths:
                        _fail(f"VPK 存在重复或歧义路径：{entry_path}")
                    paths.add(normalized)
                    crc, preload, archive, offset, length, marker = struct.unpack(
                        "<IHHIIH", _read(source, 18, tree_end)
                    )
                    if marker != 0xFFFF:
                        _fail(f"VPK 条目结束标记错误：{entry_path}")
                    if archive != 0x7FFF:
                        _fail("仅支持完整单文件 VPK，不能部署依赖外部分卷的地图")
                    if tree_end + offset + length > data_end:
                        _fail(f"VPK 文件内容越过数据区：{entry_path}")
                    # Shared ranges must not amplify a small upload into unbounded I/O or output.
                    content_bytes += preload + length
                    if content_bytes > max_content_bytes:
                        _fail("VPK 资源总大小超过单文件限制，无法安全校验或重新打包")
                    preload_offset = source.tell()
                    _read(source, preload, tree_end)
                    result.entries.append(Entry(extension, directory, name, entry_path, crc,
                                                preload_offset, preload, tree_end + offset, length))
        if not result.entries:
            _fail("VPK 内没有文件")
        if result.repairs and not allow_repair:
            _fail("；".join(result.repairs) + "，须先修复并重新打包")
        # Verify content even for repair candidates. Never recalculate a bad CRC to accept corrupt data.
        for entry in result.entries:
            checksum = 0
            for offset, length in ((entry.preload_offset, entry.preload_size),
                                   (entry.data_offset, entry.data_size)):
                for block in _chunks(source, offset, length):
                    checksum = zlib.crc32(block, checksum)
            if checksum & 0xFFFFFFFF != entry.crc:
                _fail(f"文件 CRC 校验失败，无法安全修复：{entry.path}")
        if version == 2:
            hashes_at = data_end + archive_hash_size
            source.seek(hashes_at)
            hashes = _read(source, 48, size)
            actual = (_md5(source, header_size, tree_size)
                      + _md5(source, data_end, archive_hash_size)
                      + _md5(source, 0, hashes_at + 32))
            if actual != hashes:
                _fail("VPK v2 校验和不匹配，无法安全修复")
            block_bytes = 0
            for position in range(data_end, hashes_at, 28):
                source.seek(position)
                archive, offset, length, checksum = struct.unpack('<III16s', _read(source, 28, hashes_at))
                block_bytes += length
                if archive != 0x7FFF or offset + length > data_size or block_bytes > max_content_bytes:
                    _fail("VPK v2 分块校验记录越界或依赖外部分卷")
                if _md5(source, tree_end + offset, length) != checksum:
                    _fail("VPK v2 分块校验和不匹配")
            if signature_size:
                if result.repairs:
                    _fail("带签名的 VPK 无法自动重新打包")
                source.seek(hashes_at + 48)
                key_size, = struct.unpack("<I", _read(source, 4, size))
                _read(source, key_size, size)
                sig_size, = struct.unpack("<I", _read(source, 4, size))
                _read(source, sig_size, size)
                if source.tell() != size:
                    _fail("VPK 签名区长度错误")
    return result


def repack_vpk(source_path, output_path, inspection, max_size_bytes):
    """Write a canonical v1 tree, streaming all original resource bytes unchanged.

    No extraction to disk: Unicode/legacy encodings, long names and file/directory
    name collisions must not cause missing resources. Preserve the locked output inode.
    """
    groups = {}
    for entry in inspection.entries:
        groups.setdefault(entry.extension, {}).setdefault(entry.directory, []).append(entry)
    tree_size = 1
    for extension, directories in groups.items():
        tree_size += len(extension) + 2
        for directory, entries in directories.items():
            tree_size += len(directory) + 2
            tree_size += sum(len(entry.name) + 1 + 18 for entry in entries)
    total_size = sum(e.preload_size + e.data_size for e in inspection.entries)
    if tree_size > 0xFFFFFFFF or total_size > 0xFFFFFFFF:
        _fail("重新打包后的 VPK 超过格式大小上限")
    if 12 + tree_size + total_size > max_size_bytes:
        _fail("重新打包后的 VPK 超过单文件大小限制")
    ordered = []
    with open(source_path, "rb") as source, open(output_path, "wb") as output:
        output.write(struct.pack("<III", 0x55AA1234, 1, tree_size))
        offset = 0
        for extension, directories in groups.items():
            output.write(extension + b"\0")
            for directory, entries in directories.items():
                output.write(directory + b"\0")
                for entry in entries:
                    length = entry.preload_size + entry.data_size
                    output.write(entry.name + b"\0")
                    output.write(struct.pack("<IHHIIH", entry.crc, 0, 0x7FFF, offset, length, 0xFFFF))
                    offset += length
                    ordered.append(entry)
                output.write(b"\0")
            output.write(b"\0")
        output.write(b"\0")
        for entry in ordered:
            for offset, length in ((entry.preload_offset, entry.preload_size),
                                   (entry.data_offset, entry.data_size)):
                for block in _chunks(source, offset, length):
                    output.write(block)
