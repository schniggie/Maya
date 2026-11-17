"""Minimal Android binary XML reader.

Enough to recover element names and attribute values from an APK's
AndroidManifest and res/xml resources. It does not decompile resources.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field

from maya.static.limits import MAX_POOL_STRING_BYTES, MAX_POOL_STRINGS, ScanLimitError

_RES_XML = 0x0003
_STRING_POOL = 0x0001
_START_ELEMENT = 0x0102
_END_ELEMENT = 0x0103

_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12

_NO_INDEX = 0xFFFFFFFF


@dataclass
class XmlNode:
    name: str
    attrs: dict[str, str | int | bool]
    children: list[XmlNode] = field(default_factory=list)


def parse_binary_xml(data: bytes, *, deadline: float | None = None) -> XmlNode | None:
    """Parse an Android binary XML document into a tree."""
    if len(data) < 8:
        raise ValueError("binary XML is too short")
    chunk_type, header_size, file_size = _chunk_header(data, 0)
    if chunk_type != _RES_XML:
        raise ValueError("not an Android binary XML document")
    limit = min(len(data), file_size if file_size else len(data))
    if header_size < 8 or header_size > limit:
        raise ValueError("binary XML header is invalid")

    strings: list[str] = []
    root: XmlNode | None = None
    stack: list[XmlNode] = []
    pos = header_size
    while pos + 8 <= limit:
        chunk_type, chunk_header_size, chunk_size = _chunk_header(data, pos)
        if chunk_size < 8 or pos + chunk_size > limit:
            break
        if chunk_type == _STRING_POOL and not strings:
            strings = list(_iter_string_pool(data, pos, deadline=deadline, max_strings=50_000))
        elif chunk_type == _START_ELEMENT:
            node = _parse_start_element(data, pos, chunk_header_size, strings)
            if stack:
                stack[-1].children.append(node)
            elif root is None:
                root = node
            stack.append(node)
        elif chunk_type == _END_ELEMENT and stack:
            stack.pop()
        pos += chunk_size
    return root


def parse_string_pool(data: bytes, offset: int, *, deadline: float | None = None) -> list[str]:
    """Parse a ResStringPool chunk. Used for resources.arsc as well as XML."""
    return list(iter_string_pool(data, offset, deadline=deadline))


def iter_string_pool(data: bytes, offset: int, *, deadline: float | None = None, max_strings: int = MAX_POOL_STRINGS):
    """Yield pool strings without retaining the whole pool."""
    return _iter_string_pool(data, offset, deadline=deadline, max_strings=max_strings)


def _chunk_header(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset + 8 > len(data):
        raise ValueError("truncated chunk header")
    return struct.unpack_from("<HHI", data, offset)


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise ValueError("truncated u16")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise ValueError("truncated u32")
    return struct.unpack_from("<I", data, offset)[0]


def _iter_string_pool(data: bytes, offset: int, *, deadline: float | None, max_strings: int):
    chunk_type, header_size, chunk_size = _chunk_header(data, offset)
    if chunk_type != _STRING_POOL:
        raise ValueError("expected a string pool")
    if header_size < 28 or offset + chunk_size > len(data):
        raise ValueError("string pool header is invalid")
    string_count = _u32(data, offset + 8)
    if string_count > max_strings:
        raise ScanLimitError(f"string pool count {string_count} exceeds {max_strings}")
    flags = _u32(data, offset + 16)
    strings_start = _u32(data, offset + 20)
    utf8 = bool(flags & (1 << 8))
    offsets_at = offset + header_size
    if offsets_at + string_count * 4 > offset + chunk_size:
        raise ValueError("string pool offsets overflow the chunk")
    base = offset + strings_start
    if base > offset + chunk_size:
        raise ValueError("string pool data starts outside the chunk")
    for index in range(string_count):
        if deadline is not None and index % 4096 == 0 and time.monotonic() > deadline:
            raise ScanLimitError("static scan exceeded the time budget")
        rel = _u32(data, offsets_at + index * 4)
        yield _read_pool_string(data, base + rel, offset + chunk_size, utf8)


def _read_pool_string(data: bytes, pos: int, end: int, utf8: bool) -> str:
    if pos >= end or pos >= len(data):
        return ""
    if utf8:
        _, pos = _utf8_len(data, pos, end)
        byte_len, pos = _utf8_len(data, pos, end)
        if byte_len > MAX_POOL_STRING_BYTES or pos + byte_len > len(data):
            return ""
        return data[pos : pos + byte_len].decode("utf-8", "replace")
    char_len, pos = _utf16_len(data, pos, end)
    if char_len > MAX_POOL_STRING_BYTES // 2:
        return ""
    byte_len = char_len * 2
    if pos + byte_len > len(data):
        return ""
    return data[pos : pos + byte_len].decode("utf-16-le", "replace")


def _utf8_len(data: bytes, pos: int, end: int) -> tuple[int, int]:
    if pos >= end:
        return 0, pos
    first = data[pos]
    pos += 1
    if first & 0x80 and pos < end:
        first = ((first & 0x7F) << 8) | data[pos]
        pos += 1
    return first, pos


def _utf16_len(data: bytes, pos: int, end: int) -> tuple[int, int]:
    if pos + 2 > end:
        return 0, pos
    first = _u16(data, pos)
    pos += 2
    if first & 0x8000 and pos + 2 <= end:
        first = ((first & 0x7FFF) << 16) | _u16(data, pos)
        pos += 2
    return first, pos


def _pool_value(strings: list[str], index: int) -> str | None:
    if index == _NO_INDEX or index >= len(strings):
        return None
    return strings[index]


def _typed_value(data_type: int, data: int, strings: list[str]) -> str | int | bool | None:
    if data_type == _TYPE_STRING:
        return _pool_value(strings, data)
    if data_type == _TYPE_INT_BOOLEAN:
        return data != 0
    if data_type in {_TYPE_INT_DEC, _TYPE_INT_HEX}:
        return data
    return None


def _parse_start_element(data: bytes, pos: int, header_size: int, strings: list[str]) -> XmlNode:
    if header_size < 16 or pos + 36 > len(data):
        raise ValueError("start element is truncated")
    _ns, name_index = struct.unpack_from("<II", data, pos + 16)
    attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, pos + 24)
    attrs: dict[str, str | int | bool] = {}
    attr_at = pos + 16 + attr_start
    for index in range(attr_count):
        entry = attr_at + index * attr_size
        if attr_size < 20 or entry + 20 > len(data):
            break
        _attr_ns, attr_name, raw_value, _value_size, _res0, data_type, typed = struct.unpack_from(
            "<IIIHBBI", data, entry
        )
        key = _pool_value(strings, attr_name) or f"attr_{attr_name}"
        value = _typed_value(data_type, typed, strings)
        if value is None:
            value = _pool_value(strings, raw_value)
        if value is not None:
            attrs[key] = value
    return XmlNode(name=_pool_value(strings, name_index) or "unknown", attrs=attrs)
