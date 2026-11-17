"""Read the Mach-O facts a device-free IPA scan can defend.

The parser is enough for the header flags, linked libraries, the encryption
command, and a bounded search for stack-canary and ARC marker strings. It is
not a disassembler. ``otool`` is consulted when it is on ``PATH`` and is
skipped when it is missing or fails.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

MH_EXECUTE = 0x2
MH_PIE = 0x00200000

LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x18
LC_LAZY_LOAD_DYLIB = 0x20
LC_ENCRYPTION_INFO = 0x21
LC_REEXPORT_DYLIB = 0x1F
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LOAD_UPWARD_DYLIB = 0x23
LC_REQ_DYLD = 0x80000000

_DYLIB_COMMANDS = {
    LC_LOAD_DYLIB,
    LC_ID_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_LAZY_LOAD_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
}
_CPU = {
    7: "x86",
    12: "arm",
    0x01000007: "x86_64",
    0x0100000C: "arm64",
}
_FILETYPE = {1: "object", 2: "execute", 6: "dylib", 8: "bundle"}

_MAX_COMMANDS = 512
_MAX_MARKER_SCAN = 4 * 1024 * 1024
_MAX_STRING_SAMPLE = 1024 * 1024
_CANARY_MARKERS = (b"stack_chk_fail", b"stack_chk_guard")
_ARC_MARKERS = (b"objc_release", b"objc_storeStrong")
_OBJC_MARKERS = (b"_OBJC_CLASS_",)


@dataclass
class MachOFacts:
    """What the built-in parser could prove about one binary."""

    parsed: bool = False
    format: str = "unknown"
    cpu: str | None = None
    filetype: str | None = None
    pie: bool | None = None
    encrypted: bool | None = None
    stack_canary: bool | None = None
    arc: bool | None = None
    objc: bool = False
    linked: list[str] = field(default_factory=list)
    string_sample: bytes = b""
    notes: list[str] = field(default_factory=list)
    otool: str = "absent"


def inspect_macho(data: bytes) -> MachOFacts:
    """Parse a thin or fat Mach-O. Unrecognized bytes return ``parsed=False``."""
    facts = MachOFacts()
    if len(data) < 8:
        facts.notes.append("binary is too small to be a Mach-O")
        return facts
    magic = struct.unpack_from(">I", data, 0)[0]
    slices: list[tuple[int, int]] = []
    if magic in {FAT_MAGIC, FAT_CIGAM}:
        facts.format = "fat"
        endian = ">" if magic == FAT_MAGIC else "<"
        count = _u32(data, 4, endian)
        if count is None or count <= 0 or count > 16:
            facts.notes.append("fat header has an implausible architecture count")
            return facts
        cursor = 8
        for _ in range(count):
            if cursor + 20 > len(data):
                facts.notes.append("fat architecture list is truncated")
                break
            _cpu, _sub, offset, size, _align = struct.unpack_from(endian + "IIIII", data, cursor)
            if offset < 0 or size < 0 or offset + size > len(data):
                facts.notes.append("fat architecture points outside the file")
            else:
                slices.append((offset, size))
            cursor += 20
    else:
        facts.format = "thin"
        slices.append((0, len(data)))

    parsed_any = False
    samples: list[bytes] = []
    for offset, size in slices:
        slice_facts = _parse_slice(data, offset, size)
        if not slice_facts.parsed:
            facts.notes.extend(slice_facts.notes)
            continue
        parsed_any = True
        _merge(facts, slice_facts)
        if slice_facts.string_sample:
            samples.append(slice_facts.string_sample)
    facts.parsed = parsed_any
    if not parsed_any and not facts.notes:
        facts.notes.append("binary is not a Mach-O this parser understands")
    facts.string_sample = _join_samples(samples)
    facts.linked = list(dict.fromkeys(facts.linked))[:32]
    return facts


def otool_probe(data: bytes) -> dict[str, object]:
    """Ask ``otool`` for the PIE flag and a stack-canary symbol, when it exists.

    A missing binary, a non-zero exit, or a timeout returns a status the caller
    can record. The built-in parser result stays in place either way.
    """
    if shutil.which("otool") is None:
        return {"status": "absent"}
    descriptor, raw_path = tempfile.mkstemp(prefix="maya-macho-")
    path = Path(raw_path)
    try:
        os.write(descriptor, data[:_MAX_MARKER_SCAN])
        os.close(descriptor)
        descriptor = -1
        header = _run_otool(["-hv", str(path)])
        symbols = _run_otool(["-I", str(path)])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "failed", "error": exc.__class__.__name__}
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)
    if header is None and symbols is None:
        return {"status": "failed", "error": "otool failed"}
    pie: bool | None = None
    if header:
        for line in header.splitlines():
            if "PIE" in line.split():
                pie = True
                break
        if pie is None and "MH_MAGIC" in header:
            pie = False
    canary: bool | None = None
    if symbols and "stack_chk_fail" in symbols:
        canary = True
    return {"status": "ok", "pie": pie, "stack_canary": canary}


def apply_otool(facts: MachOFacts, probe: dict[str, object]) -> None:
    """Fill gaps from ``otool``. Do not override a flag the built-in parser proved."""
    status = str(probe.get("status") or "failed")
    facts.otool = status if status in {"absent", "ok", "failed"} else "failed"
    if status != "ok":
        if probe.get("error"):
            facts.notes.append(f"otool was not used ({probe['error']})")
        return
    facts.notes.append("otool confirmed the header or indirect symbols")
    if facts.pie is None and isinstance(probe.get("pie"), bool) and facts.filetype in {None, "execute"}:
        facts.pie = probe["pie"]
        facts.parsed = True
        if facts.filetype is None:
            facts.filetype = "execute"
    if facts.stack_canary is None and probe.get("stack_canary") is True:
        facts.stack_canary = True


def _merge(target: MachOFacts, slice_facts: MachOFacts) -> None:
    target.format = target.format if target.format != "unknown" else slice_facts.format
    target.cpu = target.cpu or slice_facts.cpu
    if slice_facts.filetype == "execute":
        target.filetype = "execute"
    elif target.filetype is None:
        target.filetype = slice_facts.filetype
    if slice_facts.filetype == "execute" and slice_facts.pie is not None:
        target.pie = slice_facts.pie if target.pie is None else (target.pie and slice_facts.pie)
    target.encrypted = _or_bool(target.encrypted, slice_facts.encrypted)
    target.stack_canary = _or_unknown(target.stack_canary, slice_facts.stack_canary)
    target.arc = _or_unknown(target.arc, slice_facts.arc)
    target.objc = target.objc or slice_facts.objc
    target.linked.extend(slice_facts.linked)
    target.notes.extend(slice_facts.notes)


def _or_bool(left: bool | None, right: bool | None) -> bool | None:
    if left is True or right is True:
        return True
    if left is False or right is False:
        return False
    return None


def _or_unknown(left: bool | None, right: bool | None) -> bool | None:
    """True wins. False is kept only when every parsed slice agrees it is absent."""
    if left is True or right is True:
        return True
    if left is None:
        return right
    if right is None:
        return None
    return left and right


def _parse_slice(data: bytes, offset: int, size: int) -> MachOFacts:
    facts = MachOFacts(format="thin")
    if size < 28 or offset + 28 > len(data):
        facts.notes.append("Mach-O slice is truncated")
        return facts
    magic = _u32(data, offset, "<")
    if magic == MH_MAGIC_64:
        endian, header_size = "<", 32
    elif magic == MH_MAGIC:
        endian, header_size = "<", 28
    elif magic == MH_CIGAM_64:
        endian, header_size = ">", 32
    elif magic == MH_CIGAM:
        endian, header_size = ">", 28
    else:
        facts.notes.append("slice magic is not Mach-O")
        return facts
    if offset + header_size > len(data):
        facts.notes.append("Mach-O header is truncated")
        return facts
    _cpu_type, _cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(endian + "IIIIII", data, offset + 4)
    facts.cpu = _CPU.get(_cpu_type, f"cpu_{_cpu_type}")
    facts.filetype = _FILETYPE.get(filetype, f"type_{filetype}")
    if filetype == MH_EXECUTE:
        facts.pie = bool(flags & MH_PIE)
    else:
        facts.pie = None
    if ncmds < 0 or sizeofcmds < 0 or ncmds > _MAX_COMMANDS:
        facts.notes.append("load-command count is implausible")
        return facts
    commands_end = offset + header_size + sizeofcmds
    slice_end = min(len(data), offset + size)
    if commands_end > slice_end:
        facts.notes.append("load commands extend past the slice")
        commands_end = slice_end
    cursor = offset + header_size
    walked = 0
    encrypted = False
    saw_command_end = True
    crypt_ranges: list[tuple[int, int]] = []
    string_ranges: list[tuple[int, int]] = []
    while walked < ncmds and cursor + 8 <= commands_end:
        cmd, cmdsize = struct.unpack_from(endian + "II", data, cursor)
        if cmdsize < 8 or cursor + cmdsize > commands_end:
            facts.notes.append("stopped at a truncated load command")
            saw_command_end = False
            break
        base = cmd & ~LC_REQ_DYLD
        body_end = cursor + cmdsize
        if base in _DYLIB_COMMANDS and cmdsize >= 24:
            name_off = _u32(data, cursor + 8, endian) or 0
            name_at = cursor + name_off
            if cursor < name_at < body_end:
                raw = data[name_at:body_end].split(b"\x00", 1)[0]
                try:
                    name = raw.decode("utf-8", errors="replace")[:180]
                except UnicodeError:
                    name = ""
                if name:
                    facts.linked.append(name)
                    if "libobjc" in name:
                        facts.objc = True
        elif base in {LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64} and cmdsize >= 20:
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", data, cursor + 8)
            if cryptid:
                encrypted = True
                if cryptsize > 0 and cryptoff >= 0:
                    crypt_ranges.append((cryptoff, cryptoff + cryptsize))
        elif base == LC_SYMTAB and cmdsize >= 24:
            _symoff, _nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", data, cursor + 8)
            if strsize > 0 and stroff >= 0:
                string_ranges.append((stroff, min(strsize, _MAX_STRING_SAMPLE)))
        cursor += cmdsize
        walked += 1
    facts.encrypted = encrypted if saw_command_end or encrypted else None
    visible, covered_encrypted = _visible_bytes(data, offset, slice_end, string_ranges, crypt_ranges)
    facts.string_sample = visible[:_MAX_STRING_SAMPLE]
    if any(marker in facts.string_sample for marker in _OBJC_MARKERS):
        facts.objc = True
    facts.stack_canary = _marker_state(
        facts.string_sample,
        _CANARY_MARKERS,
        encrypted=encrypted,
        covered_encrypted=covered_encrypted,
        complete=slice_end - offset <= _MAX_MARKER_SCAN,
    )
    if facts.objc:
        facts.arc = _marker_state(
            facts.string_sample,
            _ARC_MARKERS,
            encrypted=encrypted,
            covered_encrypted=covered_encrypted,
            complete=slice_end - offset <= _MAX_MARKER_SCAN,
        )
    else:
        facts.arc = None
    if encrypted:
        facts.notes.append("cryptid is set; markers inside the encrypted range were not assessed")
    if slice_end - offset > _MAX_MARKER_SCAN and facts.stack_canary is None and not encrypted:
        facts.notes.append("binary exceeds the marker scan budget; stack canary and ARC were not confirmed")
    facts.parsed = True
    return facts


def _marker_state(
    sample: bytes,
    markers: tuple[bytes, ...],
    *,
    encrypted: bool,
    covered_encrypted: bool,
    complete: bool,
) -> bool | None:
    if any(marker in sample for marker in markers):
        return True
    if encrypted or covered_encrypted or not complete:
        return None
    return False


def _visible_bytes(
    data: bytes,
    slice_off: int,
    slice_end: int,
    string_ranges: list[tuple[int, int]],
    crypt_ranges: list[tuple[int, int]],
) -> tuple[bytes, bool]:
    """Return plaintext bytes with encrypted spans removed.

    String-table offsets are tried as file offsets and as slice-relative
    offsets. Fat slices in the wild use both.
    """
    chunks: list[bytes] = []
    covered = False
    seen: set[int] = set()
    ranges = string_ranges or [(0, min(_MAX_MARKER_SCAN, max(slice_end - slice_off, 0)))]
    if not string_ranges and slice_end - slice_off <= _MAX_MARKER_SCAN:
        ranges = [(0, slice_end - slice_off)]
    for start, size in ranges:
        # Load-command offsets are file-absolute in a fat Mach-O and slice-relative
        # in some unpacked slices. Keep both when they land inside this slice.
        for candidate in (start, slice_off + start):
            if candidate in seen or candidate < slice_off or candidate >= slice_end:
                continue
            seen.add(candidate)
            end = min(slice_end, candidate + size, candidate + _MAX_MARKER_SCAN)
            if end <= candidate:
                continue
            blob = bytearray(data[candidate:end])
            for crypt_off, crypt_end in crypt_ranges:
                lo = max(crypt_off, candidate)
                hi = min(crypt_end, end)
                if lo < hi:
                    covered = True
                    for index in range(lo - candidate, hi - candidate):
                        blob[index] = 0
            chunks.append(bytes(blob))
    if not chunks and slice_end > slice_off:
        end = min(slice_end, slice_off + _MAX_MARKER_SCAN)
        blob = bytearray(data[slice_off:end])
        for crypt_off, crypt_end in crypt_ranges:
            lo = max(crypt_off, slice_off)
            hi = min(crypt_end, end)
            if lo < hi:
                covered = True
                for index in range(lo - slice_off, hi - slice_off):
                    blob[index] = 0
        chunks.append(bytes(blob))
    return _join_samples(chunks), covered


def _join_samples(chunks: list[bytes]) -> bytes:
    if not chunks:
        return b""
    joined = b"\x00".join(chunks)
    return joined[:_MAX_STRING_SAMPLE]


def _run_otool(args: list[str]) -> str | None:
    completed = subprocess.run(  # noqa: S603
        ["otool", *args],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout


def _u32(data: bytes, offset: int, endian: str) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from(endian + "I", data, offset)[0]
