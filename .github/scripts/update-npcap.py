#!/usr/bin/env python3
"""Refresh EasyTier's Npcap DLLs and MSVC import libraries from official releases."""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from urllib.request import urlopen
from zipfile import ZipFile

BASE = "https://npcap.com/dist"
ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "easytier" / "third_party"


def u16(data: bytes, pos: int) -> int:
    return struct.unpack_from("<H", data, pos)[0]


def u32(data: bytes, pos: int) -> int:
    return struct.unpack_from("<I", data, pos)[0]


def u64(data: bytes, pos: int) -> int:
    return struct.unpack_from("<Q", data, pos)[0]


def architecture(path: Path) -> str:
    """Inspect PE Machine and ARM64X CHPE metadata, not NSIS extraction names."""
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"not a DLL: {path}")
    pe = u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"invalid PE signature: {path}")
    machine = u16(data, pe + 4)
    optional = pe + 24
    optional_size = u16(data, pe + 20)
    magic = u16(data, optional)
    if magic == 0x20B:
        image_base = u64(data, optional + 24)
        directories = optional + 112
        count = u32(data, optional + 108)
    elif magic == 0x10B:
        image_base = u32(data, optional + 28)
        directories = optional + 96
        count = u32(data, optional + 92)
    else:
        raise ValueError(f"unsupported optional header: {path}")

    def rva_offset(rva: int) -> int:
        headers_size = u32(data, optional + 60)
        if rva < headers_size:
            return rva
        sections = optional + optional_size
        for i in range(u16(data, pe + 6)):
            section = sections + 40 * i
            virtual_size, va, raw_size, raw = struct.unpack_from("<IIII", data, section + 8)
            if va <= rva < va + max(virtual_size, raw_size):
                if rva - va >= raw_size:
                    raise ValueError(f"uninitialized RVA in {path}")
                return raw + rva - va
        raise ValueError(f"unmapped PE RVA in {path}")

    hybrid = False
    if machine == 0xAA64 and magic == 0x20B and count > 10:
        config_dir = directories + 10 * 8
        if config_dir + 8 > optional + optional_size:
            raise ValueError(f"truncated PE directory: {path}")
        config_rva, config_size = struct.unpack_from("<II", data, config_dir)
        if config_rva and config_size >= 0xD0:
            config = rva_offset(config_rva)
            if u32(data, config) >= 0xD0:
                chpe_va = u64(data, config + 0xC8)
                if chpe_va:
                    if chpe_va < image_base:
                        raise ValueError(f"invalid CHPE pointer: {path}")
                    metadata = rva_offset(chpe_va - image_base)
                    if u32(data, metadata) not in (1, 2):
                        raise ValueError(f"unknown CHPE metadata: {path}")
                    hybrid = True

    result = {(0x014C, False): "x86", (0x8664, False): "x64",
              (0xAA64, False): "arm64", (0xAA64, True): "arm64x"}.get((machine, hybrid))
    if result is None:
        raise ValueError(f"unsupported architecture {machine:#x} (hybrid={hybrid}): {path}")
    return result


def classify_dlls(folder: Path) -> dict[str, Path]:
    candidates = sorted((p for p in folder.rglob("*")
                         if p.is_file() and p.name.lower().startswith("packet")
                         and p.suffix.lower() == ".dll"), key=lambda p: str(p).lower())
    if not candidates:
        raise ValueError("no Packet*.dll files in installer")

    matches: dict[str, list[Path]] = defaultdict(list)
    for path in candidates:
        arch = architecture(path)
        name = path.name.lower()
        if arch == "x64" and name == "packet_x64.dll":
            role = "x64-sidecar"
        elif arch == "arm64" and name == "packet_arm64.dll":
            role = "arm64-sidecar"
        elif arch in ("x86", "x64", "arm64x"):
            role = arch
        else:
            raise ValueError(f"unexpected DLL ({arch}): {path}")
        matches[role].append(path)
        print(f"{arch:7} {role:13} {path.relative_to(folder)}")

    required = ("x86", "x64", "arm64x", "arm64-sidecar", "x64-sidecar")
    for role in required:
        if len(matches[role]) != 1:
            raise ValueError(f"expected exactly one {role} DLL, found {matches[role]}")
    return {role: matches[role][0] for role in required}


def sdk_library(folder: Path, *parts: str) -> Path:
    suffix = tuple(p.casefold() for p in parts)
    matches = [p for p in folder.rglob("*") if p.is_file()
               and tuple(x.casefold() for x in p.parts[-len(parts):]) == suffix]
    if len(matches) != 1 or not matches[0].stat().st_size:
        raise ValueError(f"expected exactly one SDK {'/'.join(parts)}; got {matches}")
    return matches[0]


def resolve_versions(npcap: str, sdk: str) -> tuple[str, str]:
    if "latest" in (npcap, sdk):
        with urlopen(BASE + "/", timeout=30) as response:
            index = response.read().decode("utf-8", errors="replace")
        for key, pattern in (("npcap", r'npcap-(\d+(?:\.\d+)+)\.exe'),
                             ("sdk", r'npcap-sdk-(\d+(?:\.\d+)+)\.zip')):
            if (key == "npcap" and npcap == "latest") or (key == "sdk" and sdk == "latest"):
                versions = re.findall(pattern, index)
                if not versions:
                    raise ValueError(f"unable to discover latest {key} version")
                version = max(versions, key=lambda v: tuple(map(int, v.split("."))))
                if key == "npcap":
                    npcap = version
                else:
                    sdk = version
    for version in (npcap, sdk):
        if not re.fullmatch(r"\d+(?:\.\d+)+", version):
            raise ValueError(f"invalid version: {version!r}")
    return npcap, sdk


def download(url: str, destination: Path) -> None:
    print(f"Downloading {url}")
    with urlopen(url, timeout=120) as source, destination.open("wb") as output:
        shutil.copyfileobj(source, output)


def update(npcap: str, sdk: str) -> None:
    if shutil.which("7z") is None:
        raise RuntimeError("7z is required (Ubuntu package: 7zip)")
    npcap, sdk = resolve_versions(npcap, sdk)
    print(f"Npcap {npcap}; SDK {sdk}")
    with tempfile.TemporaryDirectory(prefix="easytier-npcap-") as temp:
        folder = Path(temp)
        exe = folder / "npcap.exe"
        zip_path = folder / "npcap-sdk.zip"
        extracted = folder / "installer"
        sdk_folder = folder / "sdk"
        extracted.mkdir()
        sdk_folder.mkdir()
        download(f"{BASE}/npcap-{npcap}.exe", exe)
        download(f"{BASE}/npcap-sdk-{sdk}.zip", zip_path)
        # -aou keeps same-name NSIS resources without overwriting.
        # The generated names are intentionally NOT used for architecture selection.
        subprocess.run(["7z", "x", "-y", "-aou", f"-o{extracted}", str(exe)],
                       check=True, stdout=subprocess.DEVNULL)
        with ZipFile(zip_path) as archive:
            archive.extractall(sdk_folder)

        dll = classify_dlls(extracted)
        changes = {
            OUTPUT / "i686/Packet.dll": dll["x86"],
            OUTPUT / "x86_64/Packet.dll": dll["x64"],
            OUTPUT / "arm64/Packet.dll": dll["arm64x"],
            OUTPUT / "arm64/Packet_arm64.dll": dll["arm64-sidecar"],
            OUTPUT / "arm64/Packet_x64.dll": dll["x64-sidecar"],
            OUTPUT / "i686/Packet.lib": sdk_library(sdk_folder, "Lib", "Packet.lib"),
            OUTPUT / "x86_64/Packet.lib": sdk_library(sdk_folder, "Lib", "x64", "Packet.lib"),
            OUTPUT / "arm64/Packet.lib": sdk_library(sdk_folder, "Lib", "ARM64", "Packet.lib"),
        }
        # Validate every input before changing tracked files.
        for target, source in changes.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            print(f"Updated {target.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("npcap_version", nargs="?", default="latest")
    parser.add_argument("sdk_version", nargs="?", default="latest")
    args = parser.parse_args()
    try:
        update(args.npcap_version, args.sdk_version)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
