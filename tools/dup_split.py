#!/usr/bin/env python3
"""Split the payload overlay out of the Dell Update Package EXE.

The DUP is a PE32+ launcher with a 7-Zip archive appended after the last section.
Usage: dup_split.py <dup.exe> <out.7z>
"""
import struct
import sys

SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"


def overlay_offset(path):
    with open(path, "rb") as f:
        f.seek(0x3C)
        pe = struct.unpack("<I", f.read(4))[0]
        f.seek(pe + 6)
        nsec = struct.unpack("<H", f.read(2))[0]
        f.seek(pe + 20)
        opt_size = struct.unpack("<H", f.read(2))[0]
        sec_off = pe + 24 + opt_size
        end = 0
        for i in range(nsec):
            f.seek(sec_off + i * 40)
            s = f.read(40)
            _vsz, _va, rsz, ro = struct.unpack("<IIII", s[8:24])
            end = max(end, ro + rsz)
        return end


def main():
    src, out = sys.argv[1], sys.argv[2]
    start = overlay_offset(src)
    with open(src, "rb") as f:
        f.seek(start)
        probe = f.read(1 << 20)
    idx = probe.find(SEVEN_ZIP_MAGIC)
    if idx < 0:
        sys.exit(f"no 7z signature found in overlay at 0x{start:X}")
    start += idx
    with open(src, "rb") as f, open(out, "wb") as o:
        f.seek(start)
        while True:
            b = f.read(1 << 24)
            if not b:
                break
            o.write(b)
    print(f"wrote {out} from 0x{start:X}")


if __name__ == "__main__":
    main()
