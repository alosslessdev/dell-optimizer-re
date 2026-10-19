#!/usr/bin/env python3
"""Extractor for InstallShield 'ISSetupStream' overlay (SetupSuite, InstallShield 2012+).

Faithful Python port of the format logic from lifenjoiner/ISx (ISx.c v0.3.11):
  - IS_HEADER at PE overlay start: "InstallShield\0" or "ISSetupStream\0"
  - per-file IS_FILE_ATTRIBUTES_X (24 bytes) [+24 bytes when type == 4] + UTF-16LE name
  - data obfuscation: key[i] = name_utf8[i] ^ MAGIC[i % 4], MAGIC = 13 35 86 07
    decode_byte(b, k) = ~(k ^ rol4(b))
  - 'ISSetupStream': key phase restarts every 1024 bytes; cipher applied when
    (flags & 4) -> 1024-byte blocks, or 2nd pass when (flags & 2)
  - is_unicode_launcher != 0 -> payload is zlib-wrapped
"""
import os, struct, sys, zlib

import numpy as np

MAGIC = bytes((0x13, 0x35, 0x86, 0x07))
PREFER_BLOCK = 4096 * 64

# decode_byte(b, k) = ~(k ^ rol4(b)) == (~rol4(b)) ^ k  -> LUT + XOR
_R = np.arange(256, dtype=np.uint8)
ROL_INV = np.array([(~(((int(b) << 4) | (int(b) >> 4)) & 0xFF)) & 0xFF for b in range(256)],
                   dtype=np.uint8)


def gen_key(seed: bytes):
    return np.frombuffer(bytes(seed[i] ^ MAGIC[i % 4] for i in range(len(seed))), dtype=np.uint8)


def decode_stream(data: np.ndarray, key: np.ndarray, block: int, ustrm: bool):
    """decode_file() semantics: key phase restarts at every encoded block boundary;
    'ustrm' additionally restarts the key phase every 1024 bytes within the block."""
    kl = len(key)
    if kl == 0:
        return data
    out = np.empty_like(data)
    for off in range(0, len(data), block):
        n = min(block, len(data) - off)
        i = np.arange(n, dtype=np.int64)
        idx = (i % 1024 if ustrm else i) % kl
        out[off:off + n] = ROL_INV[data[off:off + n]] ^ key[idx]
    return out


def pe_overlay_offset(path):
    with open(path, 'rb') as f:
        f.seek(0x3C)
        peoff = struct.unpack('<I', f.read(4))[0]
        f.seek(peoff + 6)
        nsec = struct.unpack('<H', f.read(2))[0]
        f.seek(peoff + 20)
        optsize = struct.unpack('<H', f.read(2))[0]
        end = 0
        for i in range(nsec):
            f.seek(peoff + 24 + optsize + i * 40)
            s = f.read(40)
            _vsz, _va, rsz, ro = struct.unpack('<IIII', s[8:24])
            end = max(end, ro + rsz)
        return end


def main():
    src, dst = sys.argv[1], sys.argv[2]
    os.makedirs(dst, exist_ok=True)
    data_off = pe_overlay_offset(src)
    with open(src, 'rb') as f:
        f.seek(data_off)
        hdr = f.read(46)
        sig = hdr[:14].rstrip(b'\0').decode('ascii', 'replace')
        num_files, typ = struct.unpack_from('<HI', hdr, 14)
        print(f'overlay@0x{data_off:X} sig={sig!r} num_files={num_files} type={typ}')
        assert sig in ('InstallShield', 'ISSetupStream'), sig
        ustrm = sig == 'ISSetupStream'
        pos = data_off + 46
        for idx in range(num_files):
            f.seek(pos)
            ax = f.read(24)
            if len(ax) < 24:
                break
            name_len, flags = struct.unpack_from('<II', ax, 0)
            file_len = struct.unpack_from('<I', ax, 10)[0]
            is_unicode_launcher = struct.unpack_from('<H', ax, 22)[0]
            if typ == 4:
                f.seek(pos + 48)
            else:
                f.seek(pos + 24)
            name_bytes = f.read(name_len)
            name = name_bytes.decode('utf-16-le', 'replace').rstrip('\0')
            seed = name.encode('utf-8')
            pos = f.tell()
            file_data = np.frombuffer(f.read(file_len), dtype=np.uint8).copy()
            pos += file_len

            key = gen_key(seed)
            has4 = flags & 4
            has24 = flags & 6
            decoded = 'none'
            if has4 and has24:
                file_data = decode_stream(file_data, key, 1024, ustrm)
                decoded = 'block1024' + ('+ustrm' if ustrm else '')
            elif has24:  # flags & 2, no bit 4 -> second pass over whole file, old method
                file_data = decode_stream(file_data, key, max(len(file_data), 1), False)
                decoded = 'full-xor'
            inflated = ''
            if is_unicode_launcher:
                try:
                    file_data = np.frombuffer(zlib.decompress(file_data.tobytes()), dtype=np.uint8)
                    inflated = ' +inflate'
                except zlib.error as e:
                    inflated = f' +inflate FAILED({e})'
            rel = name.replace('\\', '/').lstrip('/')
            out = os.path.join(dst, rel)
            os.makedirs(os.path.dirname(out) or dst, exist_ok=True)
            with open(out, 'wb') as o:
                o.write(file_data)
            print(f'[{idx:3d}] 0x{pos - file_len:08X} {file_len:10d} -> {len(file_data):10d} '
                  f'flags=0x{flags:X} ustrmlauncher={is_unicode_launcher} [{decoded}{inflated}] {rel}')


if __name__ == '__main__':
    main()
