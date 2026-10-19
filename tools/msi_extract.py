#!/usr/bin/env python3
"""Extract an MSI (as raw OLE streams pulled out by 7-Zip -tCompound) with real
long file names and directory structure.

MSI table streams are column-major: each column is N rows wide, stacked in
_Columns 'Number' order. Strings are 2-byte string-pool ids; int2 = 2 bytes,
int4 = 4 bytes (only FileSize in the File table).
"""
import os, struct, subprocess, sys

STREAMS = sys.argv[1]          # dir with !File, !Directory, !Component, !_StringPool, !_StringData, Data1.cab
CABDIR = sys.argv[2]           # where to unpack Data1.cab
OUT = sys.argv[3]              # output tree
SEVEN = sys.argv[4]            # 7zz binary


def load_strings():
    sp = open(os.path.join(STREAMS, '!_StringPool'), 'rb').read()
    sd = open(os.path.join(STREAMS, '!_StringData'), 'rb').read()
    n = (len(sp) - 4) // 4
    strings = {0: ''}
    off = 0
    for i in range(n):
        l, _rc = struct.unpack_from('<HH', sp, 4 + 4 * i)
        strings[i + 1] = sd[off:off + l].decode('cp1252', 'replace')
        off += l
    return strings


def parse_columns(strings):
    raw = open(os.path.join(STREAMS, '!_Columns'), 'rb').read()
    nrow = len(raw) // 8
    # column-major: Table(nrow x u16), Number(nrow x u16), Name(nrow x u16), Type(nrow x u16)
    tabs = struct.unpack_from(f'<{nrow}H', raw, 0)
    nums = struct.unpack_from(f'<{nrow}H', raw, nrow * 2)
    names = struct.unpack_from(f'<{nrow}H', raw, nrow * 4)
    types = struct.unpack_from(f'<{nrow}H', raw, nrow * 6)
    cols = {}
    for i in range(nrow):
        cols.setdefault(strings[tabs[i]], []).append((nums[i], strings[names[i]], types[i]))
    return {t: sorted(v) for t, v in cols.items()}


def parse_table(strings, cols, table, colspec):
    raw = open(os.path.join(STREAMS, '!' + table), 'rb').read()
    schema = cols[table]
    widths = [4 if colspec.get(name) == 'i4' else 2 for _, name, _ in schema]
    nrow = len(raw) // sum(widths)
    assert nrow * sum(widths) == len(raw), (table, len(raw), sum(widths))
    out = []
    off = 0
    percol = []
    for (_, name, _), w in zip(schema, widths):
        fmt = f'<{nrow}{"I" if w == 4 else "H"}'
        vals = struct.unpack_from(fmt, raw, off)
        percol.append((name, vals))
        off += nrow * w
    for i in range(nrow):
        row = {}
        for name, vals in percol:
            v = vals[i]
            row[name] = strings[v] if colspec.get(name, 's') == 's' else v
        out.append(row)
    return out


def main():
    strings = load_strings()
    cols = parse_columns(strings)
    files = parse_table(strings, cols, 'File', {'FileSize': 'i4', 'Attributes': 'i2', 'Sequence': 'i2'})
    comps = parse_table(strings, cols, 'Component', {'Attributes': 'i2'})
    dirs = parse_table(strings, cols, 'Directory', {})
    print(f'tables: File={len(files)} Component={len(comps)} Directory={len(dirs)}')

    # directory id -> full path (DefaultDir may be "short|long"; take long)
    dparent = {d['Directory']: d.get('Directory_Parent') for d in dirs}
    dname = {d['Directory']: d.get('DefaultDir', d['Directory']) for d in dirs}

    def dirname(did):
        parts = []
        seen = set()
        while did and did not in seen:
            seen.add(did)
            n = dname.get(did, did)
            if '|' in n:
                n = n.split('|', 1)[1]
            if n not in ('.', ''):
                parts.append(n)
            did = dparent.get(did)
        return os.path.join(*reversed(parts)) if parts else ''

    compdir = {}
    compcond = {}
    for c in comps:
        compdir[c['Component']] = dirname(c.get('Directory_', ''))
        compcond[c['Component']] = (c.get('Condition') or '').lower()

    # unpack cabinet
    os.makedirs(CABDIR, exist_ok=True)
    subprocess.run([SEVEN, 'x', '-y', '-o' + CABDIR, os.path.join(STREAMS, 'Data1.cab')],
                   check=True, stdout=subprocess.DEVNULL)
    cab_names = {f.lower(): f for f in os.listdir(CABDIR)}

    os.makedirs(OUT, exist_ok=True)
    manifest = []
    missing = 0
    for f in files:
        key = f['File']
        src = cab_names.get(key.lower())
        longname = f.get('FileName', key)
        if '|' in longname:
            longname = longname.split('|', 1)[1]
        comp = f.get('Component_', '')
        arch = 'arm64' if 'arm64' in compcond.get(comp, '') else 'x64'
        root = OUT if arch == 'x64' else OUT + '_arm64'
        rel = os.path.join(compdir.get(comp, ''), longname)
        dst = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if src is None:
            missing += 1
            manifest.append((arch, rel, key, f.get('FileSize'), 'MISSING'))
            continue
        if os.path.exists(dst):
            manifest.append((arch, rel, key, f.get('FileSize'), 'COLLISION'))
        os.replace(os.path.join(CABDIR, src), dst)
        manifest.append((arch, rel, key, f.get('FileSize'), 'ok'))
    with open(os.path.join(OUT, '_msi_file_manifest.txt'), 'w') as m:
        for row in manifest:
            m.write('\t'.join(str(x) for x in row) + '\n')
    print('extracted', len(manifest) - missing, 'missing', missing)


if __name__ == '__main__':
    main()
