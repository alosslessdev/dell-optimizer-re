#!/usr/bin/env python3
"""Parse a raw SMBIOS dump for Dell type-0xDA "Calling Interface" tables.

Accept:
  * a dmidecode --dump-bin file (entry point + structure table), or
  * a bare SMBIOS structure table (e.g. the SMBiosData byte array read from
    root\\wmi MSSmBios_RawSMBiosTables).

Prints, per 0xDA table: command I/O address/code, the supported-commands bitmask
(with class 1 "tokens" and class 8 "battery info ex" highlighted) and every token
(ID/location/value). Battery tokens:
  0x0341 PrimarilyAC  0x0342 Adaptive  0x0343 Custom  0x0346 Standard  0x0347 Express
  0x0349 CustomChargeStart  0x034A CustomChargeEnd
  0x0374/0x0375 = Advanced-Charge disable/enable (observed in the Windows app; not used by Linux)
"""
import struct
import sys

KNOWN = {
    0x0341: "BAT_PRI_AC_MODE", 0x0342: "BAT_ADAPTIVE_MODE", 0x0343: "BAT_CUSTOM_MODE",
    0x0346: "BAT_STANDARD_MODE", 0x0347: "BAT_EXPRESS_MODE",
    0x0349: "BAT_CUSTOM_CHARGE_START", 0x034A: "BAT_CUSTOM_CHARGE_END",
    0x0374: "ADV_CHARGE_DISABLE(app)", 0x0375: "ADV_CHARGE_ENABLE(app)",
    0x007D: "BRIGHTNESS", 0x01E1: "KBD_LED_OFF", 0x01E2: "KBD_LED_ON",
    0x02EA: "KBD_LED_AUTO_25", 0x02EB: "KBD_LED_AUTO_50", 0x02EC: "KBD_LED_AUTO_75",
    0x02F6: "KBD_LED_AUTO_100", 0x0451: "KBD_LED_AC",
}
BATTERY_MODE_TOKENS = (0x0341, 0x0342, 0x0343, 0x0346, 0x0347)


def table_offset(data):
    if data[:4] in (b"_SM_", b"_SM3"):
        if data[:4] == b"_SM3":
            return struct.unpack_from("<Q", data, 0x10)[0], struct.unpack_from("<I", data, 0x0C)[0]
        return struct.unpack_from("<I", data, 0x18)[0], struct.unpack_from("<H", data, 0x1C)[0]
    return 0, len(data)


def parse_tokens(blob):
    """blob starts at the structure header (type, len, handle...)."""
    if len(blob) < 11 or blob[0] != 0xDA:
        return None
    length = blob[1]
    if length < 17:
        return None
    io_addr, io_code = struct.unpack_from("<HB", blob, 4)
    supported = struct.unpack_from("<I", blob, 7)[0]
    ntok = (length - 11) // 6
    tokens = []
    for i in range(ntok):
        off = 11 + i * 6
        if off + 6 > len(blob):
            break
        tid, loc, val = struct.unpack_from("<HHH", blob, off)
        if tid == 0x0000 and loc == 0x0000 and val == 0x0000:
            break  # terminator
        tokens.append((tid, loc, val))
    return {"io_addr": io_addr, "io_code": io_code, "supported": supported, "tokens": tokens}


def walk(data, start, max_len):
    off = start
    found = 0
    end = min(len(data), start + max_len) if max_len else len(data)
    while off + 4 <= end:
        stype, length = data[off], data[off + 1]
        if length < 4:
            break
        if stype == 0x7F:  # end-of-table
            break
        blob = data[off:off + length]
        if stype == 0xDA:
            t = parse_tokens(blob)
            if t:
                found += 1
                print(f"\n[type 0xDA #{found}] at file offset 0x{off:X}")
                print(f"  command I/O address : 0x{t['io_addr']:04X}")
                print(f"  command I/O code    : 0x{t['io_code']:02X}")
                print(f"  supported commands  : 0x{t['supported']:08X} "
                      f"(binary {t['supported']:032b})")
                print(f"    class 1 (tokens)  : {'YES' if t['supported'] & (1 << 1) else 'no'}")
                print(f"    class 8 (battery) : {'YES' if t['supported'] & (1 << 8) else 'no'}")
                mode = [k for k in BATTERY_MODE_TOKENS if any(tok[0] == k for tok in t["tokens"])]
                print(f"  battery mode tokens : {len(mode)}/5 "
                      f"({'charge control available' if mode else 'NO charge control'})")
                print(f"  battery level tokens: "
                      f"{'start+end present' if all(any(tok[0] == k for tok in t['tokens']) for k in (0x0349, 0x034A)) else 'missing'}")
                print(f"  tokens ({len(t['tokens'])}):")
                for tid, loc, val in t["tokens"]:
                    name = KNOWN.get(tid, "")
                    print(f"    0x{tid:04X} loc=0x{loc:04X} val=0x{val:04X}  {name}")
        # skip formatted area + strings (until double NUL)
        off += length
        while off + 1 < end and not (data[off] == 0 and data[off + 1] == 0):
            off += 1
        off += 2
    return found


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: parse_smbios_da.py <dump.bin>")
    data = open(sys.argv[1], "rb").read()
    start, max_len = table_offset(data)
    found = walk(data, start, max_len)
    if not found:
        print("no type-0xDA table found")
        sys.exit(2)
    print(f"\n{found} table(s) parsed")


if __name__ == "__main__":
    main()
