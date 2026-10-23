#!/usr/bin/env python3
"""Read or write Dell battery charge configuration through class-8 DACI.

This is the path Dell Optimizer uses on Windows:
  class 8, select 18 = GetBatteryInfoEx
  class 8, select 19 = SetBatteryInfoEx

It is useful on machines where the SMBIOS 0xDA battery tokens exist but have
location 0xffff, so the normal dell-laptop sysfs token path returns EIO.

Requires root (CAP_SYS_RAWIO) and /dev/wmi/dell-smbios.

Examples:
  sudo python3 dell_daci_battery.py read
  sudo python3 dell_daci_battery.py read --battery 1 --json
  sudo python3 dell_daci_battery.py set --mode 5 --start 70 --stop 79 --apply

`set` is a dry run unless --apply is given.  It does not restore by itself;
record the current values and write them back when finished.
"""
import argparse
import fcntl
import json
import os
import struct
import sys

DEV = "/dev/wmi/dell-smbios"
# _IOWR('W', 0, struct dell_wmi_smbios_buffer); sizeof() == 0x34
IOCTL = (3 << 30) | (0x34 << 16) | (ord("W") << 8) | 0
# The request buffer's ext.blength field must be the payload length, not
# the 0x8008-byte WMI buffer size (the firmware rejects the latter).
PAYLOAD_LEN = 0x50

MODE_NAMES = {
    0: "Reserved",
    1: "Standard",
    2: "Express",
    3: "PrimarilyAC",
    4: "Adaptive",
    5: "Custom",
    6: "LongLife",
    7: "Advanced",
}


def read_size(fd):
    raw = os.read(fd, 8)
    if len(raw) != 8:
        raise OSError("short read from %s" % DEV)
    return struct.unpack("<Q", raw)[0]


def daci(fd, size, select, inputs, flags):
    """Issue one class-8 call and return the four output dwords."""
    buf = bytearray(size)
    struct.pack_into("<Q", buf, 0x00, size)
    struct.pack_into("<HH", buf, 0x08, 8, select)
    struct.pack_into("<4I", buf, 0x0C, *inputs)
    struct.pack_into("<4I", buf, 0x1C, 0xFFFFFFFD, 0, 0, 0)
    struct.pack_into("<II", buf, 0x2C, flags, PAYLOAD_LEN)
    fcntl.ioctl(fd, IOCTL, buf, True)
    return struct.unpack_from("<4I", buf, 0x1C)


def read_cfg(fd, size, battery):
    out = daci(fd, size, 18, [(battery << 8) | 3, 0x2C, 0, 0], 0x100)
    status, r2, r3, r4 = out
    return {
        "status": status,
        "mode": r2 & 0xFF,
        "mode_name": MODE_NAMES.get(r2 & 0xFF, "Unknown"),
        "start": (r2 >> 8) & 0xFF,
        "stop": (r2 >> 16) & 0xFF,
        "supported": r3,
        "allow_start": r4 & 0xFF,
        "allow_stop": (r4 >> 8) & 0xFF,
        "granularity": (r4 >> 16) & 0xFF,
        "location": (r4 >> 24) & 0xFF,
    }


def write_cfg(fd, size, battery, mode, start, stop):
    packed = (stop << 16) | (start << 8) | mode
    out = daci(fd, size, 19, [(battery << 8) | 0, packed, 0x2C, 0], 0x10000)
    status, _r2, r3, _r4 = out
    return {
        "status": status,
        "effective_start": r3 & 0xFF,
        "effective_stop": (r3 >> 8) & 0xFF,
    }


def print_cfg(cfg, as_json):
    if as_json:
        print(json.dumps(cfg, sort_keys=True))
        return
    print(
        "mode={mode} ({mode_name}) start={start} stop={stop} "
        "supported=0x{supported:x} allowable={allow_start}..{allow_stop} "
        "granularity={granularity} location={location} status=0x{status:x}".format(**cfg)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--battery", type=int, default=1,
                        help="DACI battery number, 1..16 (default: 1)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_read = sub.add_parser("read", help="read current charge configuration")
    p_read.add_argument("--json", action="store_true", help="machine-readable output")

    p_set = sub.add_parser("set", help="write charge configuration (dry run unless --apply)")
    p_set.add_argument("--mode", type=int, required=True,
                       choices=sorted(MODE_NAMES), help="charge mode (1..7)")
    p_set.add_argument("--start", type=int, default=0,
                       help="custom start limit, percent (mode 5)")
    p_set.add_argument("--stop", type=int, default=0,
                       help="custom stop limit, percent (mode 5)")
    p_set.add_argument("--apply", action="store_true",
                       help="actually write; without this only prints the request")
    p_set.add_argument("--json", action="store_true", help="machine-readable output")

    args = parser.parse_args()
    if not 1 <= args.battery <= 16:
        parser.error("--battery must be 1..16")
    if args.cmd == "set" and not (0 <= args.start <= 100 and 0 <= args.stop <= 100):
        parser.error("--start/--stop must be 0..100")

    try:
        fd = os.open(DEV, os.O_RDWR)
    except OSError as e:
        print("cannot open %s: %s" % (DEV, e), file=sys.stderr)
        return 1

    try:
        size = read_size(fd)
        current = read_cfg(fd, size, args.battery)
        if args.cmd == "read":
            print_cfg(current, args.json)
            return 0 if current["status"] == 0 else 1

        if not args.apply:
            if args.json:
                print(json.dumps({"current": current, "would_write": vars(args)},
                                 sort_keys=True))
            else:
                print("current: ", end="")
                print_cfg(current, False)
                print("would write: mode=%d start=%d stop=%d (add --apply to write)"
                      % (args.mode, args.start, args.stop))
            return 0

        result = write_cfg(fd, size, args.battery, args.mode, args.start, args.stop)
        readback = read_cfg(fd, size, args.battery)
        if args.json:
            print(json.dumps({"write": result, "readback": readback}, sort_keys=True))
        else:
            print("write: status=0x%x effective_start=%d effective_stop=%d"
                  % (result["status"], result["effective_start"], result["effective_stop"]))
            print("readback: ", end="")
            print_cfg(readback, False)
        if result["status"] != 0:
            return 1
        if readback["start"] != result["effective_start"] or readback["stop"] != result["effective_stop"]:
            print("readback does not match the reported effective limits", file=sys.stderr)
            return 1
        return 0
    except OSError as e:
        print("DACI call failed: %s" % e, file=sys.stderr)
        return 1
    finally:
        os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
