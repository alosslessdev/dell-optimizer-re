#!/usr/bin/env python3
"""Classify every extracted DLL/EXE as managed (.NET) or native.

Usage: make_inventory.py <extract_root> <out_dir>
Writes <out_dir>/managed.txt and <out_dir>/native.txt (paths relative to extract_root),
matching what work/decompile_all.sh consumes.
"""
import os
import subprocess
import sys

TREES = ("app/SourceDir", "pkg_coreservices/SourceDir", "pkg_appcore/SourceDir",
         "pkg_usersubagent/SourceDir")


def main():
    root, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    managed, native = [], []
    for tree in TREES:
        for dirpath, _dirs, files in os.walk(os.path.join(root, tree)):
            for name in files:
                if not name.lower().endswith((".dll", ".exe")):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    desc = subprocess.run(["file", "-b", path], capture_output=True,
                                          text=True, timeout=30).stdout
                except Exception:
                    continue
                rel = os.path.relpath(path, root)
                if ".Net assembly" in desc or "Mono/.Net" in desc:
                    managed.append(rel)
                else:
                    native.append(rel)
    managed.sort()
    native.sort()
    with open(os.path.join(outdir, "managed.txt"), "w") as f:
        f.write("\n".join(managed) + "\n")
    with open(os.path.join(outdir, "native.txt"), "w") as f:
        f.write("\n".join(native) + "\n")
    print(f"managed={len(managed)} native={len(native)}")


if __name__ == "__main__":
    main()
