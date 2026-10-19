# NOTICE / legal

## No proprietary material is distributed here

This repository contains **original analysis and tooling**. It intentionally does **not** include,
and must not be used to redistribute:

* Dell installers, MSIs, CABs, DLLs, EXEs, drivers, configuration files or any other Dell binary;
* decompiled, disassembled or otherwise reconstructed source code of Dell software
  (ILSpy output, Ghidra output, pseudocode dumps);
* extracted application resources, assets, logs or data files;
* serial numbers, service tags, license keys or other unit-specific identifiers.

The reference installer is publicly available from Dell. Obtain your own copy and verify it:

```
Dell-Optimizer-Application_GJ7NN_WIN64_6.3.5.0_A00.exe
size   796,601,680 bytes
sha256 144970f8260f076c7e334ceeacfd56cae423c531375febfa124712bff4402d01
```

## Trademarks and affiliation

Dell, Dell Optimizer, Inspiron, Latitude, Precision, OptiPlex, Vostro, XPS and Alienware are
trademarks of Dell Inc. or its subsidiaries. This project is **not affiliated with, endorsed by, or
sponsored by Dell**. All trademarks belong to their respective owners.

## Nature of the work

The findings come from static analysis of a publicly downloadable installer and from the public
Linux kernel source. No technical protection measures were circumvented; no keys, credentials or
activation data were extracted. Reconstructed interface definitions (structures, constants, token
IDs, GUIDs, sysfs/CLI names) are documented for interoperability and research purposes.

## Your obligations

* Review Dell's end-user license terms and the law of your jurisdiction before using or publishing
  derived material. Reverse-engineering and publication rights differ by country and by contract;
  this file is **not legal advice**.
* Do not install modifications on hardware you do not own or administer.
* Charge-threshold changes are written to firmware. Use the record/change/read-back/restore procedure
  in `docs/10-agent-handoff.md`.

## Third-party components

See [tools/THIRD_PARTY.md](tools/THIRD_PARTY.md). In short:

* `tools/iss_stream_extract.py` is a port of the format logic from
  [lifenjoiner/ISx](https://github.com/lifenjoiner/ISx) (MIT, © 2017 lifenjoiner);
* decompilation in the reproduction pipeline uses [ILSpy `ilspycmd`](https://github.com/icsharpcode/ILSpy) (MIT);
* quotes from the Linux kernel (7.2.9) are short excerpts under GPL-2.0, cited in place;
* Ghidra (Apache-2.0) was used as a tool; no Ghidra output is distributed.

## No warranty

The analysis is provided "as is", without warranty of any kind. Firmware behaviour may differ by
model, BIOS version and configuration; verify on your own hardware.
