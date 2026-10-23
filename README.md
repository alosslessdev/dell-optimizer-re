# Dell Optimizer 6.3.5.0 — reverse-engineering notes

Findings from a static reverse-engineering study of the **Dell Optimizer 6.3.5.0** application
installer (Dell Update Package `GJ7NN`, Windows x64) and of **Linux 7.2.9** support for the same
battery features.

This repository contains **analysis and tooling only**. It does **not** contain Dell binaries,
extracted application files, decompiled source, or Ghidra dumps — see [NOTICE.md](NOTICE.md).
To reproduce anything you must obtain the installer yourself from Dell and comply with its license
terms. Reference artifact (for matching your copy):

```
file : Dell-Optimizer-Application_GJ7NN_WIN64_6.3.5.0_A00.exe
size : 796,601,680 bytes
sha256: 144970f8260f076c7e334ceeacfd56cae423c531375febfa124712bff4402d01
```

## Key findings

| Doc | Finding |
|---|---|
| [docs/00-extraction.md](docs/00-extraction.md) | The package is three nested containers: Dell Update Package (PE + appended 7-Zip) → InstallShield `ISSetupStream` v4 (custom XOR/nibble-rotate + zlib, keyed from the entry name) → four MSIs. Includes reproducible extractors. |
| [docs/01-architecture.md](docs/01-architecture.md) | .NET 10 app: Unified-Agent plugin framework (`Dell.Enterprise.Client.Framework.*`), feature plugins (`Dell.Optimizer.Plugin.*`), WPF power UI (`Dell.UUE.*`), TechHub Platform subagents (`C:\Program Files\Dell\DTP`), plus the `DellInstrumentation.sys` kernel driver. |
| [docs/02-battery-charge-levels.md](docs/02-battery-charge-levels.md) | **Battery charge levels**: UI slider → `ISystemPowerConfiguration.SetBatteryCustomChargeModeAsync` → `IPowerManagement` → `DSIS` → `BiosIntfAgent.ExecuteDACI(cbClass=8, cbSelect=19, AdvanceBatteryConfig{m_nChargingMode=5, start, stop})` → `BiosIntfWrapper.dll` → `BIOSIntf.dll` → WMI-ACPI `ROOT\WMI!WMI_Query.DoBFn` → SMBIOS type 0xDA SMI. Reads use `cbSelect=18`, `m_nBatteryCommand=3`; BIOS echoes clamped limits in `cbRes3`. Includes the full function-level trace, interlocks, and read-only battery-status math. |
| [docs/04-battery-adjacent-features.md](docs/04-battery-adjacent-features.md) | Dynamic Charge (DNN model `Dnn.exe`, BMU feature extraction), Intelligent Battery Extender, Peak Shift, Advanced Charge (mode 7, weekday working-hours bitmaps), DTP battery telemetry. |
| [docs/05-native-bios-interface.md](docs/05-native-bios-interface.md) | Native layer: 254 exports across `BiosIntfWrapper.dll`, `BIOSIntf.dll` (two builds), `DBUtilAccessLib_Win64.dll`, `Dell.TechHub.NativeLibraryWrapper.dll`; `DellInstrumentation.sys` IOCTLs (`\\.\Dell_Instrumentation`, MSR/MMIO/SMI); the charge-level ABI buffer and dispatch addresses. |
| [docs/07-linux-kernel-battery-support.md](docs/07-linux-kernel-battery-support.md) | **Linux equivalent**: `dell-laptop` exposes `charge_types` (Standard/Fast/Trickle/Adaptive/Custom) and `charge_control_start/end_threshold` (50–95 / 55–100, min-diff 5) by writing SMBIOS tokens 0x0341–0x0347 / 0x0349–0x034A over the Dell SMBIOS calling interface (ACPI-WMI GUID `A80593CE-…` or `dcdbas`/SMM). No Advanced Charge / Peak Shift / Dynamic Charge support. Userspace can issue the app's class-8 calls via `/dev/wmi/dell-smbios` with `CAP_SYS_RAWIO`. |
| [docs/08-model-and-capability-gating.md](docs/08-model-and-capability-gating.md) | Machine gating: installer + runtime model-ID regex (CY25/CY26), CustomerType from the model-ID line, SKU allow/block lists with `AnySKU` thresholds; chassis checks; firmware capability probes; panel-ID-gated color profiles; plugin dependency gates. Inspiron 15 3535 case study included. |
| [docs/10-agent-handoff.md](docs/10-agent-handoff.md) | **Continuation runbook** for verifying everything on a physical Dell machine (Windows + Linux probes, decision matrix, safe charge-level test, what evidence to record). |

## Tools (MIT, self-contained)

| Tool | Purpose |
|---|---|
| `tools/dup_split.py` | Split the 7-Zip payload out of a Dell Update Package PE |
| `tools/iss_stream_extract.py` | InstallShield `ISSetupStream` v4 extractor (port of ISx's format logic; ISx is MIT — attribution included) |
| `tools/msi_extract.py` | MSI table parser + cabinet extraction with real long names, directories, x64/ARM64 split |
| `tools/dup_split.py`, `tools/make_inventory.py`, `tools/unpack_all.sh` | End-to-end extraction pipeline |
| `tools/gen_catalog.py`, `tools/decompile_all.sh` | Bulk ILSpy decompilation + member catalog generation (for your own analysis) |
| `tools/probe_windows.ps1` | Read-only Windows probe: model/SKU/chassis/BIOS, battery, Dell Optimizer presence, gating verdict, optional SMBIOS 0xDA dump |
| `tools/probe_linux.sh` | Read-only Linux probe: DMI, Dell drivers, BAT0 attributes, 0xDA token table; optional safe charge-threshold test |
| `tools/gating_verdict.py` | Applies the app's model-ID/SKU gating rules to a given product name/SKU |
| `tools/parse_smbios_da.py` | Parses a raw SMBIOS dump for Dell type-0xDA calling-interface tables (tokens + supported classes) |

## Reproduce the analysis

```bash
# 1. obtain the installer yourself, place it in input/
sha256sum input/Dell-Optimizer-Application_GJ7NN_WIN64_6.3.5.0_A00.exe   # must match above

# 2. unpack everything (DUP -> 7z -> ISSetupStream -> MSIs)
bash tools/unpack_all.sh --no-decompile

# 3. optional: decompile (needs .NET SDK + `dotnet tool install --global ilspycmd`)
bash tools/unpack_all.sh
```

The extraction steps are fast (~2 minutes). Full decompilation of the 1,582 managed binaries takes
roughly two hours and produces the working tree referenced by the evidence paths in the docs.

## Continue on the target machine

`docs/10-agent-handoff.md` is written so another agent (or you) can pick up on the physical Dell
machine: it lists exactly which values to collect, how to decide whether the unit is eligible and
whether its firmware exposes the battery tokens, how to test a charge threshold safely and restore
it, and which evidence to record. Start with:

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File tools/probe_windows.ps1
```
```sh
# Linux
sudo bash tools/probe_linux.sh            # read-only
sudo bash tools/probe_linux.sh --test-charge 80   # writes + restores, see doc
```

## Evidence paths

Docs cite paths such as `decompiled/<Assembly>/<Type>.cs`, `extract/...`, and
`ghidra/decompiled_*.c`. Those are **local working artifacts** produced by the tools and are not
distributed here; the assembly/type/method identifiers are stable and can be found by anyone who
unpacks the public installer with `tools/unpack_all.sh`.

## Session archive

[session-archive/](session-archive/) holds the sanitized transcript of the reverse-engineering
session that produced these notes: archive built with the `omp-archive` plugin, with artifacts,
secrets, absolute paths and decompiled-source excerpts removed.

## License

* Tooling: MIT (see [LICENSE](LICENSE)).
* Documentation: CC BY 4.0 (see [LICENSE-docs.md](LICENSE-docs.md)).
* Third-party attributions and legal notes: [NOTICE.md](NOTICE.md).
