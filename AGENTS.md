# AGENTS.md — continuation guide

You are continuing a reverse-engineering study. This repo holds **analysis + tooling only** (no Dell
binaries, no decompiled source). Read this file first, then `docs/10-agent-handoff.md`.

## Repo map

```
README.md                  findings summary + reproduction
NOTICE.md                  legal/attribution (read before publishing anything)
docs/00-extraction.md      how the installer is packed/unpacked
docs/01-architecture.md    app/process/plugin architecture
docs/02-battery-charge-levels.md   THE charge-level trace (Windows)
docs/04-battery-adjacent-features.md
docs/05-native-bios-interface.md   native exports, IOCTLs, charge ABI
docs/07-linux-kernel-battery-support.md  Linux equivalent + capability probe
docs/08-model-and-capability-gating.md   model/SKU/chassis/firmware gating
docs/10-agent-handoff.md   the runbook for the physical machine
tools/                     extractors, decompiler driver, on-machine probes
```

## Ground truth (do not re-derive)

* Windows charge levels: `ISystemPowerConfiguration.SetBatteryCustomChargeModeAsync` →
  `IPowerManagement` → `DSIS` → `BiosIntfAgent.ExecuteDACI(8, 19, AdvanceBatteryConfig{mode=5,start,stop})`
  → `BiosIntfWrapper.dll` → `BIOSIntf.dll` → WMI `ROOT\WMI!WMI_Query.DoBFn` → SMBIOS 0xDA SMI.
  Read: class 8, select 18, command 3. `docs/02` has the full function map and interlocks.
* Linux: `dell-laptop` writes tokens 0x0349/0x034A (levels) and 0x0341-0x0347 (modes) over
  `dell-smbios` (ACPI-WMI `A80593CE-…` or `dcdbas`/SMM), exposing `charge_types` +
  `charge_control_start/end_threshold` on `BAT0`, **only if the firmware's 0xDA table contains the
  mode tokens**. Kernel clamps: start 50-95, end 55-100, min diff 5. `docs/07`.
* App eligibility: vendor + model-ID regex + CustomerType (from the model-ID's first char) + SKU
  allow/block + `AnySKU` (Commercial 0x0983, Consumer 0x0AF3). `docs/08`.
* The app has **no Advanced Charge / Peak Shift / Dynamic Charge equivalent in Linux**; Long Life
  (mode 6) is firmware/warranty-provisioned and cannot be set by charge levels.

## Next actions (in order)

1. Run `tools/probe_windows.ps1` (or `tools/probe_linux.sh`) on the target machine; keep the output.
2. Determine the unit's `SystemSKU`; run `tools/gating_verdict.py --product "<name>" --sku <SKU>`.
3. Dump SMBIOS and run `tools/parse_smbios_da.py`: is class 8 in `supportedCmds`? Are BAT_* tokens
   present (0x0341-0x0347, 0x0349/0x034A)?
4. On Linux, check `BAT0` attributes; optionally run the safe test
   `sudo bash tools/probe_linux.sh --test-charge 80` (records and restores).
5. Write `docs/11-target-machine-findings.md` with a verdict table and redacted evidence.
6. Update `README.md` if the findings change any stated conclusion.

## Hard rules

* Never commit or publish: installer/MSIs/DLLs/EXEs, decompiled `.cs`, Ghidra `.c`, raw SMBIOS dumps
  with serials, service tags, license keys.
* Charge writes: record → change once → read back → restore. AC connected, battery above start.
* Keep identifiers (assembly/type/method names, token IDs, GUIDs) — those are factual findings.
* Check Dell's EULA and local law before publishing; this is not legal advice.
