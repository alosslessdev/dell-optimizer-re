# Agent handoff — continue on the target Dell machine

This repository documents a static study of Dell Optimizer 6.3.5.0 (Windows) and Linux 7.2.9
support for the same battery features. The next phase runs **on the physical target machine**
(reference case: Dell **Inspiron 15 3535**, 2023 consumer AMD laptop). This file is the runbook.

## 0. Rules

* **Read-only first.** Collect everything before writing anything (`probe_*` default is read-only).
* **Record before you change.** Any write to charge thresholds must be preceded by recording the
  current values, and restored afterwards (the probe scripts do this automatically).
* **Do not publish** Dell binaries, extracted files, decompiled source, Ghidra dumps, serial numbers,
  service tags, or Windows product keys. Publish only probe output with identifiers redacted.
* Run as Administrator / root only for the specific read operations that need it.
* This is interoperability research; check Dell's EULA and your local law before publishing results.

## 1. What is already known (do not re-derive)

* Charge-level write path (Windows): class-8 DACI `SetBatteryInfoEx` (select 19) with
  `AdvanceBatteryConfig{m_nChargingMode=5, m_nStartChrgLimit, m_nStopChrgLimit}`; read path select 18,
  command 3. See `docs/02-battery-charge-levels.md`.
* Linux equivalent: tokens 0x0349/0x034A (start/end) + 0x0341-0x0347 (modes) via
  `dell-smbios`; sysfs `charge_types`, `charge_control_start_threshold`,
  `charge_control_end_threshold` on `BAT0`. See `docs/07-linux-kernel-battery-support.md`.
* Firmware gate: SMBIOS type 0xDA calling-interface table must contain the battery tokens; the app
  additionally needs class 8 in the supported-commands bitmask. See docs/02 §3.6, docs/07 §8.
* App eligibility gate: vendor string, model-ID regex, CustomerType from the model-ID line, then
  SKU allow/block lists with `AnySKU` thresholds. Inspiron 3535 family passes; **its SKU was not
  resolvable from public data** — determining it is task #1. See `docs/08-...` §8.

## 2. Task list

| # | Task | Tool / command | Deliverable |
|---|---|---|---|
| 1 | Identify the machine | `tools/probe_windows.ps1` (or `probe_linux.sh`) | manufacturer, product name, SKU, chassis, BIOS version |
| 2 | App eligibility verdict | `probe_windows.ps1` prints it, or `python3 tools/gating_verdict.py --product "<name>" --sku <SKU>` | PASS/FAIL + reason |
| 3 | Firmware capability | `probe_windows.ps1 -DumpSmbios smbios.bin` then `python3 tools/parse_smbios_da.py smbios.bin`; Linux: `probe_linux.sh` (uses `dmidecode --dump-bin`) | supported-class bitmask (bit 8?), BAT_* tokens present? |
| 4 | Windows app check | Does the power/battery card appear? Is `DellOptimizerService` running? Does `%ProgramData%` log show charge-mode calls? | UI + log evidence |
| 5 | Linux check | `ls /sys/class/power_supply/BAT0/`; `dmesg | grep -iE 'dell|smbios'`; `lsmod | grep dell` | attrs present/absent + driver state |
| 6 | Safe functional test | `probe_linux.sh --test-charge 80` (Linux) or app UI / CLI (Windows) | before/after values, read-back, restore proof |
| 7 | Write findings | new `docs/11-target-machine-findings.md` | evidence table + verdicts, identifiers redacted |

## 3. Windows probe details

```powershell
# read-only
powershell -ExecutionPolicy Bypass -File tools/probe_windows.ps1

# also dump raw SMBIOS for 0xDA analysis (read-only)
powershell -ExecutionPolicy Bypass -File tools/probe_windows.ps1 -DumpSmbios smbios.bin
python tools\parse_smbios_da.py smbios.bin
```

The probe collects:
* `Win32_ComputerSystem` (Manufacturer/Model), `Win32_SystemEnclosure.ChassisTypes`,
  `Win32_BIOS` (SMBIOSBIOSVersion/ReleaseDate), `root\wmi MS_SystemInformation`
  (SystemManufacturer/SystemProductName/SystemSKU);
* `Win32_Battery` / `BatteryStatus` and, if present, `root\wmi BatteryStaticData`/`BatteryFullChargedCapacity`;
* Dell Optimizer presence: install dir, `DellOptimizer*` services, uninstall registry entry;
* the app-gating verdict (same rules as `docs/08`);
* optional raw SMBIOS dump (`MSSmBios_RawSMBiosTables.SMBiosData`).

Windows charge-level checks (only if the card exists):
* UI: Dell Optimizer → Power → Battery settings (charge mode + custom range).
* CLI: `do-cli.exe configure SystemPowerConfiguration.ChargingMode Custom` (note: switching to
  Custom re-applies the currently reported limits).
* Record the read-back values after any change; the BIOS may clamp them.

## 4. Linux probe details

```sh
# read-only (run as root for dmidecode dump)
sudo bash tools/probe_linux.sh

# safe functional test: record -> set end threshold 80 -> read back -> restore
sudo bash tools/probe_linux.sh --test-charge 80
```

Checks performed:
* `/sys/class/dmi/id/{sys_vendor,product_name,product_sku,chassis_type,bios_version,bios_date}`;
* `dmidecode -t 0,1,3` (system/BIOS/chassis) and `dmidecode --dump-bin` for the 0xDA parse;
* `lsmod`/`modinfo` for `dell_laptop`, `dell_smbios`, `dell_smbios_wmi`, `dell_smbios_smm`,
  `dcdbas`, `dell_wmi_ddv`; `dmesg | grep -iE 'dell|smbios'`;
* `/sys/class/power_supply/BAT0/` contents; current `charge_types`, start/end thresholds;
* kernel config for `CONFIG_DELL_LAPTOP`, `CONFIG_DELL_SMBIOS`, `CONFIG_DELL_SMBIOS_WMI/SMM`;
* verdict: attrs present? tokens present in 0xDA? transport registered?

## 5. Decision matrix (expected outcomes)

| Observation | Interpretation | Next |
|---|---|---|
| App verdict FAIL (SKU blocked / below AnySKU) | model not in this release's allow-list | do not install; record SKU + reason |
| App verdict PASS, battery card absent | platform passes but firmware lacks charge capability | verify 0xDA tokens / class 8; record |
| App verdict PASS, card present, writes work | charge levels programmable | record modes/limits, clamping behaviour |
| Linux: `charge_types` present | firmware exposes BAT_* mode tokens; charge control works | test start/end, record clamp values |
| Linux: attrs absent but `dell_laptop` loaded | no BAT_* tokens (or no transport) | parse 0xDA dump; check `dmesg`/modules |
| Linux: attrs absent, `dell_laptop` absent | chassis/vendor DMI mismatch or module not loaded | check `dmi/id`, `modprobe dell_laptop`, config |

## 6. Safe charge-test procedure (Linux)

1. Record: `cat charge_types`, `cat charge_control_start_threshold`, `cat charge_control_end_threshold`.
2. Keep AC connected; keep the battery above the start threshold.
3. `echo 80 | sudo tee /sys/class/power_supply/BAT0/charge_control_end_threshold`
4. Read back; note the value the firmware stored (may be clamped, e.g. 80 → 80).
5. Optionally test start: set 55, then 60, observing the kernel's min-diff-5 enforcement.
6. Restore the recorded values (or `100` for end / `0` or previous start).
7. `dmesg | tail` and record any errors.

Do not loop writes; each write is an SMBIOS call into firmware.

## 7. Evidence to record (and publish)

* Probe outputs with **service tag/serial redacted**.
* `supportedCmds` bitmask and the token list from the 0xDA dump (IDs/locations/values).
* Linux: sysfs listing, module list, relevant dmesg lines.
* Windows: app version, UI state screenshot description, log excerpts (redacted).
* Before/after charge thresholds + read-back.

**Never publish**: the installer, MSIs, DLLs/EXEs, decompiled `.cs`, Ghidra `.c`, raw SMBIOS dumps
containing serial numbers, license keys.
