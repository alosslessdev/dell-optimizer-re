# Tools

Self-contained helpers to reproduce the extraction/decompilation and to continue the study on a
physical Dell machine. Everything here is MIT-licensed (see `../LICENSE`, `THIRD_PARTY.md`).

## Prerequisites

`python3` (+ `numpy` for `iss_stream_extract.py`), `7-Zip` (`7zz` or `7z` on `PATH`; not bundled),
`bsdtar` recommended for the payload, `file(1)`. Decompilation additionally needs the .NET SDK and
`dotnet tool install --global ilspycmd`.

## Extraction / reproduction

| Tool | Usage |
|---|---|
| `dup_split.py` | `python3 dup_split.py <DUP.exe> payload.7z` — splits the appended 7-Zip payload out of a Dell Update Package |
| `iss_stream_extract.py` | `python3 iss_stream_extract.py <DellOptimizer.exe> <outdir>` — extracts an InstallShield `ISSetupStream` v4 overlay (needs numpy) |
| `msi_extract.py` | `python3 msi_extract.py <raw-stream-dir> <cab-tmp> <outdir> <7zz>` — parses MSI tables (`!File/!Component/!Directory/!_Columns/!_StringPool`) and unpacks `Data1.cab` with real long names, directories and x64/ARM64 separation. First dump the raw streams with `7zz x -tCompound <msi>` |
| `make_inventory.py` | `python3 make_inventory.py <extract-root> <outdir>` — writes `managed.txt`/`native.txt` |
| `unpack_all.sh` | `bash unpack_all.sh [--no-decompile] [--no-catalog]` — full pipeline; expects `../input/Dell-Optimizer-Application_GJ7NN_WIN64_6.3.5.0_A00.exe` |
| `decompile_all.sh` | bulk ILSpy decompilation of every unique managed binary (needs `ilspycmd`) |
| `gen_catalog.py` | generates per-assembly member catalogs from the decompiled trees |

## On-machine probes (continuation)

| Tool | Usage | Writes? |
|---|---|---|
| `probe_windows.ps1` | `powershell -ExecutionPolicy Bypass -File probe_windows.ps1 [-DumpSmbios smbios.bin]` — identity/SKU/chassis/BIOS, battery, Dell Optimizer presence, gating verdict, optional raw SMBIOS dump | no |
| `probe_linux.sh` | `sudo bash probe_linux.sh` — DMI, dmidecode + 0xDA analysis, Dell modules/dmesg, `BAT0` attributes, verdict | no |
| `probe_linux.sh --test-charge 80` | records the current thresholds, sets end=80, tests min-diff, then **restores** | yes (root, auto-restore) |
| `dell_daci_battery.py` | `sudo python3 dell_daci_battery.py --battery 1 read` — reads mode/start/stop via class-8 DACI; `set --mode M --start S --stop T --apply` writes and reads back | yes for `set --apply` (root) |
| `test_daci_threshold.sh` | `sudo bash test_daci_threshold.sh --apply` — records, lowers the stop limit by 1, verifies, then **restores**; refuses non-Custom mode or AC offline unless `--force` | yes (root, auto-restore) |
| `gating_verdict.py` | `python3 gating_verdict.py --product "<name>" --sku <SKU>` — applies the app's vendor/model-ID/CustomerType/SKU rules | no |
| `parse_smbios_da.py` | `python3 parse_smbios_da.py <dump.bin>` — prints Dell type-0xDA calling-interface tables: supported-commands bitmask, battery tokens, values | no |

### Notes

* `parse_smbios_da.py` accepts a `dmidecode --dump-bin` file or a bare SMBIOS structure table (the
  `SMBiosData` byte array from `root\wmi MSSmBios_RawSMBiosTables`).
* The Linux probe's `--test-charge` mode uses a `trap` to restore the recorded values even on error.
  Keep AC connected; do not loop writes.
* `dell_daci_battery.py` is for machines where the 0xDA battery tokens exist but have location `0xffff`,
  so the normal token path returns `EIO`. It uses the same class-8/select-18/19 path as Dell Optimizer.
  `test_daci_threshold.sh` is the safe record/write/read-back/restore harness for it.
* For the patched `dell-laptop` module, install `../patches/dell-laptop-bat1.conf` as
  `/etc/modprobe.d/dell-laptop-bat1.conf` to select `BAT1`.
* Windows `-DumpSmbios` may require an elevated shell for the WMI class.
* Redact service tags/serials before publishing probe output.
