# 00 — Unpacking the installer (reproducible)

Source: `input/Dell-Optimizer-Application_GJ7NN_WIN64_6.3.5.0_A00.exe`
(796,601,680 bytes, PE32+ x64; originally delivered at `~/Downloads/` and moved into the project folder).
Everything below was produced on Linux; all tools/scripts are in `work/`.

## Layer 1 — Dell Update Package (DUP) shell

* `file`: PE32+ GUI x86-64, 7 sections; sections end at file offset `0x471E00`.
* Overlay at `0x471E00` begins with the **7-Zip signature** (`7z\xBC\xAF\x27\x1C`) → a 791,940,944-byte
  archive (`work/payload.7z`, md5 `1de7b798e7c402da6b34085c1a9959a8`).
* The stub is Dell's "Update Package" UI (HTML-driven; `Mup.xml` behavior table with `/apponly`,
  `/driveronly`, `/extractall`, `/passthrough`, ...).
* Archive contents (3 files): `Mup.xml`, `package.xml`, `DellOptimizer.exe` (795,412,960 bytes).
* Extracted with `bsdtar -xf work/payload.7z -C extract/`.

## Layer 2 — InstallShield SetupSuite (`ISSetupStream` v4)

`DellOptimizer.exe` is a PE32 i386 InstallShield 2022/2023 launcher (FileVersion 6.3.5.0 /
engine 29.0.0.111). Its overlay starts at `0x1C2800` with the magic `ISSetupStream\0` —
**not** readable by 7-Zip (`7zz l -t#` fails).

Format (reverse-engineered from lifenjoiner/ISx v0.3.11 and validated byte-for-byte):

```
IS_HEADER (46 bytes): SIG[14]="ISSetupStream\0", num_files u16 (=218), type u32 (=4), x4[8], x5 u16, x6[16]
per file (type 4): IS_FILE_ATTRIBUTES_X (24 bytes) + 24 unknown bytes + UTF-16LE name (filename_len bytes)
  IS_FILE_ATTRIBUTES_X = { filename_len u32, encoded_flags u32, x3[2], file_len u32, x5[8], is_unicode_launcher u16 }
payload: XOR-obfuscated (+ optional zlib)
```

Obfuscation:
* key seed = UTF-8 of the file's *wide* name; `key[i] = seed[i] ^ MAGIC[i % 4]`, `MAGIC = 13 35 86 07`
* `decode_byte(b, k) = ~(k ^ rol4(b))` (rol4 = 4-bit nibble rotate)
* `ISSetupStream`: key phase restarts every 1024 bytes (`decode_data_ustrm`), cipher applied in
  1024-byte blocks when `encoded_flags & 4` (all 218 files here have `flags = 0x6`); `flags & 2` without
  bit 4 means a second full-file decode pass (old method) — not used in this package
* `is_unicode_launcher != 0` → payload is a zlib stream (215 of 218 files)

Extractor: `work/iss_stream_extract.py` (numpy-vectorized port of ISx logic; 15 s for 791 MB):

```
python3 work/iss_stream_extract.py extract/DellOptimizer.exe extract/is_payload
```

Output: `extract/is_payload/` (892 MB) — log in `docs/00-extraction-log.txt`. 218 files:
redist bundles (windowsdesktop-runtime-10 x64/arm64, aspnetcore-runtime-10, VC_redist),
Intel Context Sensing zips, four MSIs, InstallShield runtime (`ISSetup.dll`, `ISRT.dll`, `Setup.inx`,
`Setup.xml`, `Setup64.exe`, `ClrWrap.dll`), PowerShell deployment scripts
(`ModularDeployment.ps1`, `HardwareChecks.ps1`, `RemoveLegacyApps.ps1`, `UninstallDPM.ps1`, ...).

## Layer 3 — the MSIs

| MSI | GUID dir | Output tree |
|---|---|---|
| `Dell Optimizer.msi` (97.7 MB) | `{A861556A-7676-4F68-8CA9-992EECE14211}` | `extract/app` (+ `extract/app_arm64`) |
| `Dell.Core.Services.Installer_64bit.msi` | `{8BDD9DC3-...}` | `extract/pkg_coreservices` |
| `Dell AppCore.msi` | `{3674DF8F-...}` | `extract/pkg_appcore` |
| `Dell UserSubAgent.msi` | `{F51A237C-...}` | `extract/pkg_usersubagent` |

**Gotcha**: `7zz x <msi>` mangles long file names (truncates to 28 chars, dedupes with `1`/`2`
suffixes) and flattens directories. Real names/paths live in the MSI tables. Extraction is therefore
done in two steps:

1. `7zz x -tCompound` pulls the raw OLE streams: `!File`, `!Component`, `!Directory`, `!_Columns`,
   `!_StringPool`, `!_StringData`, `!_Tables`, `Data1.cab`.
2. `work/msi_extract.py` parses the tables and unpacks `Data1.cab`:

```
python3 work/msi_extract.py extract/msi_rawstreams extract/cabtmp extract/app work/7zz/7zz
```

Table streams are **column-major** (each column = N rows stacked in `_Columns.Number` order;
strings = 2-byte pool ids, int2 = 2 bytes, int4 = 4 bytes — in the File table only `FileSize` is int4).
Verified: File=2501 rows, Component=119, Directory=128; 2501/2501 files extracted, 0 missing.
x64 and ARM64 components install to identical paths (selected via
`Component.Condition = "ProcessorArchitecture=..."`), so the extractor segregates them into
`extract/app` (x64) and `extract/app_arm64`; the same for the other MSIs.

`extract/app/_msi_file_manifest.txt` lists `arch, relative path, MSI File key, size, status` for
every file.

## Result

```
extract/app/SourceDir/Program Files 64/Dell/DellOptimizer   # the application (2501 files x64)
extract/app_arm64/...                                        # ARM64 twin
extract/pkg_coreservices/SourceDir/Program Files 64/Dell/DTP # Dell TechHub Platform (subagents, DBUtilDriver)
extract/pkg_appcore/SourceDir/Program Files 64/Dell/DellOptimizer/Console  # thick client + systray
extract/pkg_usersubagent/SourceDir/Program Files 64/Dell/PlatformUserSubAgent
```

## Decompilation coverage (known gaps)

`work/decompile_all.sh` decompiled every unique managed binary to `decompiled_all/<Name>__<hash8>/`:
1582 assemblies produced output (1 failure: `DotNext.dll` from AnalyticsSubAgent — retried manually into
`decompiled_all/DotNext.Threading__retry/`, which is complete except two types ILSpy cannot render:
`DotNext.Collections.Generic.Dictionary.KeysGetter`/`ValuesGetter`). ~450 further directories are
resource-only satellite assemblies (`*.resources.dll`) with no IL to document. Catalogs were generated for
the 1131 assemblies that contain code: 246,654 types / 1,535,797 members (`docs/03-function-catalog.md`).

## Tooling produced (kept in `work/`)

| Tool | Purpose |
|---|---|
| `work/iss_stream_extract.py` | ISSetupStream v4 extractor (also handles legacy `InstallShield` overlay) |
| `work/msi_extract.py` | MSI table parser + cabinet extractor with long names/dirs/arch split |
| `work/7zz/` | 7-Zip 24.09 (used for `-tCompound` stream extraction and `.cab`) |
| `work/decompile_all.sh` | ilspycmd bulk decompile of every unique managed binary |
