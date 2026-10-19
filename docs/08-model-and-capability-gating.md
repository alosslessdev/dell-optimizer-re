# 08 — How Dell Optimizer gates features by machine (model / chassis / firmware / devices)

Answer to "the app should gate functions or check the laptop model": it does — at four distinct layers,
two of them an explicit **model/SKU allow-list**. All claims below are grounded in the extracted files
(`extract/is_payload/*` from the installer) and the decompiled assemblies (`decompiled*/`).

## 1. Install-time platform gate (installer): model-ID + SKU allow/block list

`extract/is_payload/HardwareChecks.ps1` (392 lines) runs as an InstallShield suite custom action and
computes the suite property **`IS_SUPPORTED_DELL_SYSTEM`** (0/1). Steps:

1. **Vendor check** (`:33-38`): `MS_SystemInformation.SystemManufacturer` must contain
   `"Dell Inc."` or `"Dell Technologies Inc."`, else unsupported.
2. **Model-ID regex on the product name** (`:44-106`) — two naming-rule generations:
   * CY26 (ref `UUE-4617`):
     `^(?<productLine>D|DA|DX|C|P|PW|PR|PV|PE)(?<tier>[SAX9753M])?(?<formFactor>[MRST0-9][0-9])(?<generation>[0-9]{2})(?<cpuVendor>[0-9])$`
   * CY25/legacy (ref `UUE-472`): `^[CDEPQMFR][ABCEV012789][MRST0-9][0-9]{4}$`
   Excluded lines: Chromebooks (`C`), ChengMing (`modelId[1]=='7'`), thin clients (`'9'`).
3. **Customer type** (`Commercial` vs `Consumer`), from the model ID's product-line character — NOT the SKU
   (`:64-96`):
   * CY26: `ModelId[0] == 'D'` → Consumer, anything else → Commercial;
   * CY25: `ModelId[0] ∈ {C, D, E}` → Consumer, else Commercial;
   * legacy product names (no model-ID match): the XML `Allow/SystemFamily` names are matched against the
     product name (`Contains`), Commercial section first then Consumer — the matching section sets the
     CustomerType (`:107-121`, logged as *"Supported System Family: …, customer type: …"*).
4. **Allow/block/AnySKU evaluation against the shipped XML** (`:131-166`):
   * `Hardware/<Commercial|Consumer>/Allow/Platform/SKU` → SKU match ⇒ supported, exit 0
   * `.../Block/Platform/SKU` → SKU match ⇒ unsupported
   * otherwise **hex SKU ≥ `AnySKU`** ⇒ supported (Commercial `0983`, Consumer `0AF3`)

`extract/is_payload/HardwareCheckList.xml` (3.6 KB, comment: *"Add platform allow or block in ascending
order so that SKU comparison logic will not fail"*):

| Section | Contents (shipped 6.3.5.0) |
|---|---|
| `Commercial/Allow/SystemFamily` | Precision, Latitude, OptiPlex |
| `Commercial/Allow/Platform` | e.g. Latitude 3311 (`0971`), Precision 5550 (`097E`), 5820 (`0738`), 7820 (`0739`), 7920 (`073A`), … |
| `Commercial/Block/Platform` | Latitude 3410 (`09F1`), 3510 (`09F2`), 3420 (`0A84`), 3520 (`0A85`), OptiPlex 3090 (`0A30`/`0A31`), … |
| `Commercial/AnySKU` | `0983` |
| `Consumer/Allow/SystemFamily` | Inspiron, Vostro, XPS |
| `Consumer/Block/Platform` | SKUs `0C52`, `0B24`, `0B31`, `0AF4`, `0B70`, `0B25`, `0B32`, `0B26`, `0B33`, `0BB6` |
| `Consumer/AnySKU` | `0AF3` |

5. **Per-feature install gate**: `CoreFeatureChecks.ps1` builds the feature set from portability and CPU
   architecture — portables get `Power, PresenceDetection, Display, Collaboration, PurchasedApps`;
   desktops get `Power, Display, PurchasedApps`; unsupported CPU arch gets none (`:16-26`) — then filters
   it by `SupportedFeatureOnPlatform` (`:45-56`), a property produced by `ModularDeployment.ps1:270-271`
   and consumed by `Setup.xml:308-355` conditions (`Compare="Contains" CompareTo="Power|PresenceDetection|
   Display|Collaboration|PurchasedApps"`) to decide which MSI/feature installs.

## 2. Runtime suite gate: same list, embedded in the app

`Dell.Optimizer.Environment.dll` embeds the same whitelist as the resource
`Dell.Optimizer.Environment.HardwareCheckList.xml` (string present in the DLL; 56 KB assembly).

`Dell.Optimizer.Environment.HardwareCheck.IsSupportDellOptimizer()`:

* reads `ROOT\WMI MS_SystemInformation` via `Dell.Optimizer.Common.PlatformInfo.GetSystemInfo()`
  (`SystemManufacturer`, `SystemProductName`, `SystemSKU`, cached);
* re-applies the vendor check and the **same two model-ID regexes**
  (`PlatformInfo._ModelIdPattern` / `_LegacyModelIdPattern`) with the same exclusions;
* `IsAllowedSKU`: exact SKU in `Allow` ⇒ true, exact SKU in `Block` ⇒ false, else
  `Convert.ToInt32(sku,16) >= Convert.ToInt32(AnySKU,16)`;
* `Commercial` list for Pro/Precision-family models, `Consumer` list for
  `DellLaptops/DellPremiumLaptops/DellDesktops/DellXPS`.

Enforcement: `Dell.Optimizer.Environment.AgentEnvironment` (`:87-91`) logs `Fatal("Unsupported system")` and
**throws** `NotSupportedException("The system is not support Dell Optimizer.")` — the agent refuses to start
on a non-whitelisted machine.

Model classification (`Dell.Optimizer.Common.PlatformInfo` + `SystemModel`): product-line char → family
(`D`→Dell Laptops/Premium, `E`→Desktops, `P`→Pro Laptops, `Q`→Pro Desktops, `M`→Pro Max Laptops,
`F`→Pro Max Desktops, `R`→Rugged, `W`→Pro Precision, `V`→Pro Essential, `E`→Pro Education,
`C`→Chromebooks, Alienware via 8-char legacy IDs), plus `_DesktopIdentifier = "MSTR"` and an
AIO-name regex (`\b(All in One|All-in-One|AllinOne|AIO)\b`); rule generation →
`ModelIDNamingRuleType { Legacy, CY25, CY26 }`. Consumers: `Dell.Optimizer.Configuration.ConfigurationManager:640`
(reads the `Model` property), `Dell.Optimizer.Plugin.DellOptimizerConfiguration`,
`Dell.Optimizer.Plugin.Monitor`, `Dell.UUE.CoreCommon.Utilities`, `Dell.UUE.CommonPlugins.Helpers`,
`Dell.UUE.CoreInterfaces.Telemetry.Providers`.

## 3. Chassis / form-factor gates

| Check | Source | Rule |
|---|---|---|
| Can this machine have a battery? | `Plugin.PowerManager.SystemInfo` (`Win32_SystemEnclosure.ChassisTypes`) | true only for {1 Other, 8 Portable, 9 Laptop, 10 Notebook, 11 Hand Held, 14 Sub Notebook, 30 Tablet, 31 Convertible, 32 Detachable}; otherwise logged "Unsupported chassis type(s)" and battery-related metadata (e.g. thermal sync availability, `!SystemInfo.CanContainBattery()` in `SystemPowerConfiguration.UpdateSettingsMetadataAsync`) is disabled |
| Desktop vs portable | `Dell.UUE.CoreInterfaces.Telemetry.Providers.DeviceInfoProvider.IsDesktop()` (`ChassisTypes[0]`) | desktop {3,4,6,7,13,15}, portable {8,9,10,14}; used for telemetry/feature decisions |

## 4. Firmware capability gates (per feature, probed at runtime)

These are the "can this particular platform do X" checks (details in
`docs/02-battery-charge-levels.md` §3.6/§5.1 and `docs/07`):

* DACI **supported-commands bitmask** from SMBIOS type 0xDA → `DSIS.IsClassSupported(class)`
  (battery features require class 8; token writes require class 1) and token-existence lookups
  (`_smbiosTokens`), the Windows analogue of the kernel's `da_supported_commands`/token table.
* Battery **supported charge-mode bitmask** (`cbRes3`: bits 0-6 = Standard/Express/PrimarilyAC/Auto/
  Custom/PermanentLongLife/AdvancedCharge) and **allowable limits + granularity** (`cbRes4`);
  the UI only offers modes 1–5 and clamps the slider to BIOS-reported min/max.
* Thermal (USTT tables, `SupportedThermalModes`, fan-failure state), keyboard illumination tokens,
  Peak Shift/Advanced Charge tokens, Dell Command Monitor BMU namespace
  (`root\dcim\sysman\diagnostics`), A3-SMI interface support (DTP side).

## 5. Peripheral / device-presence gates

* **Color profiles by panel ID**: the installer ships per-panel data
  (`AppPlugins/Assets/colorprofiles/<PANEL>_<ver>_....dpp` + `<PANEL>_InitData.txt`, e.g. `20H2C`, `2MWT9`,
  `AUO1399`, `AUO13B2`) and the Display feature applies only the profile matching the detected panel.
* Presence detection (sensor presence), collaboration (camera/audio stacks + Zoom SDK), haptic
  touchpad, privacy screen, VOIP/audio plugins — each gates on the corresponding device/interface being
  present (TechHub `DeviceQuery`/collector plugins, `Dell.DeviceQuery`, `IP*Validator` helper DLLs
  shipped under `Tool/x64|ARM64/…Validator`).

## 6. Plugin availability / dependency gating

* Framework level: `[PluginRequires(Id=…, Version=…)]`, `PluginStateInfo`, and service-dependency
  failures surfaced as `DependencyFailCode` values (e.g.
  `DynamicChargeCannotChangeChargeModeFromPermanentLongLifeMode`,
  `…FromCustomMode`, `…FromAdvancedMode`, `BatteryCannotChangeChargeModeFromPermanentLongLifeMode`).
* UI level: a dedicated takeover plugin `Dell.UUE.NonApplicableSystemPlugin.UI`
  (id `{31FA8A5C-B058-455C-B117-95498500C4F2}`, `IConsoleTakeoverPagePlugin`) renders a full-window
  "not applicable" page with only **Close** and **Uninstall** commands — shown instead of feature pages
  when the feature set does not apply to the machine.

## 7. Practical consequences

* The whitelist is **per release** and SKU/hex-threshold based: a machine can be a genuine Dell but
  unsupported (blocked SKU or SKU < `AnySKU`), and newly released models are unsupported until the
  list is updated (e.g. the shipped list's Consumer block entries are explicit SKUs, everything else
  rides on `AnySKU`).
* Consequences of the gate: install refuses (`IS_SUPPORTED_DELL_SYSTEM=0` → feature conditions in
  `Setup.xml` drop all features), and if the app is present anyway the agent throws
  `NotSupportedException` at start.
* A model can pass the platform gate but still have individual features gated off by chassis, firmware
  capability probe, device presence, or plugin dependency failure — that is why the same app version
  shows different feature sets on different Dell machines.

## 8. Case study — Inspiron 15 3535 (2023 consumer AMD laptop)

**App side (gating verdict).** No artifact contains a 3535-specific entry (grepped installer payload, MSIs,
app tree, color profiles, DUP `package.xml`/`Mup.xml` — the DUP only declares
`<SupportedDevices><Device componentID="114288">Dell Optimizer</Device>`, no model list). Therefore the
Inspiron 3535 is decided by the generic Consumer path:

1. Vendor check → `Dell Inc.` ✔
2. Product name (`Inspiron 15 3535`) matches neither model-ID regex → the legacy path matches the XML
   `SystemFamily` name `Inspiron` (Consumer section) ✔ → `IsSupportedProductLine = true`
3. SKU decision (the only remaining gate, `HardwareCheckList.xml` Consumer section):
   * blocked if the SMBIOS SKU is exactly `0C52`, `0B24`, `0B31`, `0AF4`, `0B70`, `0B25`, `0B32`, `0B26`, `0B33` or `0BB6`;
   * otherwise supported iff hex SKU ≥ `AnySKU = 0AF3`;
   * the Consumer `Allow/Platform` list is empty, so every consumer Inspiron rides on this threshold.

So model-family support is confirmed, but the per-unit verdict needs the machine's SKU — it is not present
in any public data set checked (linux-hardware.org has zero probes for this model; Dell's driver API
returns 403 to scripts). Check it directly:

```powershell
Get-WmiObject -Namespace root\wmi -Class MS_SystemInformation | Select-Object SystemSKU, SystemProductName
# supported if: not in {0C52,0B24,0B31,0AF4,0B70,0B25,0B32,0B26,0B33,0BB6} and [Convert]::ToInt32($sku,16) -ge 0x0AF3
```
```sh
cat /sys/class/dmi/id/product_name /sys/class/dmi/id/product_sku
```

Installer feature set for a portable = `Power, PresenceDetection, Display, Collaboration, PurchasedApps`
(`CoreFeatureChecks.ps1`), so the battery/power feature is in scope; whether the charge-level card actually
appears then depends on the **firmware capability probe** (`cbRes3` mode bitmask / class-8 support), not on
the model name.

**Linux kernel side (7.2.9).**

* No model gating for the 3535: `dell-laptop` matches the DMI table `dell_device_table[]` by
  `DMI_SYS_VENDOR="Dell Inc."` + `DMI_CHASSIS_TYPE ∈ {8,9,10,30,31,32}` (`dell-laptop.c:121-168`) — a
  3535 (notebook chassis) matches and probes.
* There is **no blacklist** in this kernel; `dell_quirks[]` has 23 model entries, all old
  (Vostro V130/131/3350/3450/3460/3555/3560, Inspiron 1012/1018/N311z/M5110/N5110/5420/5520/5720/7420/
  7520/7720, XPS13 9333, XPS 13 9370, Latitude E6410, Latitude 7520) — nothing for the 3535, so the
  generic code path applies (no `touchpad_led`/`kbd_missing_ac_tag` quirks needed).
* Charge control on a 3535 is **firmware-dependent, not model-gated**: `dell-laptop` registers
  `charge_types` + `charge_control_start/end_threshold` on `BAT0` only when the SMBIOS 0xDA token table
  contains the BAT_* tokens (`battery_get_supported_modes() != 0`, `dell-laptop.c:2431-2450`). The
  transport is the ACPI-WMI SMBIOS interface (GUID `A80593CE-A997-11DA-B012-B622A1EF5492`, priority 1) or
  SMM via `dcdbas` (priority 0). Extra telemetry needs the DDV WMI interface
  (GUID `8A42EA14-4F2A-FD45-6422-0087F7A7E608`, `dell-wmi-ddv.c:42`).
* Verify on the machine: `ls /sys/class/power_supply/BAT0/` (look for `charge_types` /
  `charge_control_*_threshold`), `dmesg | grep -iE 'dell|smbios'`, `modinfo dell_laptop | head -3`.

Bottom line: the app supports the *family* (subject to the SKU threshold/block list checked above), and
the kernel supports the *machine* by chassis — but whether battery charge levels can be set at all is
decided by the 3535's firmware exposing the Dell SMBIOS battery tokens (app: class-8 `Get/SetBatteryInfoEx`
or token support; Linux: the same token table via `dell-smbios`).

## 9. Evidence index

| Claim | Evidence |
|---|---|
| Install-time vendor/model/SKU gate | `extract/is_payload/HardwareChecks.ps1:33-38, 44-106, 125-166` |
| Shipped allow/block list + thresholds | `extract/is_payload/HardwareCheckList.xml` (parsed: Commercial{Precision,Latitude,OptiPlex}/0983, Consumer{Inspiron,Vostro,XPS}/0AF3) |
| Per-feature install gating | `CoreFeatureChecks.ps1:16-26, 45-56`; `ModularDeployment.ps1:270-271`; `Setup.xml:308-355` |
| Runtime duplicate of the gate | `decompiled_all/Dell.Optimizer.Environment__*/Dell.Optimizer.Environment/HardwareCheck.cs`; embedded resource `Dell.Optimizer.Environment.HardwareCheckList.xml` |
| Hard enforcement | `Dell.Optimizer.Environment/AgentEnvironment.cs:87-91` (`NotSupportedException`) |
| Model-ID regexes + family mapping | `decompiled_all/Dell.Optimizer.Common__*/Dell.Optimizer.Common/PlatformInfo.cs`, `SystemModel.cs`, `ModelIDNamingRuleType.cs` |
| Consumers of the model info | `Dell.Optimizer.Configuration/ConfigurationManager.cs:640`; `Dell.UUE.CoreInterfaces.Telemetry.Providers/DeviceInfoProvider.cs`; `Dell.UUE.CoreCommon.Utilities`; `Dell.UUE.CommonPlugins.Helpers`; `Dell.Optimizer.Plugin.Monitor` |
| Chassis gates | `decompiled/Dell.Enterprise.Client.Framework.Plugin.PowerManager/…/SystemInfo.cs` (`ComputeCanContainBattery`); `…/DeviceInfoProvider.cs:305-330` (`IsDesktop`) |
| Firmware capability gates | `docs/02-battery-charge-levels.md` §3.6, §5.1; `docs/07-linux-kernel-battery-support.md` §3 |
| Panel-ID color profiles | `extract/app/_msi_file_manifest.txt` (`Assets/colorprofiles/…`) |
| Not-applicable takeover UI | `decompiled_all/Dell.UUE.NonApplicableSystemPlugin.UI__*/…/NonApplicableSystemPlugin.cs`, `…/NonApplicableSystemTakeOverViewModel.cs` |
| Inspiron 3535: no per-model entry anywhere | greps over `extract/is_payload/`, `extract/app/…`, MSI manifests; DUP `extract/package.xml` (`SupportedDevices` = only `Dell Optimizer`, componentID 114288); color profiles are panel-keyed |
| Inspiron 3535: kernel match path | `linux-7.2.9/drivers/platform/x86/dell/dell-laptop.c:121-168` (vendor + chassis table), `:170-…` + `:2469` (`dell_quirks`, 23 old-model entries, none modern Inspiron) |
| Inspiron 3535: charge control gate | `dell-laptop.c:2431-2450` (`battery_get_supported_modes()` from token table); transports `dell-smbios-wmi.c:32,261` / `dell-smbios-smm.c:128`; DDV GUID `dell-wmi-ddv.c:42` |
| Inspiron 3535: public data availability | linux-hardware.org search `vendor=Dell&name=Inspiron+15+3535` returned 0 probes (fetched 2026-10-09); Dell driver API returned HTTP 403 |
