# Dell Optimizer 6.3.5.0 — Battery Charge-Level Subsystem (deep reverse-engineering)

Target: `Dell-Optimizer-Application_GJ7NN_WIN64_6.3.5.0_A00.exe` → `Dell Optimizer.msi` (app 6.3.5.0).
All code references are ILSpy 11 decompilations under `decompiled/` (C#) and Ghidra output under
`ghidra/` (native). Every claim below is backed by decompiled code in this tree.

---

## 1. TL;DR — how a charge-level change reaches the battery

```
UI (WPF)  ChargingModeViewModel.OnRangeSliderMouseUp(start%, end%)
  └─ Dell.UUE.PowerPlugin.Core  BatterySettings.SetBatteryCustomChargeMode(...)
       └─ Dell.UUE.CoreCommon    BatteryRepository.SetBatteryCustomChargeModeAsync(...)
            └─ [unified-agent RPC] ISystemPowerConfiguration.SetBatteryCustomChargeModeAsync(CustomChargeModeSettings)
                 └─ Dell.Optimizer.Plugin.SystemPowerConfiguration  Imp_SetBatteryCustomChargeModeAsync
                      └─ IPowerManagement.SetBatteryCustomChargingModeAsync(systemIndex, start, stop)
                           └─ Dell.Enterprise.Client.Framework.Plugin.PowerManagement  PowerManagement
                                └─ DSIS.SetBatteryCustomChargingMode(battery#, ref start, ref stop)
                                     └─ BiosIntfAgent.ExecuteDACI(cbClass=8, cbSelect=19, MarshalBiosData)
                                          └─ P/Invoke Dell.Enterprise.Client.Framework.BiosIntfWrapper.dll
                                               └─ BIOSIntf.dll CHapiIntf::ExecuteDACI → CBatteryInfoGet/SetBuffer
                                                    └─ WMI: ROOT\WMI class WMI_Query, method DoBFn (WMI-ACPI bridge)
                                                         └─ SMBIOS type 0xDA Dell Calling Interface (SMI) → EC/charge firmware
```

The final hop is a **WMI-ACPI call, not DeviceIoControl** (`IWbemServices::ExecMethod "DoBFn"` on the
`WMI_Query` instance in `ROOT\WMI`, payload as `VT_ARRAY|VT_UI1` byte arrays) — proven in
`docs/05-native-bios-interface.md` §6 with Ghidra function addresses and the exact request-buffer ABI
(`cbClass/cbSelect` u16s, `(battery<<8|command)`, mode/start/stop packed dword, flags 0x100 read /
0x10000 set, payload at +0x30).

Reads use the same pipe with `cbSelect=18` (`GetBatteryInfoEx`) and `m_nBatteryCommand = 3`.

The wire protocol is Dell's **DACI** ("Dell API Calling Interface"): a `(class, select, structure)` RPC into
BIOS. All battery charge-level programming uses **class 8 (`DA_CLASS_08`)**, **select 18 = GetBatteryInfoEx /
19 = SetBatteryInfoEx** (`BatteryClassSelectEnum`). Generic SMBIOS token writes use class 1 / select 0.

---

## 2. The BIOS payload structure

`Dell.Enterprise.Client.Framework.BiosIntf` (managed, decompiled in
`decompiled/Dell.Enterprise.Client.Framework.BiosIntf/`):

```csharp
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct AdvanceBatteryConfig {
    public uint Version;             // ASCII "01.00" packed big-endian char-wise (see below)
    public uint SunWorkingHours;     // byte0 = BeginningOfDay bitmap, byte1 = WorkPeriod bitmap
    public uint MonWorkingHours;     // ... 7 daily words; used by Advanced Charge (mode 7) only
    public uint TueWorkingHours;
    public uint WedWorkingHours;
    public uint ThuWorkingHours;
    public uint FriWorkingHours;
    public uint SatWorkingHours;
    public byte m_nBatteryCommand;   // 0 = set, 3 = get (observed)
    public byte m_nBatteryNumber;    // 1..16 (MAXIMUM_BATTERY_COUNT = 16)
    public byte m_nChargingMode;     // see BatteryChargingModeEnum below
    public byte m_nStartChrgLimit;   // custom-mode start charge level in % (lower threshold)
    public byte m_nStopChrgLimit;    // custom-mode stop  charge level in % (upper threshold)
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct MarshalBiosData {
    public BiosDataType biosDataType;               // 0 TOKEN_DATA, 1 ADVANCE_BATTERY_CONFIG, 2 PEAK_SHIIFT_CONFIG
    public TokenData tokenData;                     // cbArg1..4, cbRes1..4, SecKeyParam
    public AdvanceBatteryConfig advanceBatteryConfig;
    public PeakShiftConfig peakShiftConfig;
    public uint Status;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct TokenData {
    public uint cbArg1, cbArg2, cbArg3, cbArg4;
    public int  cbRes1;      // result code → ErrorEnum
    public uint cbRes2, cbRes3, cbRes4;
    public SecKeyParam skpArg;
}
```

Charge-mode enum (identical in `Contract.PowerManagement.BatteryChargeModeEnum` and
`Plugin.PowerManagement.Bios.BatteryChargingModeEnum`, byte-valued):

| v | Name | UI name (`Contract.SystemPowerConfiguration.BatteryChargeMode`) |
|---|------|------|
| 0 | Reserved | — |
| 1 | StandardCharge | `Standard` |
| 2 | ExpressCharge | `ExpressCharge` |
| 3 | PredominatelyAcUse | `PrimarilyAC` |
| 4 | Auto | `Adaptive` |
| 5 | Custom | `Custom` (start/stop % limits) |
| 6 | PermanentLongLife | `LongLifeWarranty` (warranty-locked) |
| 7 | AdvancedCharge | `Advanced` (scheduled charging) |
| 255 | Unknown | `ChargeModeUnknown` |

BIOS result decoding (`BatteryPropertyParser.Parse`, see §4.3):

| Field | Meaning |
|---|---|
| `tokenData.cbRes1` | `ErrorEnum` result code (0 = success) |
| `tokenData.cbRes3` (get) | supported-modes bitmask (bit0 Standard, bit1 Express, bit2 PrimarilyAC, bit3 Auto, bit4 Custom, bit5 PermanentLongLife, bit6 AdvancedCharge) — `BatteryInformationBitMasks` |
| `tokenData.cbRes2` bytes[1],[2] (get, mode==5) | effective start/stop charge limit in % |
| `tokenData.cbRes4` bytes[0..3] (get) | allowable start %, allowable stop %, granularity (dead band) %, battery location (0 Primary, 1 BatterySlice, 2 ModuleBay, else Unknown) |
| `tokenData.cbRes3` (set, custom) | bytes[0],[1] = effective start/stop after BIOS validation |

`AdvanceBatteryConfig.Version` packing: 4 ASCII chars, most-significant first
(`StringToUint32("01.00")` skips the dot → 0x30313030); `VersionUintToString` inverts it.

---

## 3. Layer-by-layer function reference (charge-level path)

### 3.1 UI — `Dell.UUE.PowerPlugin.UI` (WPF thick client, plugin id `{6882607A-630D-4F94-BE88-1251C1CBFD4D}`)

`Dell.UUE.PowerPlugin.UI.ChargingMode.ViewModels.ChargingModeViewModel : ObservableRecipient, IChargingModeViewModel`
(`decompiled/Dell.UUE.PowerPlugin.UI/Dell.UUE.PowerPlugin.UI.ChargingMode.ViewModels/ChargingModeViewModel.cs`)

| Function | Documentation |
|---|---|
| `ChargingModeViewModel(IBatterySettings, IPowerConfiguration)` | Ctor; snapshots `batteryProperty = GetAllBatteryInfo()[0]`, derives `_isDynamicChargeEnable`, `_isChargeModeEnabled` (false when DynamicCharge on or warranty battery), initial `ChargingMode`, `CardEnabled`, slider visibility (`_isCustomPowerSliderVisible` iff mode == Custom). |
| `OnRangeSliderMouseUp(object, DragCompletedEventArgs)` | **The charge-level entry point.** Casts sender to `Slider`, takes `SelectionStart`/`SelectionEnd` as start/end %, calls `BatterySettings.SetBatteryCustomChargeMode(start, end, Maximum, Minimum, DeadBand)` on a background task, then re-reads `GetAllBatteryInfo()` and raises `CustomChargingCurrentStart/End` property changes. |
| `UpdateDynamicCharge(bool, bool)` | Sets `IBatterySettings.DynamicChargeEnabled`, recomputes `_isChargeModeEnabled`, optionally refreshes `ChargingModeCardEnabled` (used by PeakShift toggle interplay). |
| `ChargingMode` (property setter) | Validates supported; writes `_batterySettings.ChargingMode`, toggles `IsChargeModeCustomEnabled` (slider visibility) and `IsDynamicChargeCanEnabled` (DynamicCharge can't be on in Custom mode), raises `OnPropertyChanged`. |
| `IsBatteryLongLifeWarranty` / `IsChargingModeSupported` / `ChargingModeCardEnabled` / `IsDynamicChargeCanEnabled` | UI-state predicates computed from `batteryProperty`, mode, and interlocks. |
| ctor-time messenger registrations (`PeakShiftUpdated`, `PowerToggleUpdated`, ...) | Keep card enablement consistent when Peak Shift/Dynamic Charge change elsewhere. |

`Dell.UUE.PowerPlugin.UI.BatteryInfoPanel.ViewModel.BatteryInfoViewModel` — battery tile: charge level %,
charge status, health, location; models in `Dell.UUE.CoreCommon.Power.Models.*`
(`BatteryInfoModel`, `BatteryChargeModeModel`, `CustomChargeModeSettingsModel`, ...).

### 3.2 UI→service glue — `Dell.UUE.PowerPlugin.Core` and `Dell.UUE.CoreCommon`

`Dell.UUE.PowerPlugin.Core.Implementations.BatterySettings : IBatterySettings`
(`decompiled/Dell.UUE.PowerPlugin.Core/Dell.UUE.PowerPlugin.Core.Implementations/BatterySettings.cs`)

| Function | Documentation |
|---|---|
| `SetBatteryCustomChargeMode(int start, int end, int maximum, int minimum, int deadBand)` | Synchronous wrapper (`JoinableTaskFactory.Run`) over `IBatteryRepository.SetBatteryCustomChargeModeAsync`; returns true iff `ErrorEnum.NoError`. |
| `ChargingMode` / `DynamicChargeEnabled` / other `IBatterySettings` members | Thin settings-backed properties over `ISystemPowerConfiguration`/`IDynamicCharge` settings names (`PowerSettingsConstants`). |

`Dell.UUE.CoreCommon.Power.Implementations.BatteryRepository : IBatteryRepository`
(`decompiled/Dell.UUE.CoreCommon/Dell.UUE.CoreCommon.Power.Implementations/BatteryRepository.cs`)

| Function | Documentation |
|---|---|
| `SetBatteryCustomChargeModeAsync(startChargingInPercentage, endChargingInPercentage, maximum, minimum, deadBand)` | Resolves `ISystemPowerConfiguration` plugin, calls `SetBatteryCustomChargeModeAsync(new CustomChargeModeSettings(start, end, minimum, maximum, deadBand))`, logs non-success, returns `errorEnum == NoError`. |
| `GetAllBatteryInfoAsync(bool useCache)` | Cached `ISystemPowerConfiguration.GetAllBatteryInfoAsync()` → `BatteryInfoModel[]`. |
| `RestoreBiosAlertsAsync()` / `GetAllDisabledBIOSAlertsAsync()` | BIOS-alert management RPC pass-through. |

Settings names (`Dell.UUE.CoreCommon.Power.PowerSettingsConstants`):
`ISystemPowerConfiguration.ChargingMode`, `IDynamicCharge.State`, `IBatteryExtender.State`,
`ISystemPowerConfiguration.PeakShiftState`, `ISystemPowerConfiguration.PeakShiftBatteryThreshold`
(minimum 15), `ISystemPowerConfiguration.ThermalMode`,
`ISystemPowerConfiguration.SyncThermalModeAndWindowsPowerSlider`.

### 3.3 Contract — `Dell.Enterprise.Client.Framework.Contract`

`SystemPowerConfiguration.ISystemPowerConfiguration : IUnifiedAgentContract, IContractBase`:

| Method | Documentation |
|---|---|
| `Task<IList<BatteryInfo>> GetAllBatteryInfoAsync()` | Per-slot battery state incl. charge mode, supported modes, custom limits, health, interlock flags. |
| `Task<ErrorEnum> SetBatteryCustomChargeModeAsync(CustomChargeModeSettings)` | **Sets charge levels.** `CustomChargeModeSettings { Start, Stop, Minimum, Maximum, DeadBand }` (all percent). |
| `Task<PeakShift> GetPeakShiftInformationAsync()` / `SetPeakShiftInformationAsync(PeakShift)` | Peak-shift schedule (charge only in off-peak windows). |
| `Task<AdvancedCharge> GetAdvancedChargeInformationAsync()` / `SetAdvancedChargeInformationAsync(AdvancedCharge)` | Advanced Charge (mode 7) per-weekday schedule. |
| `Task<FanFailureModesEnum> GetFanFailureModeAsync()` | Fan state gating thermal changes. |
| `Task<bool> RestoreBIOSAlertsAsync(List<string>)` / `HideBIOSAlertAsync(string)` / `GetAllDisabledBIOSAlertsAsync()` | BIOS alert suppression. |

`PowerManagement.IPowerManagement` (used by the SystemPowerConfiguration plugin):
`GetAllBatteryInformationAsync`, `GetBatteryHealthInformationAsync(systemIndex)`,
`GetBatteryPropertyAsync(systemIndex)`, `GetBatteryReportAsync(systemIndex)`,
`IsSystemPluggedInAsync`, `EnableAdvancedChargeAsync(bool)`,
`SetBatteryAdvancedChargeModeAsync(AdvancedChargeMode)`,
`SetBatteryChargingModeAsync(BatteryChargeModeEnum, systemIndex)`,
`SetBatteryCustomChargingModeAsync(systemIndex, startChargingLimit, stopChargingLimit)`,
`GetUsttInformationAsync`/`SetUsttInformationAsync` (thermal),
`GetPeakShiftInformationAsync`/`SetPeakShiftInformationAsync`,
`GetKeyboardIlluminationFeatureInformationAsync`/`...CurrentStateAsync`.

Data contracts (same assembly): `BatteryProperty` (current mode + start/stop limits, supported-mode
bools, `AllowableStartChargingLimit`, `AllowableStopChargingLimit`, `Granularity`, `Location`,
`AdvancedChargeMode`, `Error`, `RawBufferData`), `CustomChargeModeSettings`, `BatteryInfo`,
`BatteryChargeModeModifyFlag`, `AdvancedCharge`/`AdvancedChargeModeDailySettings`,
`PeakShift`/`PeakShiftDailySettings`, `BatteryHealth`, `BatteryReport`, `ErrorEnum`, `BatteryLocationEnum`.

`BatteryChargeModeModifyFlag` values: `CantModifyNotSupported=0`, `CanModify=1`,
`CantModifyWarrantyBattery=2`, `CantModifyPolicySetting=3`, `CantModifyAdvancedChargeActive=4`.

`ErrorEnum`: `NoError=0`, `InvalidService=1`, `ChargingModeNotSupported=251`,
`InvalidInterfaceBuffer=252`, `NullInterfaceBuffer=253`, `InvalidBatteryNumber=254`,
`MemoryAllocationError=255`, `Unknown=256`, `SmbiosTokenNotFound=257`, and the
negative-space BIOS status values `InterfaceBufferTooSmall=0xFFFFFFFA`,
`InterfaceBufferFormatError=0xFFFFFFFB`, `InterfaceNotExecuted=0xFFFFFFFD`,
`InterfaceFunctionNotSupported=0xFFFFFFFE`, `InterfaceError=0xFFFFFFFF`.

### 3.4 Settings façade + policy engine — `Dell.Optimizer.Plugin.SystemPowerConfiguration`

`decompiled/Dell.Optimizer.Plugin.SystemPowerConfiguration/Dell.Optimizer.Plugin.SystemPowerConfiguration/SystemPowerConfiguration.cs`
(1242 lines; publishes `ISystemPowerConfiguration` — `[PublishedUnelevatedInterface]`).

| Function | Documentation |
|---|---|
| `SystemPowerConfiguration(IAgent)` | Plugin ctor (`SystemPowerConfigurationAspect`). |
| `GetImplementationType()` | Returns `typeof(SystemPowerConfiguration)`. |
| `_Powermanagement` (property) | `PluginRequest.RequestContract<IPowerManagement>()` — the RPC stub to the PowerManagement plugin. |
| `AllBatterySlots` (property) | Enumerates battery slots (`BatteryInformation`), used by `Imp_GetAllBatteryInfoAsync`. |
| `IsBatteryActive(BatteryInformation)` | Slot-present check (skips empty slots). |
| `WorkerLoopAsync()` / `AddActionToWorkerQueue(Action)` / `StopWorkerLoop()` | Unbounded `Channel<Action>` worker serializing settings side effects at startup/shutdown. |
| `CreateSettingsHandler()` | `[StaticSettingsHandler<PersistentSettings>(true), ProxySettingsHandler(ProxySettings.ProxySettingsItems)]` — persistent state + the proxy items below. |
| `ProxySettings.ProxySettingsItems` (see `ProxySettings.cs`) | **Settings-write backends** (`SettingsName` → setter/getter delegates): `ThermalMode` (fan-failure gated `SetUsttInformationAsync`, FailCode 57; getter returns mode 0 when fan failed) and `ChargingMode` (the CLI path — see §3.4a). |
| `OnStart()` / `OnStop()` / `OnActivate()` / `OnDeactivate()` | Lifecycle: starts worker, subscribes `ProcessExit`, wires `PluginSettings` Value/Metadata events, refreshes metadata. |
| `UpdateSettingsMetadataAsync()` | Queries supported charge modes per battery and publishes settings metadata (enumerations/limits) so UI/CLI show only valid values; `RetrySetMetadataAsync(name, metadata, retryCount=3, delayMs=3000)` handles flaky first-writes. |
| `GetOtherPluginState(string)` / `SetOtherPluginStateAsync(string, bool)` | Cross-plugin settings peek/poke (`IDynamicCharge`, `IBatteryExtender` state names). |
| `IsPSDictDailySettingsEqual` / `IsPeakShiftDailySettingsEqual` / `IsTimeSettingsEqual` | Deep-equality helpers used to suppress redundant PeakShift writes. |
| `CreateAdvancedChargeModeDailySettings(AdvancedChargeDailySettings)` | Maps contract daily settings → `AdvancedChargeModeDailySettings` (BIOS working-hours model). |
| `PluginSettings_ValueChanging(object, ValueChangingEventArgs)` | **Policy gate for external writes.** `ThermalMode`/`Sync...`: throws unless fan OK. `PeakShiftState`/`PeakShiftBatteryThreshold`: throws if DynamicCharge enabled+locked. `ChargingMode`: throws when current mode is `LongLifeWarranty(6)` ("3 year warranty on this battery has locked it"), `Advanced(7)` ("Advanced Charge Policy is enabled"), or `IDynamicCharge` state is true. `AdvancedChargeState`: throws if DynamicCharge locked or charging mode locked. Internal requests (`IsInternalRequest()`) skip checks. |
| `PluginSettings_ValueChanged(object, ValueChangedEventArgs)` | Post-change side effects (propagates ChargingMode/AdvancedCharge/PeakShift to `IPowerManagement`, enqueues worker actions). |
| `IsInternalRequest()` | True when the request did not come from an `ExternalRequestContext`. |
| `PluginSettings_MetadataChanging/Changed` | Metadata guard/refresh. |
| `PowerSaver_EventOccurred(object, EffectivePowerMode)` | Reacts to Windows power-slider changes (thermal/EPP sync). |
| `IsDynamicChargeEnabledAndLocked()` / `IsChargingModeLocked()` / `IsAdvancedChargeEnabledAndLocked()` | Interlock predicates reading other plugins' settings. |
| `GetSystemChargingStatus(int systemIndex, ref BatteryInfo)` | Fills `BatteryInfo` charge status from battery report (charging/discharging/idle). |
| `GetChargeModes(BatteryProperty, BatteryInfo)` | Translates BIOS supported-modes bitmask → `AvailableChargeModes` list; for Custom also fills `CustomChargeModeSettings(start, stop, minimum, maximum, deadBand)`. |
| `DetermineChargeModeModifyState(BatteryInfo, BatteryProperty)` (static) | Maps current mode → `BatteryChargeModeModifyFlag`: mode 6 → `CantModifyWarrantyBattery`, mode 7 → `CantModifyAdvancedChargeActive`, modes 1–5 → `CanModify` if a supported mode exists (custom always), else `CantModifyNotSupported`. |
| `ConvertBattHealthIndexToHealthState(BatteryHealthEnum)` | BIOS health index → `BatteryHealthState`. |
| `DetermineBatteryType(BatteryInfo)` | Primary/slice/module-bay/unknown classification. |
| `Imp_GetPeakShiftInformationAsync()` / `Imp_SetPeakShiftInformationAsync(PeakShift)` | Read/write PeakShift via `IPowerManagement` (equality-checked first). |
| `Imp_GetAllBatteryInfoAsync()` | Per-slot: `GetBatteryHealthInformationAsync` + `GetBatteryPropertyAsync`, merges manufacturer/serial/part number, `GetChargeModes`, `DetermineChargeModeModifyState`; failure info 5/6 ⇒ charge mode cleared to `ChargeModeUnknown` and mode list emptied (non-Dell battery), other failure ⇒ `Health=Failed`; missing health info ⇒ everything cleared. Sets `Type` via `DetermineBatteryType`, appends `GetSystemChargingStatus`. |
| `Imp_SetBatteryCustomChargeModeAsync(CustomChargeModeSettings)` | **The policy-checked charge-level setter.** Rejects null (`-1`); rejects `Start < Minimum`, `Stop > Maximum`, `Start >= Stop` (`-1`); requires an active battery slot (`-2` if none); refuses when `IDynamicCharge` state is true (`-2`); refuses when `AdvancedChargeState == true` (`-2`); then `SetBatteryCustomChargingModeAsync(FirstActiveBatterySystemIndex, Start, Stop)`. |
| `Imp_GetFanFailureModeAsync()` | Fan failure enumeration (thermal interlock). |
| `Imp_GetAdvancedChargeInformationAsync()` / `Imp_SetAdvancedChargeInformationAsync(AdvancedCharge)` | Read/write Advanced Charge schedules via `IPowerManagement.SetBatteryAdvancedChargeModeAsync`. |
| `Imp_RestoreBIOSAlertsAsync` / `Imp_HideBIOSAlertAsync` / `Imp_GetAllDisabledBIOSAlertsAsync` | BIOS alert management. |
| `FirstActiveBatterySystemIndex` | Index of first present battery (used because custom charge is applied to the active battery). |

### 3.4a The `ChargingMode` settings proxy (CLI / external-client path)

Writing the setting `ISystemPowerConfiguration.ChargingMode` (e.g. `do-cli configure
SystemPowerConfiguration.ChargingMode Custom`) lands in `ProxySettings`'s `ChargingMode`
`SetProxyValueDelegate` (`decompiled/Dell.Optimizer.Plugin.SystemPowerConfiguration/.../ProxySettings.cs`):

1. If `GetOtherPluginState("IDynamicCharge")` → fail `FailCode 57` "Charging Mode is being managed by
   Dynamic Charge."
2. `FirstActiveBatterySystemIndex < 0` → fail 57 "No available battery."
3. `GetBatteryPropertyAsync(systemIndex)`; if `CurrentChargeMode == AdvancedCharge(7)` → fail 57
   "Charging Mode is being managed by Advanced Charge."
4. `Enum.TryParse<BatteryChargeMode>(value, ignoreCase)`; unparseable → fail 57.
5. Target ≠ `Custom(5)` → `SetBatteryChargingModeAsync(mode, systemIndex)` (→ DSIS preset write).
   Target = `Custom(5)` → `SetBatteryCustomChargingModeAsync(systemIndex, CurrentStartChargingLimit,
   CurrentStopChargingLimit)` — i.e. switching *to* custom re-applies the currently reported limits.
6. Read-back verification: `GetBatteryPropertyAsync(...).CurrentChargeMode == target` must hold,
   else fail 57 "Failed to set charging mode."

`SettingsAction.SetPowerChargingModeValueAsync` (CLI) adds a second verification: if the setting value
did not change at all it returns `FailCode.BatteryCannotChangeChargeModeFromCustomMode`.

### 3.5 Power-management plugin — `Dell.Enterprise.Client.Framework.Plugin.PowerManagement`

`PowerManagement : PowerManagementAspect` (`.../PowerManagement.cs`), publishes `IPowerManagement`.

| Function | Documentation |
|---|---|
| `PowerManagement(IAgent)` | Ctor; `RefreshBatteryIndexMapping()`. |
| `Imp_GetAllBatteryInformationAsync()` | DSIS battery list (serial, manufacturer, part number, slot). |
| `Imp_GetBatteryHealthInformationAsync(int systemIndex)` | `DSIS.GetBatteryHealthInformation(dsisIndex)`. |
| `Imp_GetBatteryPropertyAsync(int systemIndex)` | `DSIS.GetBatteryProperty(dsisIndex)` — charge modes + limits. |
| `Imp_GetBatteryReportAsync(int systemIndex)` | Windows battery IOCTL report (§5). |
| `Imp_IsSystemPluggedInAsync()` | AC online check. |
| `Imp_EnableAdvancedChargeAsync(bool enabled)` | **`DSIS.AssertSmbiosToken(enabled ? 885 : 884)`** (SMBIOS tokens 0x375/0x374). |
| `Imp_SetBatteryAdvancedChargeModeAsync(AdvancedChargeMode)` | `DSIS.SetBatteryAdvancedChargeMode`. |
| `Imp_SetBatteryChargingModeAsync(BatteryChargeModeEnum, int systemIndex)` | Maps `systemIndex → dsisIndex` (`SearchDsisIndex`, else `InvalidBatteryNumber=254`), then `DSIS.SetBatteryChargingMode`. |
| `Imp_SetBatteryCustomChargingModeAsync(int systemIndex, int startChargingLimit, int stopChargingLimit)` | Index mapping then `DSIS.SetBatteryCustomChargingMode(dsisIndex, ref start, ref stop)` (BIOS may clamp values; refs updated). |
| `Imp_GetUsttInformationAsync` / `Imp_SetUsttInformationAsync` | Thermal tables/mode via DSIS. |
| `Imp_GetPeakShiftInformationAsync` / `Imp_SetPeakShiftInformationAsync` | PeakShift via DSIS. |
| `Imp_GetScreenTimeStatisticsAsync` | `NotImplementedException` in this build. |
| `Imp_GetKeyboardIlluminationFeatureInformationAsync` / `Imp_GetKeyboardIlluminationCurrentStateAsync` | Keyboard backlight via DSIS. |
| `RefreshBatteryIndexMapping()` | Rebuilds `_dsisToSystemMap` (Windows battery index ↔ DSIS battery number) under `_mapLock`. |
| `SearchDsisIndex(int systemIndex)` | Reverse lookup with `_isMapRefreshNeeded` refresh. |

### 3.6 DSIS — the BIOS calling-interface client

`decompiled/Dell.Enterprise.Client.Framework.Plugin.PowerManagement/.../DSIS.cs` (1275 lines).
Field notes: `MAXIMUM_BATTERY_COUNT = 16`, `BATTERY_ADVANCED_CHARGED_MODE_DISABLE = 884`,
`BATTERY_ADVANCED_CHARGED_MODE_ENABLE = 885`; delegates `_GetRawSmbiosData` (WMI) and
`_BiosIntfExecuteDACI = BiosIntfAgent.ExecuteDACI` (injectable for tests).

| Function | Documentation |
|---|---|
| `GetRawSmbiosData()` (static) | WMI `root\wmi:SELECT * FROM MSSmBios_RawSMBiosTables` → `SMBiosData` byte[] (`MSSmBios_RawSMBiosTables`, `WmiUtils.GetObjectSearcherByQuery`). |
| `SmbiosTables` (property, lazy) | Parses raw SMBIOS into `Dictionary<int, SmbiosTable>` (typed tables incl. `SmbiosTableCallingInterface`). |
| `IsPortableBatteryTable(SmbiosTable)` | SMBIOS type 22 filter. |
| `CreatePeakShiftInstance()` | Builds default `PeakShift` from BIOS capabilities. |
| `ClearCache()` | Drops `_smbiosTables`/`_smbiosTokens` caches. |
| `GetAllBatteryInformation()` / `GetBatteryInformation(int)` / `GetBatteryCount()` | Portable-battery table (type 22) → `BatteryInformation` (manufacturer, serial, piece part id, system index). |
| `UpdateSmbiosTokenInformation()` | Collects tokens from **SMBIOS type 218 (0xDA) "Calling Interface" token tables** (`SmbiosTableCallingInterface.TokenList`) into `_smbiosTokens` (ID → `SmbiosToken{Location, Value}`). |
| `GetSupportedDACIClasses()` | Reads supported DACI classes from SMBIOS table 55808 (0xDA00 area). |
| `IsClassSupported(int classValue)` | Membership check (ARM64 special case: class 8 subset). All charge functions gate on `IsClassSupported(8)`; token writes gate on `IsClassSupported(1)`. |
| `MappingBiosIntfStatus(ErrorEnum, BiosIntfStatus)` | Maps native `BiosIntfStatus` (SUCCESS/FAILURE/.../INVALID_PARAM) onto `ErrorEnum`. |
| `GetBatteryHealthInformation(int batteryNumber)` | DACI **class 8 / select 18**, `m_nBatteryCommand` health query → `BatteryHealth` parse. |
| `GetBatteryProperty(int batteryNumber)` | **Charge-mode/limits read**: builds `MarshalBiosData{ biosDataType=ADVANCE_BATTERY_CONFIG, advanceBatteryConfig{ m_nBatteryCommand=3, m_nBatteryNumber=batteryNumber } }`, calls `ExecuteDACI(8, 18)`, on success `BatteryProperty.Parse(biosData)` + `AdvancedChargeMode.Parse(...)`. Validates `1 <= batteryNumber <= 16` else `InvalidBatteryNumber`. |
| `SetBatteryAdvancedChargeMode(AdvancedChargeMode)` | **Advanced Charge write**: `advancedChargeMode.ToBiosIntfStruct(1, BatteryChargingModeEnum.AdvancedCharge)`, `ExecuteDACI(8, 19)`; result `tokenData.cbRes1`. |
| `SetBatteryChargingMode(BatteryChargeModeEnum mode, int batteryNumber)` | **Preset-mode write** (modes 1–4 only; 5/6/7 rejected with `ChargingModeNotSupported=251`): `AdvanceBatteryConfig{ m_nBatteryCommand=0, m_nBatteryNumber, m_nChargingMode=(byte)mode }`, `ExecuteDACI(8, 19)`. Battery number bounds 1..16. |
| `SetBatteryCustomChargingMode(int batteryNumber, ref int startChargingLimit, ref int stopChargingLimit)` | **Charge-level write**: `AdvanceBatteryConfig{ m_nBatteryCommand=0, m_nBatteryNumber, m_nChargingMode=5 (Custom), m_nStartChrgLimit=(byte)start, m_nStopChrgLimit=(byte)stop }`, `ExecuteDACI(8, 19)`; on success reads back BIOS-validated values from `BitConverter.GetBytes(tokenData.cbRes3)` → `start = bytes[0]`, `stop = bytes[1]` (this is how BIOS clamping is observed). |
| `GetUsttInformation()` / `SetUsttInformation(ThermalModeEnum, ThermalModeEnum)` | Thermal tables/mode (DACI class 8, USTT selects). |
| `GetPeakShiftInformation()` / `SetPeakShiftInformation(PeakShift)` | PeakShift via `PeakShiftConfig` (`biosDataType=PEAK_SHIIFT_CONFIG`), `ExecuteDACI(8, 19)` on write. |
| `GetKeyboardIlluminationFeatureInformation()` / `GetKeyboardIlluminationCurrentState()` | Keyboard illumination DACI reads. |
| `AssertSmbiosToken(uint smbiosTokenId)` | **Token write**: looks up `SmbiosToken{Location, Value}` in `_smbiosTokens` (else `SmbiosTokenNotFound=257`), sends `MarshalBiosData{ biosDataType=TOKEN_DATA, tokenData{ cbArg1=Location, cbArg2=Value, cbRes1=-3 } }` to `ExecuteDACI(1, 0)`. Used for Advanced Charge enable (885) / disable (884). |

### 3.7 BIOS struct converters — `...Plugin.PowerManagement.SmbiosTableParsers`

| Function | Documentation |
|---|---|
| `AdvancedChargeModeParser.Parse(AdvancedChargeMode, AdvanceBatteryConfig)` | Decodes `Version` + 7 daily working-hours words (`byte0 = BeginningOfDay bitmap`, `byte1 = WorkPeriod bitmap`, `ParseFromBiosIntfHours`) into per-weekday settings. |
| `AdvancedChargeModeParser.ToBiosIntfStruct(AdvancedChargeMode, int battNumber, BatteryChargingModeEnum)` | Inverse: fills `m_nBatteryCommand=0`, battery number, mode, `Version`, daily hour words (`ConvertToBiosIntfHours` = `[BeginningOfDay, WorkPeriod, 0, 0]`). |
| `BatteryPropertyParser.Parse(BatteryProperty, MarshalBiosData)` | Full decode per §2 table; sets `RawBufferData = ByteMapper.StructToBytes(biosData)`, `IsChargeModeSupported=true` on success. |
| `BatteryHealthParser.Parse`, `PeakShiftParser.Parse/ToBiosIntfStruct`, `ThermalTablesParser.Parse`, `KeyboardIlluminationParser.Parse` | Same pattern for their payloads. |
| `BatteryInformationBitMasks.IsSupported(capability, mask)` | `(capability & mask) == mask`. |

### 3.8 Managed→native bridge — `Dell.Enterprise.Client.Framework.BiosIntf`

| Function | Documentation |
|---|---|
| `BiosIntfWrapper.CreateBiosIntf()` / `InitializeBiosIntf(nint)` | `[DllImport("Dell.Enterprise.Client.Framework.BiosIntfWrapper.dll")]` — allocate/initialize the native BIOS object (done once in the `BiosIntfAgent` static ctor; `IsInitialized` flag). |
| `BiosIntfWrapper.ExecuteDACI(nint hObj, ushort cbClass, ushort cbSelect, ref MarshalBiosData, string pwd, PwdType)` | **The single gateway to firmware** for all charge programming (class 8/select 18-19). |
| `BiosIntfWrapper.GetToken/SetToken(nint, ushort tokenId, ref MarshalBiosData[, ushort value])` | Direct SMBIOS-token access (alternative to `AssertSmbiosToken`'s DACI class 1 path). |
| `BiosIntfWrapper.GetAttribute/SetAttribute(nint, string name[, string value])` | Dell BIOS attribute string access. |
| `BiosIntfWrapper.GetDeviceState(nint, ref MarshalDeviceState)` / `SetPrivacyScreen(nint, bool)` | Device-state query / privacy-screen control. |
| `BiosIntfAgent.ExecuteDACI(ushort cbClass, ushort cbSelect, ref MarshalBiosData, string pwd = "", PwdType = NONE)` | Managed façade used by `DSIS._BiosIntfExecuteDACI`: process-wide singleton handle (`_BiosIntf`), all calls serialized under `_BiosIntfLock`, returns `BiosIntfStatus.FAILURE` when uninitialized or on exception. |
| `BiosIntfAgent.GetToken/SetToken/GetAttribute/SetAttribute/GetDeviceState/SetPrivacyScreen` | Same singleton+lock pattern for the other native entry points. |
| `DiagsIntfAgent` | Diagnostics-flavoured sibling of `BiosIntfAgent`. |
| `PwdType` | BIOS password context for privileged calls: `NONE, USER, ADMIN, BOTH, HDD, HDDandADMIN, HDDandUSER, TRIPLE` (charge calls use `NONE` with empty password string). |
| `BiosIntfStatus` | Native status enum (`SUCCESS..DUPLICATE_ENTRY`, 21 values). |

Native continuation (Ghidra): `docs/05-native-bios-interface.md`.

### 3.9 Long Life mode (charge mode 6) — what it is and what can set it

Names: BIOS `BatteryChargingModeEnum.PermanentLongLife = 6` / contract `BatteryChargeMode.LongLifeWarranty = 6`
/ UI `BatteryChargeModeModel.LongLifeWarranty`; supported-modes bit `BatteryInformationBitMasks.PermanentLongLifeMode = 0x20`
(also `BatteryCapability.PermLongLifeSupported = 0x20` in the legacy plugins). The app's runtime status name for
the dependent state is `DynamicChargeStatus.LclBattery` ("long-cycle-life battery") and the UI shows a
three-year-warranty sticky banner (`DYNAMIC_CHARGE_THREEYEARWARRANTYLOCKEDTEXT`, `WarrantyIcon`,
`UUE_UXTextBlock_ChargingMode_CustomThreeYearsBatteryWarranty`).

**It is a firmware charging policy, not a charge-level setting the app writes:**

* `DSIS.SetBatteryChargingMode(mode, battery#)` writes only modes 1–4; mode 5 goes through the separate
  custom call; **modes 6 and 7 are rejected with `ChargingModeNotSupported = 251`** — there is no path that
  writes `m_nChargingMode = 6`.
* The app never offers it: `GetChargeModes()` adds only bits 0–4 of the BIOS supported mask (6 is read into
  `SupportsPermanentLongLifeMode` but not added to `AvailableChargeModes`), and
  `UpdateSettingsMetadataAsync` publishes `ChargingMode` metadata with only Standard/Express/PrimarilyAC/
  Auto/Custom.
* While mode 6 is active the app **locks** everything: `PluginSettings_ValueChanging` throws
  "Charging Mode cannot be changed because your 3 year warranty on this battery has locked it",
  `DetermineChargeModeModifyState` → `CantModifyWarrantyBattery`, the UI card is disabled
  (`CardEnabled = ModuleEnabled && !IsBatteryLongLifeWarranty`), the CLI reports
  `BatteryCannotChangeChargeModeFromPermanentLongLifeMode`, and Dynamic Charge is blocked with
  `DynamicChargeCannotChangeChargeModeFromPermanentLongLifeMode`.
* The app does *display* the custom charge-window controls for mode 6
  (`_isChargeModeCustomEnabled = ChargingMode == Custom || IsBatteryLongLifeWarranty`) — read-only, because the
  card is disabled. That, plus the warranty strings, indicates the firmware implements long-life as an enforced
  charge window owned by the battery/warranty provisioning, not by the app.
* Legacy nuance: the shipped `Dell.Enterprise.Client.Framework.Plugin.PowerManager` plugin
  (`[PluginInfo("07F41493-…","PowerManager")]`) exposes setting `Settings.ChargeMode`, whose metadata is
  `Enum.GetNames(typeof(ChargingModes))` — including `PermanentLongLifeMode = 6` and `AdvancedChargingMode = 7` —
  and its `KnobSettings.SetChargeMode` passes the value straight to the DACI `ChargeModeTable` write. Nothing in
  the UI/CLI targets that legacy key, and the active `ISystemPowerConfiguration` path guards against mode 6.

Bottom line: charge *levels* (start/stop %) are only programmed in **Custom (5)**; Long Life (6) is entered by
the platform (`LCL`/warranty battery provisioning), never by writing charge levels. On Linux there is no
Long-Life support at all (see `docs/07-linux-kernel-battery-support.md`); the closest equivalent is Custom mode
plus a low `charge_control_end_threshold` — an author-your-own window, not the firmware LCL policy.

---

## 4. Interlocks and validation rules (charge level specifically)

1. **Range validation** (`Imp_SetBatteryCustomChargeModeAsync`): `Minimum ≤ Start < Stop ≤ Maximum`
   (`Minimum/Maximum` come from BIOS `cbRes4[0]`,`cbRes4[1]`; `DeadBand` = `cbRes4[2]`).
   Violations → `ErrorEnum` `-1` (generic failure). No active battery → `-2`.
2. **DynamicCharge interlock**: while the `IDynamicCharge` plugin state is true, custom charge mode,
   ChargingMode, PeakShift and AdvancedCharge changes are refused
   (`Imp_SetBatteryCustomChargeModeAsync`, `PluginSettings_ValueChanging`).
3. **AdvancedCharge interlock**: `AdvancedChargeState == true` blocks custom charge mode; mode 7 blocks
   preset-mode changes ("Advanced Charge Policy is enabled").
4. **Warranty interlock**: `LongLifeWarranty` (mode 6) blocks all charge-mode changes
   ("3 year warranty on this battery has locked it"); UI additionally disables the whole card
   (`IsBatteryLongLifeWarranty`).
5. **Custom-mode lock-in**: CLI `configure SystemPowerConfiguration.ChargingMode <v>` verifies the value
   actually changed; if it didn't, it reports `FailCode.BatteryCannotChangeChargeModeFromCustomMode`
   ("Charging Mode is locked and can't be changed.")
   (`decompiled/do-cli/Dell.Optimizer.Cli/SettingsAction.cs`).
6. **BIOS has the last word**: on custom-mode set, the effective start/stop come back in `cbRes3` bytes
   0/1 and are what the UI re-reads and displays.

---

## 5. Read-only battery status path (charge *level* reporting)

`Dell.Enterprise.Client.Framework.Plugin.PowerManagement.PlatformAPI`
(`decompiled/.../PlatformAPI.cs`) — plain Win32, no Dell BIOS involved:

* Enumerates `GUID_DEVCLASS_BATTERY` via SetupAPI (`SetupDiGetClassDevs` with
  `DIGCF_PRESENT|DIGCF_DEVICEINTERFACE`, `SetupDiEnumDeviceInterfaces`, `SetupDiGetDeviceInterfaceDetail`).
* Opens each battery interface (`CreateFile`) and issues:
  `IOCTL_BATTERY_QUERY_TAG = CTL_CODE(41,16,0,1) = 0x294040`,
  `IOCTL_BATTERY_QUERY_INFORMATION = CTL_CODE(41,17,0,1) = 0x294044`
  (levels `BatteryInformation`, `BatterySerialNumber`),
  `IOCTL_BATTERY_QUERY_STATUS = CTL_CODE(41,19,0,1) = 0x29404C`.
* Skips UPS devices (`Capabilities & BATTERY_SYSTEM_BATTERY` must be set).

| Function | Documentation |
|---|---|
| `GetBatteryPowerState(int batteryIndex, out BATTERY_STATUS, out BATTERY_INFORMATION)` | Full tag→info→status query chain for one battery. |
| `EnumAllBatteriesSerialNumber()` | Serial numbers for all battery interfaces (`IOCTL_BATTERY_QUERY_INFORMATION` level `BatterySerialNumber`). |
| `GetAllBatteriesSerialNumbers()` | Public wrapper. |
| `GetBatteryReport(int batteryIndex)` | **Charge-level computation**: `ChargeLevel = 100` if `capacity ≥ FullChargedCapacity`, else `round(capacity*100/FullChargedCapacity + 0.51)`; `ChargeRateInMilliwatts = status.Rate`; `EstimatedUsageTimeRemaining` from `GetSystemPowerStatus().BatteryLifeTime` or `capacity/|rate|` hours; `ChargeStatus` = Discharging(1)/Idle(2)/Charging(3) from `BATTERY_STATUS.PowerState` bits (`BATTERY_DISCHARGING=2`, `BATTERY_CHARGING=4`). |
| `IsSystemPluggedIn()` / `GetSystemACLineStatus()` | `GetSystemPowerStatus` → AC line status. |
| `IsHandleValid(nint)` | Rejects 0/-1 handles. |

`BatteryReport` fields consumed downstream: `ChargeRateInMilliwatts`,
`DesignCapacityInMilliwattHours`, `FullChargeCapacityInMilliwattHours`,
`RemainingCapacityInMilliwattHours`, `ChargeLevel`, `EstimatedUsageTimeRemaining`, `ChargeStatus`.

### 5.1 Other battery interfaces — read-only (verified: no alternate charge-level setter)

Exhaustive checks of both decompiled trees show **exactly one** charge-level *write* path
(the DACI class 8 / select 19 chain above). The remaining battery interfaces are readers:

| Interface | Where | What it does |
|---|---|---|
| DTP **A3 SMI** battery/charger handlers | `Dell.TechHub.Plugins.CommonPlatformServices.Utilities` (`A3BatteryRequestHandler`, `A3ChargerRequestHandler`, `A3CallerCim`, `A3CallerSwSmi`, `A3CallerBiosIntf`, `A3RequestHandler`, `BaseA3Caller`) | Telemetry retrieval only (`GetInstances` via `BaseDataRetrieveRequestHandler`); A3 = Dell SMI command family executed over WMI (`root\dcim\...`), software-SMI, or BIOSIntf; on the native side this is the DBUtil layer (`\\.\Dell_Instrumentation` IOCTLs, request byte 0xA3) documented in `docs/05-native-bios-interface.md`. |
| Dell Command Monitor diagnostics namespace | `Dell.Enterprise.Client.Framework.Plugin.Battery.BatteryController` | Reads `root\dcim\sysman\diagnostics` to decide whether the battery exposes BMU (Battery Management Unit) diagnostics — feeds Dynamic Charge's BMU data collection (`docs/04` §1). |
| TechHub `BatteryCollector` | `Dell.TechHub.Plugins.BatteryCollector` | Static/dynamic/analytics telemetry (see `docs/04` §5). |

Grep evidence for the negative claim: `ChargingMode`/`ChargingLimit`/`ChargeLevel` setters appear only in
`Dell.Enterprise.Client.Framework.{Contract,Plugin.PowerManagement,Plugin.PowerManager,BiosIntf}`,
`Dell.Optimizer.Plugin.{SystemPowerConfiguration,DynamicCharge,BatteryExtender}`,
`Dell.TechHub.{Datatypes,Commodity.Interfaces,CommonPlatformServices.Interfaces,Plugins.CommonPlatformServices}`
(data models / commodity interfaces, no additional firmware write path) and `do-cli`.

---

## 6. CLI surface (`do-cli.exe` / `do-cli.dll`, `Dell.Optimizer.Cli`)

| Command | Function | Effect |
|---|---|---|
| `do-cli configure SystemPowerConfiguration.ChargingMode <value>` | `ConfigureCommand` → `SettingsAction.SetPowerChargingModeValueAsync(name, value)` | Writes the `ISystemPowerConfiguration.ChargingMode` setting; verifies the value actually stuck (else "Charging Mode is locked and can't be changed."). |
| `do-cli systempowerconfiguration --alertsrestore` | `SystemPowerConfigurationCommand.AlertsRestoreAction.DoAction` | `ISystemPowerConfiguration.RestoreBIOSAlertsAsync`. |
| `do-cli advancedchargeconfiguration ...` | `PowerAdvancedChargeCommand.UpdateAdvancedChargeAction` | Builds `AdvancedCharge`/`AdvancedChargeDailySettings` per weekday → `SetAdvancedChargeInformationAsync`. Options incl. `--day`, `--state`, start/end times. |
| `do-cli peakshift ...` | `PowerPeakShiftCommand` | `--day`, `--state`, `--starttime`, `--endtime`, `--chargestarttime` (hours:minutes) → `SetPeakShiftInformationAsync`. |
| `do-cli get ...` / report commands | `GetCommand`, `DellOptimizerSettingsReport*` | Dump settings incl. charging mode. |

---

## 7. Adjacent battery features (function-level summaries)

### 7.1 Dynamic Charge (`Dell.Optimizer.Plugin.DynamicCharge`, ML-assisted adaptive charging)

Plugin publishes settings `IDynamicCharge.State`. Key functions
(`decompiled/Dell.Optimizer.Plugin.DynamicCharge/.../DynamicCharge.cs`, 683 lines):

| Function | Documentation |
|---|---|
| `OnActivate/OnDeactivate` | Enable/disable the feature, re-evaluate charge-mode interlocks. |
| `PluginSettings_ValueChanging` | Enforces mutual exclusion with PeakShift (`IsPeakShiftEnabledAndLocked`) and preset charge modes. |
| `GetCurrentChargeModes()` | Snapshot of `AvailableChargeModes` for policy decisions. |
| `StartDynamicChargeControllerAsync` / `TryStartDynamicChargeControllerOnUserLogon` | Spawns `Dnn.exe` (native ML runner, `Plugins/DynamicCharge/`) with `MLInputParameter` (model inputs incl. `IMLInputParameter`, `ProcessTable`/`IProcessTable`, `LogonUser`/`ILogonUser`). |
| `SchedulerTimerExpired` / `InitializeScheduler` / `InitializeSchedulerForRetry` / `DidSchedulerTimerExpire` / `IsSchedulerRunning` / `IsSchedulerExpired` | Periodic policy re-evaluation with retry. |
| `ReadyToRunAsync()` | Precondition check (AC, battery present, no conflicting policies). |
| `DynamicChargeController` (`IDynamicChargeController`) | Runs DNN inference to choose charge policy; results feed `ChargingModeProcessing` (decides standard/custom/limits) and `PersistentSettings`/`Settings`/`DynamicChargeConfig`. |
| `OnUserAction(ActionInfo)` / `ToastAction` | User feedback (toast when policy changes). |

### 7.2 Intelligent Battery Extender (`Dell.Optimizer.Plugin.BatteryExtender`)

Publishes `IBatteryExtender.State`. Functions in
`decompiled/Dell.Optimizer.Plugin.BatteryExtender/`:
`BatteryExtender` (plugin lifecycle), `BatteryExtenderController` (policy loop),
`Persona`/`PersonaSettings`/`IPersonaSettings` (user-behaviour personas),
`SetPersonaState`/`ISetPersonaState`, `SystemPowerState`/`ISystemPowerState` (AC/battery events),
`Library`/`ILibrary` (native interop helper), `BatteryExtenderConfig`, `PersistentSettings`,
`ProxySettings`, `Settings`, `BatteryExtenderToastAction`.
Native helper `BatteryExtenderPlugin.GetClusterId.dll` (see Ghidra doc).

### 7.3 Peak Shift & Advanced Charge

* PeakShift: charge only during off-peak windows (`PeakShift`/`PeakShiftDailySettings{StartTime,EndTime,ChargeTime}`,
  `PeakShiftConfig` payload, battery-threshold setting min 15%). Writes via `ExecuteDACI(8,19)` with
  `biosDataType=PEAK_SHIIFT_CONFIG`.
* AdvancedCharge (mode 7): per-weekday "working hours" bitmaps (`BeginningOfDay`, `WorkPeriod` bytes per
  day) programmed through the same `AdvanceBatteryConfig`; master enable/disable via SMBIOS tokens
  885/884 (`AssertSmbiosToken`, class 1/select 0).

---

## 8. Evidence index

| Claim | Evidence |
|---|---|
| Custom charge write payload & DACI (8,19) | `DSIS.SetBatteryCustomChargingMode` — `decompiled/Dell.Enterprise.Client.Framework.Plugin.PowerManagement/Dell.Enterprise.Client.Framework.Plugin.PowerManagement/DSIS.cs` |
| Charge read command 3, DACI (8,18) | `DSIS.GetBatteryProperty` (same file) |
| Limits/mode decoding | `BatteryPropertyParser.Parse` — `...SmbiosTableParsers/BatteryPropertyParser.cs` |
| Policy/interlocks | `SystemPowerConfiguration.PluginSettings_ValueChanging`, `Imp_SetBatteryCustomChargeModeAsync` — `decompiled/Dell.Optimizer.Plugin.SystemPowerConfiguration/.../SystemPowerConfiguration.cs` |
| UI entry point | `ChargingModeViewModel.OnRangeSliderMouseUp` — `decompiled/Dell.UUE.PowerPlugin.UI/.../ChargingModeViewModel.cs` |
| SMBIOS token path (884/885) | `PowerManagement.Imp_EnableAdvancedChargeAsync`, `DSIS.AssertSmbiosToken` |
| P/Invoke gateway | `Dell.Enterprise.Client.Framework.BiosIntf/Dell.Enterprise.Client.Framework.BiosIntf/BiosIntfWrapper.cs` |
| Charge-level % math | `PlatformAPI.GetBatteryReport` — `.../PlatformAPI.cs` |
| Native hardware access | `docs/05-native-bios-interface.md`, `ghidra/decompiled_*.c` |
