# 04 — Battery-adjacent features (function-level reference)

Companion to `docs/02-battery-charge-levels.md`. Sources: `decompiled/Dell.Optimizer.Plugin.DynamicCharge/`,
`decompiled/Dell.Optimizer.Plugin.BatteryExtender/`. All functions of all types are listed.

## 1. Dynamic Charge (`Dell.Optimizer.Plugin.DynamicCharge.dll`)

ML-assisted adaptive charging: collects smart-battery (BMU) history, runs a DNN
(`Plugins/DynamicCharge/Dnn.exe`) over a feature vector, and proposes a charge-mode change to the user
(toast), then applies it via the standard charge-mode pipeline (`docs/02` §3). Publishes the setting
`IDynamicCharge.State`; when true it **locks** ChargingMode/custom charge/PeakShift/AdvancedCharge
(`SystemPowerConfiguration.PluginSettings_ValueChanging`).

### 1.1 `DynamicCharge : DynamicChargeAspect` (DynamicCharge.cs, 683 lines)

| Function | Documentation |
|---|---|
| `GetImplementationType()` | Returns `typeof(DynamicCharge)`. |
| `DynamicCharge(IAgent)` / `DynamicCharge(IAgent, IDynamicChargeController)` | Ctors; second injects the controller (test seam). |
| `OnStart()` / `OnStop()` | Lifecycle; stops scheduler/controller (`_SemaphoreSlim(1,1)`, `_Locker` serialize). |
| `OnActivate()` / `OnDeactivate()` | Enable/disable `IDynamicCharge.State`; on activate starts scheduler + controller attempt. |
| `CreateSettingsHandler()` | Binds `IDynamicCharge.State` and DynamicCharge config settings. |
| `CreateConfigurationHandler()` | Config-file handler (`DynamicChargeConfig`). |
| `OnUserAction(ActionInfo)` | Toast response handling (accept/decline mode change). |
| `IsInternalRequest()` | Distinguishes internal settings writes from external (UI/CLI) ones. |
| `PluginSettings_ValueChanging(...)` | Interlock enforcement: refuses changes when PeakShift enabled+locked (`IsPeakShiftEnabledAndLocked`); charge-mode transitions constrained to `GetCurrentChargeModes()`. |
| `IsPeakShiftEnabledAndLocked()` | PeakShift state/lock query. |
| `GetCurrentChargeModes()` | Snapshot of supported `BatteryChargeMode` values for policy checks. |
| `PluginSettings_ValueChanged(...)` / `CheckSettingsChange(name, value)` | React to setting writes; restart/stop the controller. |
| `ActivateAsync()` | Activation work (state propagation). |
| `PluginEnabledAsync()` | Precondition check for enabling. |
| `DidSchedulerTimerExpire()` / `IsSchedulerRunning(int eventId)` / `IsSchedulerExpired(int eventId)` | Scheduler state queries. |
| `SchedulerTimerExpired(object, PluginSchedulerEventArgs)` | Periodic policy re-evaluation; triggers `StartDynamicChargeControllerAsync`. |
| `InitializeScheduler()` / `InitializeSchedulerForRetry(int eventId)` | Sets up (retry) timers. |
| `SetDependencyFailure(FailResult)` | Records failure state/reason (used for telemetry/UI). |
| `TryStartDynamicChargeControllerOnUserLogon(object, LogonEventArgs)` | Defers controller start until user logon. |
| `StartDynamicChargeControllerAsync()` | Launches the inference pipeline (controller `StartAsync`). |
| `ReadyToRunAsync()` | Gates execution: AC attached, battery present, BMU data available, no conflicting policies. |
| `ConfigurePersistentSettingsFile()` | Initializes `%LOCALAPPDATA%\...\DynamicCharge` persistence (`PersistentSettings`). |

### 1.2 `DynamicChargeController : IDynamicChargeController` (DynamicChargeController.cs, 338 lines)

| Function | Documentation |
|---|---|
| `Instance` (static) | Lazy singleton. |
| `DynamicChargeController()` | Ctor; `LogonUser` helper. |
| `StartAsync()` | Core pipeline: `GetBMUDataTableDiffsAsync()` (8 battery-history diff tables), writes `MLFile.csv` under `%LOCALAPPDATA%\...\DynamicCharge` with header `dc_time,true_dc_time,ac_time,batt_time,discharge_events,charge_events,ac_sessions,dc_sessions,time_in_rest,time_in_fastcharge,time_in_stdcharge,time_in_topoff,time_in_NVDC,dc_events_gt_3hrs,discharge_events_end_below_5pct,discharge_events_end_below_30pct,discharge_cycles_start_below_60pct`, fills features via `ChargingModeProcessing.WriteChargingInformation`, then runs `Dnn.exe` (`_DnnExeLocation = <install>\Plugins\DynamicCharge\DNN.exe`) and interprets its verdict; asks user via toast (`DynamicChargeModeChangeRequest`, `Toast_DynamicCharge_ChargeMode_*` resources) before applying. |
| `GetBMUDataTableDiffsAsync()` | Retrieves smart-battery (BMU / "Batman3") usage tables and their deltas. |
| remaining members | Toast plumbing (`ToastAction`), settings (`IBattery.Batman3Version`), logging. |

### 1.3 `ChargingModeProcessing` (ChargingModeProcessing.cs)

| Function | Documentation |
|---|---|
| `ChargingModeProcessing()` | Ctor; `ProcessTable`, `MLInputParameter`. |
| `WriteChargingInformation(List<string> diffTables, StreamWriter, string BmuVersion)` | Requires exactly 8 tables; converts to `ulong` grids; writes feature row: `ProcessTable1 + ProcessTable2` (dc/true-dc/ac/batt time sums), `ProcessTable3A/3B/4A/4B` (events/sessions), then ML features `ProcessTimeInRest/FastCharge/StdCharge/TopOff/NVDC`, `ProcessDcEventsGt3Hrs`, `ProcessDischargeEventsEndBelow5Pct/30Pct/60Pct`. Returns false on parse/write failure. |
| `ConvertToUlongArrays(List<string>)` | CSV string tables → `List<List<ulong>>`. |

### 1.4 Support types

| Type | Members / role |
|---|---|
| `ProcessTable : IProcessTable` (132 lines) | `ProcessTable1..4B`, `ProcessTrueDCTime` — time/charge-event aggregations from BMU tables. |
| `MLInputParameter : IMLInputParameter` (361 lines) | `ProcessTimeInRest/FastCharge/StdCharge/TopOff/NVDC`, `ProcessDcEventsGt3Hrs`, `ProcessDischargeEventsEndBelow5Pct/30Pct/60Pct` — feature extractors (BMU charge-state histograms per `BmuVersion`). |
| `LogonUser : ILogonUser` | Session/user detection for deferred start. |
| `Settings` / `PersistentSettings` (67) / `DynamicChargeConfig` (20) | Setting definitions, `%LOCALAPPDATA%` persistence, config binding. |
| `ToastAction` (7) | Toast action ids for the charge-mode prompt. |

## 2. Intelligent Battery Extender (`Dell.Optimizer.Plugin.BatteryExtender.dll`)

Persona-based battery-life extension ("Intelligent Battery Extender"); setting `IBatteryExtender.State`.

| Type | Function-level contents (`decompiled/Dell.Optimizer.Plugin.BatteryExtender/`) |
|---|---|
| `BatteryExtender : BatteryExtenderAspect` (`BatteryExtender.cs`) | Plugin lifecycle (`OnStart/OnStop/OnActivate/OnDeactivate`, `CreateSettingsHandler`, `GetImplementationType`), settings `IBatteryExtender.State` handling, controller orchestration. |
| `BatteryExtenderController : IBatteryExtenderController` | Policy loop: observes `ISystemPowerState` (AC/battery transitions) and `IPersonaSettings`, decides throttling/persona switches, reports via toasts. |
| `Persona` / `PersonaSettings : IPersonaSettings` | Learned user-persona model and its persistence. |
| `SetPersonaState : ISetPersonaState` | Persona state transitions (apply/revert). |
| `SystemPowerState : ISystemPowerState` | AC/battery power-state source. |
| `Library : ILibrary` | Native interop helper (pairs with `Plugins/Bootstrap/BatteryExtenderPlugin.GetClusterId.dll`, native — see `docs/05-native-bios-interface.md`). |
| `BatteryExtenderConfig`, `PersistentSettings`, `ProxySettings`, `Settings` | Configuration, `%LOCALAPPDATA%` persistence, plugin-settings proxies. |
| `BatteryExtenderToastAction` | Toast action ids. |

## 3. Peak Shift (in `Plugin.SystemPowerConfiguration` + `Plugin.PowerManagement`)

* Contracts: `PeakShift { DailySettings: DayOfWeek → PeakShiftDailySettings { StartTime, EndTime, ChargeTime } }`,
  `PeakShiftConfig` (BIOS payload).
* Functions: `SystemPowerConfiguration.Imp_GetPeakShiftInformationAsync`,
  `Imp_SetPeakShiftInformationAsync` (equality-suppressed redundant writes via
  `IsPSDictDailySettingsEqual`/`IsPeakShiftDailySettingsEqual`/`IsTimeSettingsEqual`),
  `DSIS.GetPeakShiftInformation`/`SetPeakShiftInformation` (`ExecuteDACI(8,18/19)`,
  `biosDataType = PEAK_SHIIFT_CONFIG`), `PeakShiftParser.Parse/ToBiosIntfStruct`.
* Interlocks: blocked by DynamicCharge (locked), minimum battery threshold 15
  (`PowerSettingsConstants.PeakShiftBatteryMinimumThreshold`).
* CLI: `do-cli peakshift --day --state --starttime --endtime --chargestarttime`.

## 4. Advanced Charge (mode 7)

* Contracts: `AdvancedCharge { DailySettings: DayOfWeek → AdvancedChargeDailySettings }`,
  `AdvancedChargeMode { Version ("01.00"), DailySettings: DayOfWeek → AdvancedChargeModeDailySettings
  { BeginningOfDay (byte bitmap), WorkPeriod (byte bitmap) } }`.
* Functions: `SystemPowerConfiguration.Imp_Get/SetAdvancedChargeInformationAsync`,
  `CreateAdvancedChargeModeDailySettings`, `DSIS.SetBatteryAdvancedChargeMode`
  (`ToBiosIntfStruct(1, BatteryChargingModeEnum.AdvancedCharge)`, `ExecuteDACI(8,19)`),
  `PowerManagement.Imp_EnableAdvancedChargeAsync` → `DSIS.AssertSmbiosToken(885|884)`,
  `AdvancedChargeModeParser.Parse/ToBiosIntfStruct/ParseFromBiosIntfHours/ConvertToBiosIntfHours`.
* Interlocks: `AdvancedChargeState == true` blocks custom charge mode; DynamicCharge locks it;
  `IsAdvancedChargeEnabledAndLocked()` / `IsChargingModeLocked()` gate changes.
* CLI: `do-cli advancedchargeconfiguration --day --state --starttime --endtime`.

## 5. DTP battery telemetry (TechHub, remote plane)

`Dell.TechHub.Plugins.BatteryCollector` (Dell Core Services, `C:\Program Files\Dell\DTP\InstrumentationSubAgent`)
collects battery telemetry over the TechHub commodity plane — separate from the charge-control path:

* `BatteryDataRetriever : IBatteryDataRetriever` — gathers `BatteryStaticDataEx`, `BatteryDynamicDataEx`,
  `BatteryAnalyticsDataEx` (protobuf/MessagePack datatypes in `Dell.TechHub.Datatypes`).
* `BatteryDynamicData` fields: `TemperatureInKelvin`, `VoltageInmV`, `CurrentInmA`,
  `CurrentChargePercentage`, `RemainingCapacityInmAh/mWh`, `CycleCount`, `ManufacturerAccessCode`,
  `FullChargeCapacityInmAh/mWh`, `ChargeRateInmW`, `DischargeRateInmW`.
* `Contract.DtpAdapter.{BatteryStaticData,BatteryDynamicData,ChargingModes}` and
  `Dell.TechHub.AnalyticsDatatypes` (`ChargeStart`/`ChargeStop` analytics events) consume it.

Several versioned copies of `Dell.TechHub.Datatypes`/`Dell.TechHub.Commodity.Interfaces` ship in
different packages (per-package builds); see `docs/catalog/` for each hash-suffixed variant.
Full function-level detail is covered by the TechHub family reference (see `docs/03-function-catalog.md`).

## 6. Cross-feature interlock summary

| Feature being changed | Blocked when |
|---|---|
| ChargingMode (preset) | mode is LongLifeWarranty(6) or Advanced(7); DynamicCharge enabled |
| Custom charge levels | DynamicCharge enabled; AdvancedChargeState true; no active battery; out of `[Minimum,Maximum]`; Start ≥ Stop |
| PeakShift | DynamicCharge enabled+locked |
| AdvancedCharge | DynamicCharge enabled+locked; ChargingMode policy locked |
| ThermalMode | fan failure reported |
