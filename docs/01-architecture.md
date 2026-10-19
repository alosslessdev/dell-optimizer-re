# 01 — Application architecture (Dell Optimizer 6.3.5.0)

Ground truth: files extracted per `docs/00-extraction.md`; assemblies decompiled in `decompiled/`
(targeted) and `decompiled_all/` (all unique managed binaries). 1746 managed + 82 native binaries
across the four MSIs.

## 1. What gets installed (four MSI packages)

| Package | Install root | Role |
|---|---|---|
| **Dell Optimizer.msi** | `C:\Program Files\Dell\DellOptimizer` | The application: host exe, plugin framework, feature plugins, CLI |
| **Dell AppCore.msi** | `C:\Program Files\Dell\DellOptimizer\Console` | Console shell: `DellOptimizer.ThickClient.exe`, `DellOptimizer.Systray.exe`, WPF/WebView2 UI runtime |
| **Dell Core Services.msi** | `C:\Program Files\Dell\DTP` | Dell TechHub Platform (DTP): subagents (Analytics/DataManager/Instrumentation), `DBUtilDriver\DellInstrumentation.sys`, native BIOS libs |
| **Dell UserSubAgent.msi** | `C:\Program Files\Dell\PlatformUserSubAgent` | Per-user telemetry/workflow subagent |

Prereqs installed by the suite: .NET Desktop Runtime 10 (x64/arm64), ASP.NET Core Runtime 10,
VC++ redistributables, Intel Context Sensing Technology.

## 2. Process/module map (`Dell\DellOptimizer`)

```
DellOptimizer.exe                apphost (hostfxr) → managed bootstrap
├── Dell.Enterprise.Client.Framework*.dll      plugin framework ("Unified Agent")
│     .Contract.dll                             published RPC contracts (IPowerManagement,
│                                               ISystemPowerConfiguration, IMonitor, ...)
│     .Plugin.<X>.dll                           contract implementations ("plugins",
│                                               Plugins/Bootstrap/*.dll)
│     .BiosIntf.dll / .BiosIntfWrapper.dll      managed+native BIOS calling-interface (DACI)
├── Plugins\                                    feature plugins (Dell.Optimizer.Plugin.*)
│     ├── Bootstrap\                            framework plugins (Battery, PowerManagement,
│     │                                         PowerManager, DtpAdapter, DtpProxy, ...)
│     ├── DynamicCharge\ (Dnn.exe, model data)  ML adaptive charging
│     └── BatteryExtender\                      intelligent battery extender data
├── AppPlugins\                                 UI plugins (Dell.UUE.*)
│     ├── Dell.UUE.PowerPlugin.UI.dll           WPF power/battery UI (charge-level slider)
│     ├── Dell.UUE.PowerPlugin.Core.dll         UI-side battery settings façade
│     ├── Dell.UUE.CoreCommon.dll               repositories (BatteryRepository → RPC)
│     └── ... Collaboration/PresenceDetection/Systray/Suggestion plugins
├── UnifiedAgentProxy.dll                       RPC proxy/host for contracts
├── Dell.RPC.Transport.dll                      IPC transport
├── do-cli.exe / do-cli.dll                     command-line interface
├── Dell.TechHub.*.dll                          TechHub SDK/commodity clients (remote DTP)
└── BIOSIntf.dll, Dell.Enterprise.Client.Framework.BiosIntfWrapper.dll (native)
```

`file` classification: 1746 managed (CIL) vs 82 native. Native Dell code: `BIOSIntf.dll`,
`Dell.Enterprise.Client.Framework.BiosIntfWrapper.dll`, `Dell.TechHub.NativeLibraryWrapper.dll`,
`DBUtilAccessLib_Win64.dll`, `Dnn.exe`, `ddc_tool.exe`, `DPCC.dll`, the `*.exe` apphosts, plus
third-party natives (`WebView2Loader`, `e_sqlite3`, `microsoft.management.infrastructure.native.*`,
`ipfcoresdk`, `vcruntime*`).

## 3. Plugin framework

* Plugins are assemblies with attribute-declared identity: `[PublishedInterface(typeof(IFoo))]`,
  `[PublishedUnelevatedInterface(...)]`, `[DtpPlugin(guid, name, desc)]`, `[Plugin]`, `[PluginRequires]`,
  `[CommoditySupport]/[ItemEnumerator]/[OperationSupportChecker]` (TechHub commodities).
* Each plugin class derives from an aspect base (`PowerManagementAspect`,
  `SystemPowerConfigurationAspect`, `BaseCommoditySupportPlugin`, ...) implementing
  `Imp_*` methods that back the contract's `Task<...> Async` calls.
* Cross-plugin calls: `PluginRequest.RequestContract<IFoo>()`, settings via `ISettings`
  (`SettingsName` keys like `ISystemPowerConfiguration.ChargingMode`) with
  `ValueChanging/ValueChanged/MetadataChanging` events.
* UI plugins (WPF) implement `IConsolePlugin/IConsolePagePlugin/IFrameworkPlugin` and use
  CommunityToolkit.Mvvm (`ObservableRecipient`, `Messenger`).

## 4. Two hardware-access planes

1. **Dell BIOS calling interface (DACI)** — in-process from the Optimizer plugins:
   `DSIS` → `BiosIntfAgent.ExecuteDACI(class, select, payload)` → P/Invoke
   `Dell.Enterprise.Client.Framework.BiosIntfWrapper.dll` → `BIOSIntf.dll` → firmware.
   Used for: battery charge modes/limits, Peak Shift, Advanced Charge, SMBIOS tokens, thermal (USTT),
   keyboard illumination. Raw SMBIOS is read from WMI `root\wmi:MSSmBios_RawSMBiosTables`;
   token table = SMBIOS type 0xDA ("calling interface"). Details: `docs/02-battery-charge-levels.md`
   and `docs/05-native-bios-interface.md`.
2. **Dell TechHub Platform (DTP, remote service)** — commodity RPC to `C:\Program Files\Dell\DTP`
   subagents (`Dell.TechHub.Plugins.PowerCommodity.dll` etc.). The InstrumentationSubAgent carries its
   own `BIOSIntf.dll`/`DBUtilAccessLib_Win64.dll` and the kernel driver
   `DBUtilDriver\DellInstrumentation.sys` (exposed as `DellInstrumentation.inf`). PowerCommodity in
   this build serves **thermal** (ThermalMode/FanFailureMode via DACI `GetUSTT`/`SetUSTT`), not
   battery charge levels.

## 5. Battery/power feature map

| Feature | Assemblies | Contract surface |
|---|---|---|
| Charge mode + **charge levels** (start/stop %) | `Contract.SystemPowerConfiguration`, `Plugin.SystemPowerConfiguration`, `Plugin.PowerManagement`, `BiosIntf*`, `UUE.PowerPlugin.*`, `UUE.CoreCommon` | `ISystemPowerConfiguration.SetBatteryCustomChargeModeAsync` |
| Advanced Charge (scheduled, mode 7) | same + `Contract.PowerManagement.AdvancedChargeMode` | `ISystemPowerConfiguration.SetAdvancedChargeInformationAsync`; enable via SMBIOS token 884/885 |
| Peak Shift | same + `PeakShift*` contracts | `ISystemPowerConfiguration.SetPeakShiftInformationAsync` |
| Dynamic Charge (ML adaptive) | `Plugin.DynamicCharge`, `Plugins/DynamicCharge/Dnn.exe` | `IDynamicCharge.State` setting |
| Intelligent Battery Extender | `Plugin.BatteryExtender`, `BatteryExtenderPlugin.GetClusterId.dll` | `IBatteryExtender.State` setting |
| Battery status/level reporting | `Plugin.PowerManagement.PlatformAPI` (Win32 battery IOCTLs) | `IPowerManagement.GetBatteryReportAsync` |

## 6. CLI

`do-cli.exe` (native apphost) + `do-cli.dll` (`Dell.Optimizer.Cli`): commands
`configure`, `get`, `systempowerconfiguration`, `advancedchargeconfiguration`, `peakshift`,
`appperformance`, `audio`, `network`, `notification`, `version`, `help`, report generators
(`Dell.Optimizer.Cli.DellOptimizerReport`). Charge-relevant specifics in
`docs/02-battery-charge-levels.md` §6.

## 7. Installer internals (for completeness)

The suite installer (`DellOptimizer.exe`, InstallShield SetupSuite) drives: prerequisite redists,
`ModularDeployment.ps1`/`HardwareChecks.ps1`/`InstallKey.ps1` PowerShell custom actions,
`Tool/x64|ARM64/ModularDeploymentValidator` + `InstallerCustomAction` (.NET), MSIs per component,
legacy-app removal (`RemoveLegacyApps.ps1`, `UninstallDPM.ps1`, `RemoveIntelContextService.ps1`),
and localization (13 languages). Full listing: `docs/00-extraction-log.txt`.
