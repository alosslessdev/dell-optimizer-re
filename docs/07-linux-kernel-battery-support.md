# 07 — Can Linux do the battery-level changes the Dell Optimizer app does?

Source analysed: **Linux 7.2.9** (kernel.org tarball, extracted to `linux/linux-7.2.9/`, 1.8 GB;
release matching this machine's running kernel). All line references are into that tree.

## 1. Verdict

| Dell Optimizer (Windows) feature | Linux 7.2.9 equivalent | Supported? |
|---|---|---|
| Preset charge modes: Standard / Express / Primarily-AC / Adaptive | `charge_types` on `BAT0`: Standard / Fast / **Trickle** (="Primarily AC Use") / Adaptive / Custom | **Yes** |
| **Custom charge start/stop levels** (`SetBatteryCustomChargeModeAsync`) | `charge_control_start_threshold`, `charge_control_end_threshold` (+ select `Custom` in `charge_types`) | **Yes** |
| BIOS-reported allowable range / granularity | not exposed — kernel hardcodes 50–95 / 55–100 / min-diff 5 | **Partial** |
| Long-Life Warranty mode (app mode 6) | no token in kernel | No |
| **Advanced Charge** (mode 7, per-weekday schedule, enable/disable tokens 884/885) | nothing in tree | **No** |
| Peak Shift (off-peak charge windows) | nothing in tree (only HP has a `PEAKSHIFT` WMI constant) | No |
| Dynamic Charge (ML, `Dnn.exe`) / Intelligent Battery Extender | nothing in tree | No |
| Battery telemetry (design/full-charge capacity, chemistry, temp, serial) | ACPI battery + `dell-wmi-ddv` (read-only) | Yes (read-only) |
| Raw SMBIOS calling-interface access (what the app uses) | `/dev/wmi/dell-smbios` char device + ioctl | **Yes** (root/CAP_SYS_RAWIO) |

So: **Linux can set the same charge levels and charge modes** (same firmware settings), but through a
different transport, with kernel-hardcoded limits, and it cannot do the app's Advanced Charge schedule,
Peak Shift, Dynamic Charge or Battery Extender at all.

## 2. What the kernel implements (`drivers/platform/x86/dell/dell-laptop.c`)

Charge modes are SMBIOS tokens mapped onto the generic `power_supply` charge-type ABI
(`dell-laptop.c:104-116`):

```c
struct battery_mode_info { int token; enum power_supply_charge_type charge_type; };
static const struct battery_mode_info battery_modes[] = {
	{ BAT_PRI_AC_MODE_TOKEN,   POWER_SUPPLY_CHARGE_TYPE_TRICKLE },  /* "Primarily AC Use" */
	{ BAT_EXPRESS_MODE_TOKEN,  POWER_SUPPLY_CHARGE_TYPE_FAST },
	{ BAT_STANDARD_MODE_TOKEN, POWER_SUPPLY_CHARGE_TYPE_STANDARD },
	{ BAT_ADAPTIVE_MODE_TOKEN, POWER_SUPPLY_CHARGE_TYPE_ADAPTIVE },
	{ BAT_CUSTOM_MODE_TOKEN,   POWER_SUPPLY_CHARGE_TYPE_CUSTOM },
};
```

Token IDs (`dell-smbios.h:36-42`), all in the 0x03xx battery token block:

| Token | ID | Meaning |
|---|---|---|
| `BAT_PRI_AC_MODE_TOKEN` | 0x0341 | Primarily AC (Linux calls it *Trickle*) |
| `BAT_ADAPTIVE_MODE_TOKEN` | 0x0342 | Adaptive |
| `BAT_CUSTOM_MODE_TOKEN` | 0x0343 | Custom (uses start/end thresholds) |
| `BAT_STANDARD_MODE_TOKEN` | 0x0346 | Standard |
| `BAT_EXPRESS_MODE_TOKEN` | 0x0347 | Express (Fast) |
| `BAT_CUSTOM_CHARGE_START` | 0x0349 | custom start threshold (**the charge level**) |
| `BAT_CUSTOM_CHARGE_END` | 0x034A | custom stop threshold |

Everything is read/written through the token transport:

```c
dell_battery_set_mode(tokenid)            -> dell_set_std_token_value(buffer, tokenid, USE_TVAL)
dell_battery_read(tokenid)                -> dell_send_request_for_tokenid(buffer, CLASS_TOKEN_READ, SELECT_TOKEN_STD, ...)
dell_battery_mode_is_active(tokenid)      -> token->value == read(tokenid)
```

Custom thresholds with **kernel-side clamping** (`dell-laptop.c:2232-2267`):

```c
#define CHARGE_START_MIN 50
#define CHARGE_START_MAX 95
#define CHARGE_END_MIN   55
#define CHARGE_END_MAX  100
#define CHARGE_MIN_DIFF   5
```
* `charge_control_start_threshold` write → `clamp(start, 50, 95)`, and if `end - start < 5`, `start = end - 5`.
* `charge_control_end_threshold` write → `clamp(end, 55, 100)`, and if `end - start < 5`, `end = start + 5`.
* Reads reject out-of-range stored values with `-EIO` (`dell-laptop.c:2317-2384`).

Sysfs attributes registered via the ACPI battery hook on the **primary battery only**
(`dell-laptop.c:2387-2429`; `dell_battery_supported()` requires `power_supply->desc->name == "BAT0"`):

```
/sys/class/power_supply/BAT0/charge_types                     (rw)  e.g. "Fast [Standard] Adaptive Custom"
/sys/class/power_supply/BAT0/charge_control_start_threshold   (rw)  50..95
/sys/class/power_supply/BAT0/charge_control_end_threshold     (rw)  55..100
```

Generic ABI definitions: `Documentation/ABI/testing/sysfs-class-power:352-430`
(`charge_type` since April 2019, `charge_types` since December 2024);
enum: `include/linux/power_supply.h:45-55`. `charge_control_end_threshold`'s doc explicitly says drivers
round written values and that read-back shows the actual threshold — matching the app's behaviour of
reading BIOS-clamped values back (`cbRes3[0..1]`).

Other Dell laptops' charge support: `alienware-wmi*.c` has **no** charge/battery code;
`dell-wmi-ddv.c` exposes battery telemetry (`DELL_DDV_BATTERY_*`: design/full-charge capacity,
manufacture name/date, serial, chemistry value, temperature…) — read-only.

## 3. How it reaches firmware (vs the app's DACI path)

`drivers/platform/x86/dell/dell-smbios*.c` implements the same "SMBIOS calling interface" the Windows
app drives through `BiosIntfWrapper.dll`/`BIOSIntf.dll`:

* **Token table + supported-class bitmask**: parsed from the SMBIOS **type 0xDA ("Calling interface")**
  table (`dell-smbios-smm.c:40-52`: `case 0xda: parse_da_table(dm)`), the same structure the app reads as
  SMBIOS type 218 to build `_smbiosTokens` (`docs/02-battery-charge-levels.md` §3.6). Calls are rejected
  unless `da_supported_commands & (1 << cmd_class)` — identical semantics to the app's
  `IsClassSupported(class)` (`dell-smbios-base.c:184-200`).
* **Two transports, WMI preferred**:
  * WMI: ACPI-WMI method with GUID `A80593CE-A997-11DA-B012-B622A1EF5492`
    (`dell-smbios-wmi.c:32`), invoked as `wmidev_invoke_method(wdev, 0, 1, ...)` with a
    `dell_wmi_smbios_buffer` (`dell-smbios-wmi.c:51-70`); registered with **priority 1**
    (`dell-smbios-wmi.c:261`).
  * SMM: direct SMI via `dcdbas` — `command.magic = SMI_CMD_MAGIC`, `ecx = 0x42534931` ("BSI1"),
    buffer physical address in `ebx` (`dell-smbios-smm.c:52-66`); registered with **priority 0**
    (`dell-smbios-smm.c:128`).
  * Selection: highest priority wins (`dell-smbios-base.c`, `dell_smbios_call()`: `priv->priority >= selected->priority`).
* **Difference vs the Windows app**: the app used the WMI object `ROOT\WMI!WMI_Query.DoBFn`
  (verified in `ghidra/decompiled_BIOSIntf_app.c`, 5 references; GUID `A80593CE…` does **not** appear in
  the app's binaries). Different front-ends, same firmware SMBIOS 0xDA calling interface.
* The app additionally used DACI **class 8 / select 18–19** with `AdvanceBatteryConfig`
  (`m_nChargingMode`, `m_nStartChrgLimit`, `m_nStopChrgLimit`); **the kernel never issues class-8 calls** —
  Linux drives the same settings via class-1 token writes (0x0349/0x034A for the levels, 0x0341-0x0347 for
  the mode).

## 4. Userspace access to the raw interface (can a tool replicate the app's calls?)

`/dev/wmi/dell-smbios` (char device, `dell-smbios-wmi.c:203`), documented in
`Documentation/ABI/testing/dell-smbios-wmi` (kernel 4.15+). Protocol: `read()` a u64 for the required
buffer size, then `ioctl(DELL_WMI_SMBIOS_CMD)` — `_IOWR(WMI_IOC, 0, struct dell_wmi_smbios_buffer)`
(`include/uapi/linux/wmi.h:40,67-68`) — with the buffer carrying `class`, `select` and `input[]`.

Filtering (`dell-smbios-base.c:184-292`):

| Check | Effect |
|---|---|
| `cmd_class > 30` or `!(da_supported_commands & (1<<class))` | rejected |
| `call_blacklist` (manufacturing/diagnostics/kernel-handled: `CLASS_INFO/SELECT_RFKILL`, `CLASS_KBD_BACKLIGHT/SELECT_KBD_BACKLIGHT`, `CLASS_INFO/SELECT_THERMAL_MANAGEMENT`) | rejected |
| token reads/writes (class 1, select 0-2): token must exist in 0xDA table; `token_blacklist` ranges rejected (0x0058-59, 0x00CD-D0, 0x013A-1FF, …, 0x0332-0x0335 fan, 0x4000-7FFF internal, …); `token_whitelist` grants with capability | |
| `call_whitelist` with `CAP_SYS_ADMIN` | token read/write STD/AC/BAT, `CLASS_ADMIN_PROP`, `CLASS_INFO/SELECT_DOCK`, `CLASS_FLASH_INTERFACE` |
| **fallback**: any other class/select is allowed with `CAP_SYS_RAWIO` | → **class 8 / select 18 / 19 (the app's exact battery calls) are reachable by root** |

Note the battery tokens 0x0341–0x034A are **not** in any blacklist range in 7.2.9, so a `CAP_SYS_ADMIN`
process can write them through the char device as well (the kernel does not reserve them the way it
reserves brightness/keyboard/fan tokens). `dell-laptop` and a userspace tool could therefore both poke the
same settings — the kernel does not arbitrate.

## 5. Practical usage on a Dell laptop (x64) with kernel ≥ this tree

```sh
# what modes does the battery support, which is active?
cat /sys/class/power_supply/BAT0/charge_types        # e.g. "Fast [Standard] Adaptive Custom"

# switch to custom charge window and cap charging at 80 %
echo Custom        > /sys/class/power_supply/BAT0/charge_types
echo 55            > /sys/class/power_supply/BAT0/charge_control_start_threshold
echo 80            > /sys/class/power_supply/BAT0/charge_control_end_threshold
cat /sys/class/power_supply/BAT0/charge_control_end_threshold   # read back actual (BIOS-validated) value

# or use the app-equivalent class-8 DACI path directly (root, CAP_SYS_RAWIO):
#   open /dev/wmi/dell-smbios, read() buffer size, fill calling_interface_buffer
#   cmd_class=8, cmd_select=19, input[]={battery<<8|cmd, mode/start/stop packed …}
```

Requirements/caveats: kernel built with `CONFIG_DELL_LAPTOP` (+ `CONFIG_DELL_SMBIOS_WMI` and/or
`CONFIG_DELL_SMBIOS_SMM`); a Dell laptop whose firmware actually provides the tokens (the driver only
registers the attributes when `battery_get_supported_modes() != 0`, i.e. when at least one BAT_* token is
present); only `BAT0` (primary battery) is covered.

## 6. Conclusion

* **Charge levels: yes.** `charge_control_start_threshold` / `charge_control_end_threshold` are the direct
  Linux equivalent of the app's `SetBatteryCustomChargeModeAsync` – the same BIOS tokens
  (0x0349/0x034A) and the same presets (Standard/Express/Primarily-AC/Adaptive/Custom) via
  `charge_types` (0x0341–0x0347). Differences: the kernel hardcodes 50–95/55–100/min-5 instead of using
  the platform's reported allowable range/granularity, and it only handles the primary battery.
* **The app's remaining battery features are not available in Linux**: Advanced Charge (mode 7 + weekly
  schedule + tokens 0x0374/0x0375), Peak Shift, Dynamic Charge (ML) and Intelligent Battery Extender have
  no kernel driver and no sysfs ABI anywhere in 7.2.9. A userspace port could still implement the exact
  DACI class-8 calls through `/dev/wmi/dell-smbios` with `CAP_SYS_RAWIO`, or the 884/885 tokens as token
  writes if a future kernel/tool allowed them (0x0374/0x0375 are not blacklisted in this tree).
* Read-only telemetry (capacities, chemistry, temperature, serial) is available natively
  (ACPI battery + `dell-wmi-ddv`).

## 8. Which machines actually get charge control? (model-independent capability probe)

Not a model list — a **firmware probe**. `dell-laptop` binds purely on vendor + chassis type
(`dell_device_table[]`: `DMI_SYS_VENDOR="Dell Inc."` with `DMI_CHASSIS_TYPE ∈ {8,9,10,30,31,32}`,
`dell-laptop.c:121-168`), then discovers at probe time whether the platform supports charge control:

```
dell_init()                                    -> dell_battery_init(dev)          (dell-laptop.c:2444)
dell_battery_init: battery_supported_modes = battery_get_supported_modes();
                   if (battery_supported_modes != 0) battery_hook_register(&dell_battery_hook);
battery_get_supported_modes():                 (dell-laptop.c:2431)
    for each of the 5 mode tokens (0x0341, 0x0342, 0x0343, 0x0346, 0x0347)
        if dell_smbios_find_token(token) -> mode supported
```

Consequences:

* `dell_smbios_find_token()` only finds anything if `da_tokens` was populated by `parse_da_table()`
  from the **SMBIOS type 0xDA "Calling Interface" table** (`dell-smbios-base.c:393-424`), which requires a
  registered transport: the ACPI-WMI SMBIOS interface (GUID `A80593CE-…`, `dell-smbios-wmi.c`) or
  `dcdbas`/SMM (`dell-smbios-smm.c`). No transport → no tokens → **no charge attributes at all**.
* The three sysfs attributes are one group (`dell_battery_groups`), so
  `charge_control_start_threshold` / `charge_control_end_threshold` appear **only if at least one of the
  five mode tokens exists** — a hypothetical platform exposing just 0x0349/0x034A would show nothing.
* Only the ACPI battery named exactly `BAT0` is extended (`dell_battery_supported()`).
* Although `CONFIG_DELL_SMBIOS` builds `dell-smbios.ko` (+WMI/SMM transports) and `dell-laptop.ko`
  separately, the `dell-laptop` module depends on it; distro kernels normally enable all of them.
* The whitelist/blacklist filter (`dell_smbios_call_filter`) is invoked **only from the userspace
  char-device ioctl path** (`dell-smbios-wmi.c:148`); the kernel's own battery/mode token writes bypass it.
* Practical check on a machine: `ls /sys/class/power_supply/BAT0/ | grep -E 'charge_types|charge_control'`
  plus `dmesg | grep -iE 'dell|smbios'` and `lsmod | grep -E 'dell_smbios|dell_laptop'`.

So: any Dell laptop (consumer Inspiron included) whose firmware publishes the battery tokens via a
supported transport gets charge modes + custom thresholds — **independently of model name**; and no model
name guarantees it.

## 9. Evidence index

| Claim | Evidence (linux-7.2.9 unless noted) |
|---|---|
| Charge-mode tokens & mapping | `drivers/platform/x86/dell/dell-smbios.h:36-42`, `dell-laptop.c:104-116`, `2188-2224` |
| Custom thresholds + clamping 50/95/55/100/5 | `dell-laptop.c:2232-2267`, `2317-2384` |
| sysfs attrs, BAT0-only, ACPI battery hook | `dell-laptop.c:2387-2450` |
| ABI documentation | `Documentation/ABI/testing/sysfs-class-power:352-430`; `include/linux/power_supply.h:45-55` |
| SMBIOS 0xDA token table + supported-class check | `dell-smbios-smm.c:40-52`, `dell-smbios-base.c:184-200` |
| WMI transport (GUID, method, priority 1) | `dell-smbios-wmi.c:32,51-70,261` |
| SMM transport (dcdbas, magic, 0x42534931, priority 0) | `dell-smbios-smm.c:52-66,128` |
| Transport selection | `dell-smbios-base.c` `dell_smbios_call()` |
| Userspace char device + filters | `dell-smbios-wmi.c:203`; `dell-smbios-base.c:53-127,184-292`; `Documentation/ABI/testing/dell-smbios-wmi` |
| DDV battery telemetry | `dell-wmi-ddv.c:79-90` |
| No advanced-charge/peak-shift support | tree-wide grep (only HP has a PEAKSHIFT constant) |
| Windows app uses `ROOT\WMI!WMI_Query.DoBFn`, not GUID A80593CE… | `ghidra/decompiled_BIOSIntf_app.c`; GUID absent from app binaries |
