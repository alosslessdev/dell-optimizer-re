#!/usr/bin/env bash
# Read-only Dell machine probe for the charge-level study.
#   sudo bash probe_linux.sh                 # read-only
#   sudo bash probe_linux.sh --test-charge 80  # writes end threshold (record/restore)
# Never prints serial numbers by default beyond what battery firmware exposes; redact before publishing.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TEST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --test-charge) TEST="${2:-}"; shift 2 ;;
    -h|--help) echo "usage: $0 [--test-charge <percent>]"; exit 0 ;;
    *) echo "unknown argument: $1"; exit 2 ;;
  esac
done
say() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

say "identity (DMI)"
for f in sys_vendor product_name product_version product_sku board_vendor board_name \
         chassis_type bios_vendor bios_version bios_date; do
  [ -r "/sys/class/dmi/id/$f" ] && printf '%-16s %s\n' "$f" "$(cat "/sys/class/dmi/id/$f")"
done

say "Dell Optimizer gating verdict"
if have python3 && [ -r /sys/class/dmi/id/product_name ]; then
  python3 "$HERE/gating_verdict.py" \
    --manufacturer "$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo '')" \
    --product "$(cat /sys/class/dmi/id/product_name)" \
    --sku "$(cat /sys/class/dmi/id/product_sku 2>/dev/null || echo '')" || true
else
  echo "python3 or DMI ids unavailable"
fi

say "dmidecode (type 0/1/3)"
if have dmidecode; then
  if [ "$(id -u)" = 0 ]; then
    dmidecode -t 0 -t 1 -t 3 2>/dev/null | sed -n '1,120p'
    TMP=$(mktemp /tmp/smbios.XXXXXX.bin)
    trap 'rm -f "$TMP"' EXIT
    if dmidecode --dump-bin "$TMP" 2>/dev/null; then
      echo
      echo "-- type 0xDA analysis --"
      if have python3; then python3 "$HERE/parse_smbios_da.py" "$TMP" || true; else
        echo "python3 missing; dump kept at $TMP"; trap - EXIT; fi
    fi
  else
    echo "run as root for dmidecode and the 0xDA dump"
  fi
else
  echo "dmidecode not installed"
fi

say "kernel and Dell drivers"
uname -r
if have lsmod; then lsmod | grep -E '^(dell_laptop|dell_smbios|dell_smbios_wmi|dell_smbios_smm|dcdbas|dell_wmi|dell_wmi_ddv|dell_wmi_sysman)' || echo "no Dell modules loaded"; fi
if have modinfo; then modinfo -F filename dell_laptop 2>/dev/null || echo "dell_laptop module not found"; fi
echo "-- dmesg (dell/smbios) --"
if have dmesg; then dmesg 2>/dev/null | grep -iE 'dell|smbios' | tail -25 || true; fi
echo "-- kernel config --"
for c in /boot/config-"$(uname -r)" /proc/config.gz; do
  if [ -r "$c" ]; then
    if [ "$c" = /proc/config.gz ]; then zcat "$c" 2>/dev/null; else cat "$c"; fi |
      grep -E '^CONFIG_(DELL_LAPTOP|DELL_SMBIOS|DELL_SMBIOS_WMI|DELL_SMBIOS_SMM|DCDBAS|DELL_WMI_DDV)=' || true
    break
  fi
done

say "power supplies"
for ps in /sys/class/power_supply/*; do
  [ -d "$ps" ] || continue
  echo "-- $(basename "$ps") --"
  for a in type status manufacturer model_name technology capacity cycle_count \
           voltage_now power_now energy_now charge_now charge_full charge_full_design \
           charge_types charge_control_start_threshold charge_control_end_threshold \
           charge_behaviour; do
    [ -r "$ps/$a" ] && printf '%-32s %s\n' "$a" "$(cat "$ps/$a" 2>/dev/null)"
  done
done

say "charge-control verdict"
BAT=""
for ps in /sys/class/power_supply/BAT*; do [ -d "$ps" ] && BAT="$ps" && break; done
if [ -n "$BAT" ] && [ -r "$BAT/charge_types" ]; then
  echo "YES: firmware exposes Dell battery tokens; charge control available on $(basename "$BAT")"
  echo "     modes: $(cat "$BAT/charge_types")"
  [ -r "$BAT/charge_control_start_threshold" ] && echo "     start: $(cat "$BAT/charge_control_start_threshold")"
  [ -r "$BAT/charge_control_end_threshold" ] && echo "     end:   $(cat "$BAT/charge_control_end_threshold")"
else
  echo "NO: no charge_types attribute on BAT0 -> firmware does not expose the Dell battery tokens"
  echo "    (or no transport: check Dell modules/dmesg above and the 0xDA table)"
fi

if [ -n "$TEST" ]; then
  say "SAFE TEST: set end threshold to $TEST%"
  if [ "$(id -u)" != 0 ]; then echo "need root"; exit 1; fi
  if [ -z "$BAT" ] || [ ! -w "$BAT/charge_control_end_threshold" ]; then
    echo "no writable charge_control_end_threshold; aborting"; exit 1
  fi
  ORIG_START=$(cat "$BAT/charge_control_start_threshold" 2>/dev/null || echo "")
  ORIG_END=$(cat "$BAT/charge_control_end_threshold" 2>/dev/null || echo "")
  ORIG_MODE=$(cat "$BAT/charge_types" 2>/dev/null || echo "")
  echo "recorded: start=$ORIG_START end=$ORIG_END modes=$ORIG_MODE"
  restore() {
    [ -n "$ORIG_END" ] && echo "$ORIG_END" > "$BAT/charge_control_end_threshold" 2>/dev/null
    [ -n "$ORIG_START" ] && echo "$ORIG_START" > "$BAT/charge_control_start_threshold" 2>/dev/null
    echo "restored: start=$(cat "$BAT/charge_control_start_threshold" 2>/dev/null) end=$(cat "$BAT/charge_control_end_threshold" 2>/dev/null)"
  }
  trap restore EXIT INT TERM
  echo "$TEST" > "$BAT/charge_control_end_threshold" || { echo "write failed"; exit 1; }
  sleep 1
  echo "read back: end=$(cat "$BAT/charge_control_end_threshold")"
  # min-diff check: try a start above end-5
  if [ -w "$BAT/charge_control_start_threshold" ]; then
    echo "testing min-diff (start=$((TEST-2)) with end=$TEST)"
    echo "$((TEST-2))" > "$BAT/charge_control_start_threshold" 2>/dev/null || true
    sleep 1
    echo "read back: start=$(cat "$BAT/charge_control_start_threshold")"
  fi
  echo "restoring..."; restore; trap - EXIT INT TERM
fi

say "done"
echo "Redact serial numbers / service tags before publishing any output."
