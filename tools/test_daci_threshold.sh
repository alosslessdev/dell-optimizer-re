#!/bin/sh
# Safe class-8 DACI charge-threshold test.
#
# Requires root. Records the current mode/start/stop, lowers the stop limit by
# one percentage point, verifies the read-back, then restores the original
# values even on error.  Refuses to run unless the battery is already in Custom
# mode and AC is online; use --force to override the AC check.
#
#   sudo bash test_daci_threshold.sh --apply
#   sudo bash test_daci_threshold.sh --apply --battery 1 --force
#
# Without --apply it only prints the recorded values and the intended change.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PY="$HERE/dell_daci_battery.py"
BAT=1
APPLY=0
FORCE=0

while [ $# -gt 0 ]; do
	case "$1" in
	--apply) APPLY=1 ;;
	--force) FORCE=1 ;;
	--battery)
		shift
		[ $# -gt 0 ] || { echo "--battery needs a value" >&2; exit 2; }
		BAT=$1
		;;
	-h|--help)
		sed -n '2,16p' "$0"
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
	shift
done

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -x "$PY" ] || { echo "missing $PY" >&2; exit 1; }

AC=""
for p in /sys/class/power_supply/AC*; do
	[ -r "$p/online" ] && AC="$p/online" && break
done
if [ -n "$AC" ] && [ "$(cat "$AC")" != 1 ] && [ "$FORCE" = 0 ]; then
	echo "AC is offline; connect AC or pass --force" >&2
	exit 1
fi

read_json() {
	python3 "$PY" --battery "$BAT" read --json
}

json=$(read_json)
mode=$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["mode"])')
start=$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["start"])')
stop=$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["stop"])')

echo "recorded: battery=$BAT mode=$mode start=$start stop=$stop"
[ "$mode" = 5 ] || { echo "refusing: mode is $mode, not Custom (5)" >&2; exit 1; }
if [ "$((stop - 1))" -lt "$((start + 5))" ]; then
	echo "refusing: stop-1 would violate the minimum 5% window" >&2
	exit 1
fi

target=$((stop - 1))
if [ "$APPLY" = 0 ]; then
	echo "dry run: would write start=$start stop=$target, then restore stop=$stop"
	exit 0
fi

restore() {
	python3 "$PY" --battery "$BAT" set --mode 5 --start "$start" --stop "$stop" --apply >/dev/null 2>&1 || true
}
trap restore EXIT INT TERM

echo "write stop=$target"
python3 "$PY" --battery "$BAT" set --mode 5 --start "$start" --stop "$target" --apply

after=$(read_json)
after_stop=$(printf '%s' "$after" | python3 -c 'import json,sys; print(json.load(sys.stdin)["stop"])')
[ "$after_stop" = "$target" ] || { echo "FAIL: readback stop=$after_stop, expected $target" >&2; exit 1; }

echo "restore stop=$stop"
python3 "$PY" --battery "$BAT" set --mode 5 --start "$start" --stop "$stop" --apply

final=$(read_json)
final_stop=$(printf '%s' "$final" | python3 -c 'import json,sys; print(json.load(sys.stdin)["stop"])')
[ "$final_stop" = "$stop" ] || { echo "FAIL: restored stop=$final_stop, expected $stop" >&2; exit 1; }

trap - EXIT INT TERM
echo "PASS: $stop -> $target -> $stop"
