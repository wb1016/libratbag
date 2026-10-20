#!/usr/bin/env bash
# Capture the X-41 Pro vendor tool's real HID feature-report traffic.
#
# Runs RDCfg.exe under Wine with an LD_PRELOAD ioctl shim that logs every
# HIDIOCSFEATURE/HIDIOCGFEATURE exchange. RDCfg.exe reads the mouse config on
# startup, so merely launching it captures the query framing; remapping a
# button + clicking apply captures the write record too.
#
# Usage:
#   cd <libratbag root>
#   bash contrib/x41pro-capture.sh
#
# Output: /tmp/opencode/x41-ioctl.log  (paste it back for analysis)

set -e
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SHIM=/tmp/x41shim.so
LOG=/tmp/opencode/x41-ioctl.log
SOFT="$HERE/../X-41 PRO Gaming Mouse"

echo "== building ioctl shim =="
gcc -shared -fPIC -O2 -o "$SHIM" "$HERE/contrib/x41pro-ioctlshim.c" -ldl

echo "== granting hidraw access =="
for n in /dev/hidraw*; do sudo chmod 666 "$n"; done

if [ ! -d "$SOFT" ]; then
    echo "WARNING: vendor software dir not found at: $SOFT"
fi

mkdir -p "$(dirname "$LOG")"
rm -f "$LOG"

echo
echo "== launching RDCfg.exe under Wine =="
echo "   1) let it load (captures the config READ/queries)"
echo "   2) optionally remap one button and click Apply (captures the WRITE)"
echo "   3) close the RDCfg window when done"
echo
read -rp "Press ENTER to launch..."

cd "$SOFT"
LD_PRELOAD="$SHIM" IOCTL_LOG="$LOG" wine ./RDCfg.exe || true

echo
echo "== capture written to $LOG =="
if [ -f "$LOG" ]; then
    echo "== HID feature-report exchanges (SET=0x...06 / GET=0x...07) =="
    grep -E 'cmd=0x[0-9a-f]*(06|07)' "$LOG" | head -100 || echo "(none captured)"
    echo
    echo "== all hidraw ioctls (first 60) =="
    head -60 "$LOG"
else
    echo "no log written -- RDCfg.exe may not have reached the device under Wine."
fi
