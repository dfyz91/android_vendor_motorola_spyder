#!/data/data/com.termux/files/usr/bin/sh
# edl-termux launcher: finds the device via termux-usb, requests permission,
# runs the CLI with a fresh FD. Robust quoting: user args are passed through
# a NUL-separated temp file, never re-parsed by the shell.
#
# Usage: edl-termux-fd.sh <edlt args...>   e.g. edl-termux-fd.sh chipinfo
# Env:   EDL_USB_PATH=/dev/bus/usb/001/007  force a specific device path
#        TERMUX_USB=termux-usb              override termux-usb binary
#        EDLT_FD_FLAG=--sockfd               test hook (mock server fd);
#                                             default --fd (real USB fd)
set -u

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
# Locate the project next to this script first: the launcher then works
# straight from an extracted tree, no install.sh needed. $0 is always the
# full script path (the $PREFIX/bin wrapper execs it directly), so the
# installed layout resolves to itself too. An explicit EDLT_HOME wins.
SELF_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
if [ -n "${EDLT_HOME:-}" ]; then
    :
elif [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/edlt-fd-helper.sh" ]; then
    EDLT_HOME="$SELF_DIR"
else
    EDLT_HOME="$PREFIX/opt/edl-termux"
fi
HELPER="$EDLT_HOME/edlt-fd-helper.sh"
if [ ! -f "$HELPER" ]; then
    echo "ERROR: helper script not found: $HELPER" >&2
    echo "       Re-run: sh <project-tree>/install.sh   (or set EDLT_HOME)" >&2
    exit 2
fi
USB_TOOL="${TERMUX_USB:-termux-usb}"
PYTHON="${EDLT_PYTHON:-python}"
command -v "$USB_TOOL" >/dev/null 2>&1 || {
    echo "ERROR: $USB_TOOL not found. Install it: pkg install termux-api" >&2
    exit 1
}
command -v "$PYTHON" >/dev/null 2>&1 || {
    echo "ERROR: $PYTHON not found. Install it: pkg install python" >&2
    exit 1
}

# 1. pick the device -------------------------------------------------------
# Real termux-usb -l prints a plain JSON list of paths:
#   ["/dev/bus/usb/001/031"]
# (termux-usb has no VID/PID API - it only exposes paths, and permission
# is requested per path with `termux-usb -r -e CMD <path>`.) The VID/PID
# check therefore happens INSIDE edlt, after the FD is opened, via the
# libusb device descriptor (exit code 6 = wrong device). The test shim
# prints a list of objects with "deviceName"; we accept both formats.
if [ -n "${EDL_USB_PATH:-}" ]; then
    DEVS="$EDL_USB_PATH"
else
    LIST_JSON="$("$USB_TOOL" -l 2>/dev/null)" || {
        echo "ERROR: termux-usb -l failed. Is termux-api installed and the OTG device plugged in?" >&2
        exit 1
    }
    DEVS="$(printf '%s' "$LIST_JSON" | "$PYTHON" -c 'import json,sys
try:
    d = json.load(sys.stdin)
    if isinstance(d, list):
        for e in d:
            if isinstance(e, str) and e:
                print(e)
            elif isinstance(e, dict):
                p = e.get("deviceName") or e.get("path")
                if p:
                    print(p)
except Exception:
    pass')"
    if [ -z "$DEVS" ]; then
        echo "ERROR: no USB device found by termux-usb -l. Replug the phone in EDL (Vol+ + Vol- while connecting), then retry." >&2
        exit 1
    fi
fi

# 2. stash user args (NUL-separated, quoting-safe) -------------------------
TMPD="$PREFIX/tmp"
[ -d "$TMPD" ] || TMPD="${TMPDIR:-}"
[ -n "$TMPD" ] && [ -d "$TMPD" ] || TMPD="$HOME"
mkdir -p "$TMPD" 2>/dev/null || true
ARGS_FILE="$(mktemp "$TMPD/edlt-args.XXXXXX")"
: > "$ARGS_FILE"
for a in "$@"; do
    printf '%s\0' "$a" >> "$ARGS_FILE"
done
export EDLT_ARGS_FILE="$ARGS_FILE"
export EDLT_HOME

# 3. run with a fresh FD ---------------------------------------------------
# Try each USB device termux-usb listed. rc=6 means "wrong VID/PID"
# (not a Qualcomm 9008 device) -> try the next one. Any other rc: stop.
rc=6
for DEV in $DEVS; do
    echo "[*] device: $DEV"
    echo "[*] requesting FD via: $USB_TOOL -r -e sh <helper> $DEV"
    "$USB_TOOL" -r -e "sh '$HELPER'" "$DEV"
    rc=$?
    [ "$rc" -eq 6 ] || break
    echo "[*] $DEV is not a Qualcomm EDL 9008 device, trying next..."
done
rm -f "$ARGS_FILE"
if [ "$rc" -eq 6 ]; then
    echo "ERROR: no Qualcomm EDL device (05c6:9008) found. Put the phone in EDL mode (Vol+ + Vol- + cable), check with 'termux-usb -l', then retry." >&2
    exit 6
fi
if [ $rc -ne 0 ]; then
    echo "ERROR: edlt failed (rc=$rc). If the device was reset/disconnected, RE-RUN this launcher so termux-usb grants a NEW FD (there is no auto-reconnect)." >&2
fi
exit $rc
