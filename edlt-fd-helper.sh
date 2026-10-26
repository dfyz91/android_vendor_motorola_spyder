#!/data/data/com.termux/files/usr/bin/sh
# Helper executed by termux-usb with the USB FD appended as "$1".
# Reads the NUL-separated user args from $EDLT_ARGS_FILE, execs the CLI.
# v0.1.3: pre-flight checks with clear messages BEFORE touching the FD -
# a half-installed tree previously died with the cryptic
# "sh: 0: cannot open ...: No such file" AFTER termux-usb had already
# granted the FD (the rc=2 failure seen on the phone).
set -u

FD="${1:-}"
if [ -z "$FD" ]; then
    echo "ERROR: helper got no USB FD argument (termux-usb appends it as \$1)." >&2
    echo "       Do not run this helper by hand; use: edl-termux-fd.sh <cmd>" >&2
    exit 2
fi
EDLT_HOME="${EDLT_HOME:-/data/data/com.termux/files/usr/opt/edl-termux}"
PYTHON="${EDLT_PYTHON:-python}"
CLI="$EDLT_HOME/edl_termux/cli.py"
if [ ! -f "$CLI" ]; then
    echo "ERROR: CLI not found: $CLI" >&2
    echo "       EDLT_HOME is wrong or the tree is incomplete." >&2
    echo "       Reinstall from an extracted tree: sh ~/edl-termux/install.sh" >&2
    exit 2
fi
if [ ! -f "${EDLT_ARGS_FILE:-}" ]; then
    echo "ERROR: EDLT_ARGS_FILE not set (only the launcher may run this helper)." >&2
    exit 2
fi
# EDLT_FD_FLAG: --fd (real termux-usb USB FD, libusb_wrap_sys_device) or
# --sockfd (tests: fd of a socket to tests/mock_server.py)
FD_FLAG="${EDLT_FD_FLAG:---fd}"
export EDL_USB_FD="$FD"
exec "$PYTHON" "$CLI" "$FD_FLAG" "$FD" --args-file "$EDLT_ARGS_FILE"
