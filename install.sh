#!/data/data/com.termux/files/usr/bin/sh
# edl-termux installer for Termux (no root needed) - v0.1.3
set -e

if [ ! -d "/data/data/com.termux/files/usr" ]; then
    echo "ERROR: this install.sh is meant for Termux (PREFIX not found)."
    exit 1
fi

echo "[*] Installing packages (python, libusb, termux-api, binutils)..."
pkg install -y python libusb termux-api binutils || {
    echo "ERROR: pkg install failed. Install manually: pkg install python libusb termux-api binutils"
    exit 1
}

echo "[*] Installing edl-termux into \$PREFIX/opt/edl-termux ..."
PREFIX="/data/data/com.termux/files/usr"
DEST="$PREFIX/opt/edl-termux"
SRC="$(cd "$(dirname "$0")" && pwd)"
if [ "$SRC" = "$DEST" ]; then
    # re-install from the installed location: do not rm -rf the running dir
    echo "[*] source is already $DEST (skipping copy)"
else
    # v0.1.3: $PREFIX/opt may not exist on a fresh Termux
    mkdir -p "$(dirname "$DEST")"
    rm -rf "$DEST"
    cp -R "$SRC" "$DEST"
fi
# ensure the launcher scripts and the termux-usb test shim stay executable
# (tolerant: the clean-release tree ships no tests)
for f in edl-termux-fd.sh edlt-fd-helper.sh install.sh run_tests.sh \
         tests/test_launcher.sh tests/test_all.py tests/mock_server.py \
         tests/shims/termux-usb; do
    if [ -e "$DEST/$f" ]; then
        chmod +x "$DEST/$f" 2>/dev/null || true
    fi
done
mkdir -p "$PREFIX/bin"

cat > "$PREFIX/bin/edl-termux-fd.sh" <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
exec sh /data/data/com.termux/files/usr/opt/edl-termux/edl-termux-fd.sh "$@"
EOF
chmod +x "$PREFIX/bin/edl-termux-fd.sh"

cat > "$PREFIX/bin/edlt" <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
exec python /data/data/com.termux/files/usr/opt/edl-termux/edl_termux/cli.py "$@"
EOF
chmod +x "$PREFIX/bin/edlt"

# v0.1.3 POST-COPY SANITY CHECK: a partial copy breaks the launcher later
# with cryptic "cannot open" errors; fail loudly here instead.
missing=0
for f in edl-termux-fd.sh edlt-fd-helper.sh install.sh README.md \
         edl_termux/__init__.py edl_termux/cli.py edl_termux/usb.py \
         edl_termux/sahara.py edl_termux/firehose.py edl_termux/gpt.py; do
    if [ ! -f "$DEST/$f" ]; then
        echo "ERROR: installed tree is INCOMPLETE: missing $DEST/$f" >&2
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    echo "       The copy failed midway (storage full?). Re-run the" >&2
    echo "       self-extracting installer, then this script again." >&2
    exit 1
fi

echo "[*] Byte-compiling all python modules (syntax check)..."
python -m py_compile "$DEST"/edl_termux/*.py
if [ -d "$DEST/tests" ]; then
    python -m py_compile "$DEST"/tests/*.py
fi
echo "[*] OK"

echo
echo "Done. Quick check:"
echo "  termux-usb -l                     # phone must be listed (05c6:9008)"
echo "  edl-termux-fd.sh chipinfo"
echo "  edlt image-info <abl.img>         # offline parser, no device"
