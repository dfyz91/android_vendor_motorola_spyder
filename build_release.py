"""Script to build v0.1.4 release artifacts."""
import hashlib
import os
import shutil
import subprocess
import zipfile

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(ROOT_DIR, "release_v0.1.4", "edl-termux-v0.1.4-package")

RUNTIME_FILES = [
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "edl-termux-fd.sh",
    "edlt-fd-helper.sh",
    "install.sh",
    "edl_termux/__init__.py",
    "edl_termux/arb.py",
    "edl_termux/bootctl.py",
    "edl_termux/cli.py",
    "edl_termux/firehose.py",
    "edl_termux/gpt.py",
    "edl_termux/log.py",
    "edl_termux/oplus.py",
    "edl_termux/qcomimage.py",
    "edl_termux/reference.py",
    "edl_termux/sahara.py",
    "edl_termux/usb.py",
]

def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def build_release():
    if os.path.exists(DIST_DIR):
        shutil.rmtree(DIST_DIR)
    os.makedirs(DIST_DIR, exist_ok=True)

    # 1. edl-termux-source-v0.1.4.zip
    src_zip_path = os.path.join(DIST_DIR, "edl-termux-source-v0.1.4.zip")
    with zipfile.ZipFile(src_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in RUNTIME_FILES:
            abs_p = os.path.join(ROOT_DIR, rel)
            arcname = os.path.join("edl-termux-v0.1.4", rel)
            zf.write(abs_p, arcname)

    # 2. edl-termux-v0.1.4.patch
    patch_path = os.path.join(DIST_DIR, "edl-termux-v0.1.4.patch")
    diff_out = subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT_DIR)
    if not diff_out:
        # If HEAD is clean or no diff against HEAD, get diff from git log / status
        diff_out = subprocess.check_output(["git", "diff", "--staged"], cwd=ROOT_DIR)
    with open(patch_path, "wb") as f:
        f.write(diff_out)

    # 3. edl-termux-installer-release-v0.1.4.sh
    installer_path = os.path.join(DIST_DIR, "edl-termux-installer-release-v0.1.4.sh")
    manifest_lines = []

    with open(installer_path, "w", encoding="utf-8") as inst:
        inst.write("""#!/usr/bin/env bash
# edl-termux self-extracting installer - RELEASE v0.1.4
# Includes ELF hash-segment parsing fix, USB error classification fixes, and strict test separation.
# Generated 2026-10-26. Runtime-only distribution; no tests bundled.
# Usage: bash edl-termux-installer-release-v0.1.4.sh [target-dir]
set -eu
DEST="${1:-$HOME/edl-termux}"
mkdir -p "$DEST/edl_termux"
echo "[*] extracting edl-termux release v0.1.4 -> $DEST"
""")
        for idx, rel in enumerate(RUNTIME_FILES, 1):
            abs_p = os.path.join(ROOT_DIR, rel)
            with open(abs_p, "r", encoding="utf-8") as rf:
                content = rf.read()
            h = sha256_file(abs_p)
            manifest_lines.append(f"{h}  {rel}")
            tag = f"EDLT_FILE_{idx:03d}_END"
            inst.write(f'cat > "$DEST/{rel}" <<\'{tag}\'\n')
            inst.write(content)
            if not content.endswith("\n"):
                inst.write("\n")
            inst.write(f"{tag}\n\n")

        inst.write("""echo "[*] Byte-compiling all python modules (syntax check)..."
python3 -m py_compile "$DEST"/edl_termux/*.py
echo "[*] OK"

echo
echo "Done. Quick check:"
echo "  termux-usb -l                     # phone must be listed (05c6:9008)"
echo "  edl-termux-fd.sh chipinfo"
echo "  edlt image-info <abl.img>         # offline parser, no device"
chmod +x "$DEST/edl-termux-fd.sh" "$DEST/edlt-fd-helper.sh" "$DEST/install.sh"
echo "[*] verifying SHA-256 manifest..."
cd "$DEST"
sha256sum -c - <<'EDLT_MANIFEST_END'
""")
        for line in manifest_lines:
            inst.write(line + "\n")
        inst.write("""EDLT_MANIFEST_END
echo "[+] OK: edl-termux extracted and verified"
""")
    os.chmod(installer_path, 0o755)

    # 4. START-HERE-RU.md
    start_here_path = os.path.join(DIST_DIR, "START-HERE-RU.md")
    with open(start_here_path, "w", encoding="utf-8") as f:
        f.write("""# edl-termux v0.1.4 — Инструкция по установке и запуску

## Файлы релиза v0.1.4

- `edl-termux-installer-release-v0.1.4.sh` — самораспаковывающийся инсталлятор (только runtime).
- `edl-termux-source-v0.1.4.zip` — исходный код v0.1.4.
- `edl-termux-v0.1.4.patch` — патч изменений v0.1.4.
- `edl-termux-v0.1.4-SHA256SUMS.txt` — контрольные суммы артефактов.

## Быстрая установка в Termux

```bash
bash edl-termux-installer-release-v0.1.4.sh
```

## Проверка работы

```bash
sh ~/edl-termux/edl-termux-fd.sh chipinfo
```
""")

    # 5. edl-termux-v0.1.4-SHA256SUMS.txt
    sum_file_path = os.path.join(DIST_DIR, "edl-termux-v0.1.4-SHA256SUMS.txt")
    with open(sum_file_path, "w", encoding="utf-8") as f:
        for fn in ["edl-termux-source-v0.1.4.zip", "edl-termux-installer-release-v0.1.4.sh", "edl-termux-v0.1.4.patch"]:
            p = os.path.join(DIST_DIR, fn)
            f.write(f"{sha256_file(p)}  {fn}\n")

    # 6. edl-termux-v0.1.4-test-bundle.zip
    bundle_zip_path = os.path.join(DIST_DIR, "..", "edl-termux-v0.1.4-test-bundle.zip")
    with zipfile.ZipFile(bundle_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fn in os.listdir(DIST_DIR):
            abs_p = os.path.join(DIST_DIR, fn)
            if os.path.isfile(abs_p):
                arcname = os.path.join("edl-termux-v0.1.4-package", fn)
                zf.write(abs_p, arcname)

    print("Release build completed successfully in", DIST_DIR)

if __name__ == "__main__":
    build_release()
