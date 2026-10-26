# Changelog

## 0.1.4 (2026-10-26) - Audit fixes & test code release separation

- `edl_termux/qcomimage.py`: fixed `_find_elf_hash_segment()` to inspect program header flags regardless of `p_type`, enabling correct parsing of `p_type=PT_NULL` hash segments found in Snapdragon 888 signed ELFs (e.g., `9RT_5G.elf` and `OPPO_SM8350_New_Chimera_V2.6.elf`).
- `edl_termux/usb.py`: corrected `_err()` libusb exception classification. `LIBUSB_ERROR_IO (-1)` and `LIBUSB_ERROR_PIPE (-9)` now raise `TransportError` with original `rc`, error name, and transferred byte counts preserved. `DeviceGoneError` is now reserved strictly for `LIBUSB_ERROR_NO_DEVICE (-4)`.
- `edl_termux/sahara.py`: added explicit packet length validation in `_read_pkt()` to reject invalid/malformed length fields (`< 8` or `> 0x10000`).
- Test code separation: moved `mock_device.py` and test transports (`PipeTransport`, `RawFdTransport`) to `tests/`. Removed `--mock` CLI options from `edl_termux/cli.py` to ensure release runtime is completely free of simulation/test code.
- Verification & Release Audit: added automated release audit (`tests/check_release.py`), comprehensive unit tests in `tests/`, and top-level test runner `run_tests.sh`.

## 0.1.3 (2026-10-26) - Sahara/USB diagnostics

- `edl_termux/sahara.py`: HELLO_RESPONSE now has `status=0` and zeroed reserved
  fields; it no longer incorrectly puts `max_cmd_len` into the status field.
- HELLO negotiation follows upstream QDL behavior: command-mode info uses the
  device-advertised protocol version, while image transfer uses host Sahara v2;
  compatibility is 1 and the requested mode is selected explicitly. Decoded
  HELLO_REQ fields are logged.
- `upload_image`: verifies requested ranges remain inside the ELF and checks
  the actual number of bytes reported written; logs offset/requested/actual
  counts. `DONE_RSP status=1` is treated as IMAGE_TX_COMPLETE; status 0 is
  not falsely reported as a completed one-image Firehose handoff.
- `edl_termux/usb.py`: `libusb_wrap_sys_device` now takes pointer-sized
  `ctypes.c_ssize_t`; optional descriptor inspection reports interfaces,
  alternate settings, endpoint directions/types and `wMaxPacketSize` before
  interface claim. Interface fallback is logged.
- `edl_termux/cli.py`: added read-only `--usb-descriptors` diagnostic flag.
- Mock device DONE_RSP now mirrors IMAGE_TX_COMPLETE semantics. No partition
  write/erase/setslot/poke behavior was added or enabled.

## 0.1.2 (2026-10-26) - Termux-platform audit

Fixes for real-Termux deployment problems, found by re-auditing every
runtime file against the actual Termux environment (no root, USB access
only through the termux-usb FD, stdin usually NOT a TTY):

- `edl-termux-fd.sh`: pre-flight checks that the termux-usb binary and
  the python interpreter actually exist, with clear "pkg install
  termux-api python" hints, instead of failing later with raw errors.
- `edl-termux-fd.sh`: temp-dir fallback was `${TMPDIR:-/tmp}` - /tmp does
  not exist in Termux, so on a system without TMPDIR the launcher
  crashed inside mktemp. New fallback chain: $PREFIX/tmp -> $TMPDIR (if
  it exists) -> $HOME, and the directory is created if missing.
- `edlt-fd-helper.sh`: pre-flight checks (USB FD argument present,
  cli.py present, EDLT_ARGS_FILE present) with clear reinstall hints.
  Previously a half-installed tree died with the cryptic
  "sh: 0: cannot open ...: No such file" AFTER termux-usb had already
  granted the FD (rc=2) - the exact failure observed on the phone.
- `install.sh`: mkdir -p of $PREFIX/opt before the copy (missing on a
  fresh Termux install), and a post-copy sanity check that every
  critical file landed in the installed tree - a partial copy now
  fails loudly instead of breaking the launcher later.
- `edl_termux/cli.py` (confirm_or_yes): input() crashed with EOFError
  when stdin is not a TTY - the normal case when the process is
  spawned by `termux-usb -e`. This is now detected and reported with
  a clear "re-run with --yes" message (exit code 2).
- `edl_termux/usb.py` (load_libusb): dlopen by bare soname can fail
  for processes spawned by termux-usb (different linker namespace /
  LD_LIBRARY_PATH). The absolute $PREFIX/lib/libusb-1.0.so[.0] paths
  are now tried FIRST, and relative find_library() results are
  resolved against $PREFIX/lib (then the usual system paths).

Docs: README notes the --yes flag. Version bumped to 0.1.2.

## 0.1.1 (2026-10-26) - audit fixes

Protocol robustness (verified against reference implementations):

- `edl_termux/sahara.py` (READ_DATA_64, cmd 0x12): reference tools
  DISAGREE on the image_id field width - bkerler/edl and Quectel
  QFirehose parse a 64-bit image_id (packet length 0x20 = 32 bytes),
  other implementations use a 32-bit image_id (0x1C = 28 bytes). The
  parser now accepts BOTH, dispatching on the packet's own length field
  (the length field is authoritative per Qualcomm's packet header
  definition), and fails loudly on any other length instead of guessing.
  The mock device can emit either variant (`read64_len=0x1C|0x20|"bad"`).
- `edl_termux/gpt.py`: the GPT header CRC32 and the partition-entry-array
  CRC32 were read but never verified (UEFI spec: header CRC over bytes
  0..91 with the CRC field zeroed; array CRC over num_entries*entry_size
  bytes). `parse_header` now reports `crc_ok`; the firehose read path
  computes the entries CRC and marks the LUN accordingly.
- `edl_termux/cli.py`: new safety gate `gpt_crc_guard` - writes (w),
  erases (e) and setslot are REFUSED (exit 10) when the target LUN's GPT
  has an invalid CRC32, because acting from a damaged table can hit the
  wrong sectors. `gpt` prints a loud warning for such LUNs.
- `edl_termux/arb.py` (format_report): slot pairing used
  `name.rstrip("_ab")`, which strips ANY trailing characters from the
  set {_, a, b} - "metadata" became "metadat" and counted as slot "a".
  Replaced with a strict `_a`/`_b` suffix check.
- `edl_termux/usb.py`: explicit ctypes argtypes for
  `libusb_wrap_sys_device` (fd passed as int, handle out-param).
- `tests/test_all.py`: +6 tests (three READ_DATA_64 variants incl. the
  unknown-length rejection, GPT header CRC detection, damaged-array
  detection via the firehose path, write-gate refusal on bad CRC).

Launcher / deployment:

- `edl-termux-fd.sh`: EDLT_HOME now defaults to the directory of the
  launcher script itself, so the launcher works directly from an
  extracted tree without running install.sh first (the installed
  layout is unaffected: the $PREFIX/bin wrapper execs the launcher by
  its full path). A missing helper script now fails with a clear
  message BEFORE requesting any USB FD, instead of the cryptic
  `sh: cannot open ...` + rc=2 after the FD was already granted.

Protocol / parser fixes (found by the audit and by the failing test suite):

- `edl_termux/sahara.py` (upload_image, READ_DATA_64 handler): the 64-bit
  read-data request was unpacked as `<IIQQQ` (32 bytes). The real packet is
  command(4) + length(4) + image_id(u32) + offset(u64) + size(u64) =
  28 bytes, so the correct format is `<IIIQQ`. The wrong format crashed
  every loader upload with `struct.error: ... buffer of at least 32 bytes
  ... (actual buffer size is 28)` (15 of 23 tests failed). The docstring
  already said 28 bytes - the code did not match it.
- `edl_termux/mock_device.py` (same packet, device side): packed with
  `<IIQQQ`; now `<IIIQQ` so the mock device emits the same 28-byte packet
  as real hardware.
- `edl_termux/gpt.py`: `parse_header` unpacked `"<IQQQ"` at offset 8, which
  does not match the real GPT header layout (CRC at 16, myLBA at 24,
  altLBA at 32, firstUsable at 40, lastUsable at 48). Now
  `struct.unpack_from("<IIIIQQQQ", data, 8)` with `import zlib`, and
  `build_gpt` writes the standard header with a correct CRC32 at offset 16.
- `edl_termux/cli.py` (cmd_image_info): called
  `qcomimage.format_info(info, pk_hash=...)` but the function is
  `format_info(info, pk_hex=None)` - `edlt image-info` crashed with
  TypeError. Call fixed to `pk_hex=`.

USB / launcher fixes:

- `edl-termux-fd.sh`: device discovery expected the test-shim output format
  (a list of objects with `deviceName`/`vendorId`/`productId`). Real
  `termux-usb -l` prints a plain JSON list of paths, e.g.
  `["/dev/bus/usb/001/031"]`, so on a real device the launcher found no
  device at all ("no USB device found"). The launcher now parses BOTH
  formats and tries every listed device path; wrong-VID/PID devices are
  skipped (exit 6) until the 9008 device answers.
- `edl_termux/usb.py`: added `LibusbFdTransport.get_vid_pid()` - reads the
  device descriptor of the termux-usb FD. termux-usb has no VID/PID API,
  so the 05c6:9008 verification now happens inside edlt, on the open FD,
  before any Sahara traffic. Bypassing it (assuming every USB device is
  an EDL device) is deliberately NOT done; `--no-vid-check` exists but is
  discouraged.
- `edl_termux/cli.py`: new `--vid` / `--pid` (defaults 05c6:9008) and
  `--no-vid-check`; a wrong device exits with code 6 and a clear message.
- `edl_termux/usb.py`: `libusb_get_device` / `libusb_ref_device` /
  `libusb_get_device_descriptor` now have explicit ctypes restypes.
  Without `c_void_p` restype, ctypes defaults to int and truncates
  pointers on 64-bit builds (latent corruption in EnumTransport and in
  the new get_vid_pid).

Test fixes:

- `tests/test_launcher.sh`: invoked the launcher as `"$LAUNCHER"`, i.e. one
  quoted word "sh /path/edl-termux-fd.sh" - command not found, rc=127 for
  every E2E test. Now unquoted so the shell splits it.
- `tests/test_launcher.sh`: the mock servers now check that their port is
  free before binding; a stale `mock_server.py` from an earlier run made
  the whole suite fail with "server did not start". Clear hint added
  (`pkill -f mock_server.py` or `EDLT_MOCK_PORT`).
- `tests/test_launcher.sh`: new test 6 runs the whole launcher chain with
  the REAL `termux-usb -l` output format (plain list of path strings).
- `tests/shims/termux-usb`: `EDLT_SHIM_LIST_FORMAT=plain` makes the shim
  print the real termux-usb format for that test.

Docs: README updated (real `-l` format, VID/PID check location, new CLI
flags, exit codes including 6, stale-server hint, GPT CRC gate).

Not changed: all safety gates (read-only default, `--i-know-what-i-am-doing`,
ARB lower/higher refusals, model check, auto-backup, verify-after-write) are
intact; the release adds two more (GPT CRC gate, unknown READ_DATA_64
lengths are never guessed).

## 0.1.0 (2026-10-25)

Initial release: Sahara + Firehose client, termux-usb FD transport,
OPLUS VIP digest/sign support, ARB report, A/B bootctl, offline parsers,
mock device + 23 unit tests + launcher E2E suite.
