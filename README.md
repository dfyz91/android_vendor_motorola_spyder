# edl-termux

Qualcomm EDL (Sahara + Firehose) client for **Termux (Android, no root)** with
OPLUS (OnePlus/OPPO/Realme) VIP support and an A/B anti-rollback (ARB) inspector.

Written from scratch for the OnePlus 9R/9RT/9 (SM8350) un-brick scenario:
device in Qualcomm HS-USB QDLoader 9008 (05c6:9008), host = Termux on another
Android phone connected via OTG, USB access only through the file descriptor
passed by `termux-usb -r -e`.

## Highlights

- USB transport via `libusb_wrap_sys_device()` on the `termux-usb` FD (ctypes, no pyusb).
- Sahara protocol v1/v2: HELLO, command mode (serial/HW ID/PK hash/SW version),
  image transfer (READ_DATA / READ_DATA_64), END_IMAGE_TX/DONE, reset.
  With `-v`, every packet is logged with timestamp + hexdump; `--log FILE`
  persists the trace so `-71 (EPROTO)` can be separated from an explicit
  Sahara refusal such as END_IMAGE_TX status 0x0D.
- Firehose XML protocol: configure, getstorageinfo, GPT read (all LUNs),
  read/program/erase sectors, raw commands, reset/power.
- OPLUS VIP helpers: send signed digest (+sign) after "VIP is enabled" log,
  `vip-probe` uses the loader's own "Expected: <sha256>" answers as an oracle.
- `arb-report`: reads xbl/abl from both A/B slots, extracts image version,
  OEM/model/SoC IDs and the **anti-rollback version** from the signed-image
  hash segment (MBN v3/v5/v6/v7), compares slots and local stock images.
- `image-info` / `digest-info`: offline static parsers (Qualcomm signed images,
  OPLUS digest tables, magic 0x7CEF0312).
- Read-only by default. Writes/erases need `--i-know-what-i-am-doing` and are
  additionally guarded by model/ARB checks.

## Install (Termux)

    pkg install python libusb termux-api binutils
    sh install.sh

## Quick start

    # 1. list the 9008 device (real termux-usb prints PLAIN paths, e.g.
    #    ["/dev/bus/usb/001/031"] - the launcher understands this format)
    termux-usb -l

    # 2. chipinfo through a fresh FD (launcher tries every listed device;
    #    the Qualcomm 05c6:9008 check is done INSIDE edlt via the USB
    #    descriptor after the FD is opened - termux-usb has no VID/PID API)
    edl-termux-fd.sh chipinfo

    # 3. load a firehose programmer (read-only so far).
    # NOTE: --loader/--digest/--sign/--log are GLOBAL options and must come
    # BEFORE the subcommand ("loader"), not after it.
    edl-termux-fd.sh --loader /sdcard/prog/OPPO_SM8350_New_Chimera_V2.6.elf loader

    # 3b. OPLUS VIP variant (digest + sign from the same Chimera set):
    # edl-termux-fd.sh --loader prog.elf --digest digest.elf --sign sign.bin loader

    # 4. after the loader runs, read GPT and boot partitions
    edl-termux-fd.sh gpt
    edl-termux-fd.sh r abl_a abl_a.img
    edl-termux-fd.sh arb-report

After any device reset/EDL re-entry the old FD is dead: just re-run the
launcher, it asks `termux-usb` for a fresh FD every time.

## Offline commands (no device needed)

    edlt image-info abl.img          # version, OEM/model/SoC ID, ARB version, certs
    edlt digest-info digest.elf     # OPLUS VIP partition table
    edlt gpt-info gpt_main0.bin      # parse a dumped GPT

## Safety model

- Default pipeline is strictly read-only: chipinfo -> loader -> GPT -> dump.
- `w` (write) and `e` (erase) require `--i-know-what-i-am-doing`.
- Interactive confirmation needs a terminal; under `termux-usb -e` stdin
  is not a TTY, so pass `--yes` for non-interactive confirmed writes.
- Writing xbl/abl/xbl_config/aop/tools also requires the image's
  OEM_ID/MODEL_ID to match the connected device and shows an ARB comparison;
  an image with a LOWER anti-rollback version than the one currently on the
  slot is refused unless you pass `--allow-rollback-image` (it will probably
  not boot - the fuse can only rise, never fall).
- Writes (w), erases (e) and setslot are refused when the target LUN's GPT
  has an invalid CRC32 - a damaged table means unreliable sector
  coordinates. The `gpt` command prints a warning for such LUNs; dump and
  inspect the table before anything else.

## USB identity check and exit codes

The launcher passes every device from `termux-usb -l` to edlt; edlt reads the
device descriptor of the FD and refuses anything that is not 05c6:9008
(override values with `--vid`/`--pid`; do NOT use `--no-vid-check` on a
device you are not sure about).

Exit codes: 0 ok; 1 general error; 2 aborted; 3 device gone (re-run the
launcher for a fresh FD); 4 Sahara refused the programmer (auth/ARB/VIP -
NOT a USB problem); 5 firehose error; 6 wrong USB device (not 05c6:9008);
10 write/erase refused by a safety gate; 11 post-write verify mismatch.

If the launcher E2E test reports "port is already in use", a stale mock
server from a previous run is still alive: run `pkill -f mock_server.py`
or set `EDLT_MOCK_PORT`.

## Tests (no device needed)

    sh run_tests.sh                  # unit tests + launcher end-to-end (all)
    sh tests/test_launcher.sh        # termux-usb shim + launcher end-to-end only
    python tests/test_all.py         # unit/protocol tests only

## Sources / credits

- Sahara & Firehose protocol: linux-msm/qdl (BSD), bkerler/edl (GPLv3) - protocol knowledge only, no code copied.
- OPLUS digest table format: JacksonOnly/OplusDigestUtils (MIT).
- Qualcomm signed image hash segment (MBN v3/v5/v6/v7): JacksonOnly/QualcommImageUtils (MIT).
- termux-usb FD wrapping approach: Querela/termux-usb-python (MIT).
- VIP behaviour ("VIP is enabled", digest send, per-command hash NAK): bkerler/edl issue #439 (public log excerpts).

License: MIT (see LICENSE).


## USB descriptor diagnostics (v0.1.3)

Before a read-only chipinfo check, inspect the actual configuration without
changing it or claiming an interface manually:

```sh
sh ~/edl-termux/edl-termux-fd.sh --usb-descriptors -v --log ~/edl-chipinfo.log chipinfo
```

`--usb-descriptors` reports every interface and alternate setting, endpoints,
direction, transfer type and `wMaxPacketSize` before the normal interface claim.
`chipinfo` is read-only. For a programmer test, use only a trusted ELF and keep
all partition-write commands disabled; loading an ELF executes device code even
when no partition write is requested.
