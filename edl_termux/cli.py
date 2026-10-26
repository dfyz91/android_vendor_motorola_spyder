#!/usr/bin/env python3
"""edlt - EDL (Sahara/Firehose) client for Termux, no root, OPLUS VIP aware.

Runs against:
 - a termux-usb FD (EDL_USB_FD / --fd N) via libusb_wrap_sys_device
 - normal libusb enumeration (--enum), for desktop/rooted use

Default policy: READ-ONLY. Writes/erases need --i-know-what-i-am-doing,
are auto-backed-up, ARB-checked and model-checked.
"""
import argparse
import hashlib
import io
import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from edl_termux import arb as arb_mod
from edl_termux import bootctl, firehose, gpt, oplus, qcomimage, reference, sahara
from edl_termux.log import Logger
from edl_termux.usb import (DeviceGoneError, EnumTransport, LibusbFdTransport,
                            TransportError)


class SafetyError(Exception):
    pass


def die(msg, code=1):
    print("ERROR: %s" % msg, file=sys.stderr)
    sys.exit(code)


def read_args_file(path):
    with open(path, "rb") as f:
        raw = f.read()
    return [a.decode() for a in raw.split(b"\x00") if a]


# ---------------------------------------------------------------- session
class Session:
    """One USB session: Sahara (optionally command-mode first) -> loader ->
    (optional VIP) -> firehose -> configure -> storage -> GPT."""

    def __init__(self, args, log):
        self.args = args
        self.log = log
        self.tr = None
        self.sc = None
        self.fh = None
        self.table = None
        self.storage = None

    def open(self):
        a = self.args
        if a.enum:
            self.tr = EnumTransport(log=self.log)
        else:
            fd = a.fd if a.fd is not None else os.environ.get("EDL_USB_FD")
            if fd is None:
                die("no USB access: pass --fd N / EDL_USB_FD (termux-usb) or --enum")
            self.tr = LibusbFdTransport(
                fd, log=self.log, dump_descriptors=a.usb_descriptors
            )
            # verify the FD really points at the expected Qualcomm EDL
            # device before any Sahara traffic (termux-usb can hand us
            # an arbitrary USB device; the launcher cannot see VID/PID)
            if not a.no_vid_check:
                try:
                    vid, pid = self.tr.get_vid_pid()
                except Exception as e:
                    die("could not read USB device descriptor: %s" % e, 6)
                if (vid, pid) != (a.vid, a.pid):
                    die("wrong USB device: %04x:%04x, expected %04x:%04x "
                        "(Qualcomm EDL 9008). If this FD belongs to a "
                        "different gadget, do not bypass this check - "
                        "unplug other USB devices and re-run. "
                        "(override only with --no-vid-check)"
                        % (vid, pid, a.vid, a.pid), 6)
        return self.tr

    def _gone_hint(self):
        return ("Device gone / FD dead (reset or disconnect). "
                "RE-RUN the launcher so termux-usb grants a NEW FD - "
                "there is no auto-reconnect.")

    def chipinfo(self):
        self.open()
        self.sc = sahara.SaharaClient(self.tr, log=self.log)
        info = self.sc.chipinfo()
        return info

    def to_image_mode(self):
        """After chipinfo: switch Sahara into image-transfer mode."""
        self.sc.switch_mode(sahara.MODE_IMAGE_TX_PENDING)
        self.sc.hello = {"mode": sahara.MODE_IMAGE_TX_PENDING}

    def load_loader(self, need_chipinfo=False):
        """Full bring-up. need_chipinfo=True also runs command mode first
        (identity/model check before any dangerous operation)."""
        a = self.args
        self.open()
        self.sc = sahara.SaharaClient(self.tr, log=self.log)
        if need_chipinfo:
            info = self.sc.chipinfo()
            ok, notes = reference.matches_device(info)
            if not ok and not a.force:
                die("device model check FAILED:\n  - %s\nRefusing. If this "
                    "really is the intended device, retry with --force."
                    % "\n  - ".join(notes))
            self.to_image_mode()
        else:
            self.sc.connect(want_mode=sahara.MODE_IMAGE_TX_PENDING)
        img = self._read_loader_image()
        try:
            self.sc.upload_image(img, image_id=reference.PROGRAMMER_IMAGE_ID,
                                 progress_cb=self._progress, need_connect=False)
        except DeviceGoneError as e:
            die("%s\n%s" % (e, self._gone_hint()), 3)
        except sahara.SaharaError as e:
            status = getattr(e, "status", None)
            if status is not None:
                die("device REJECTED the programmer: %s\nSahara END_IMAGE_TX "
                    "status 0x%02x = %s\nThis is NOT a transport error: the "
                    "PBL/TrustZone refused this image (auth/VIP/ARB/wrong "
                    "programmer). Try another programmer, or check the "
                    "digest/sign flow." %
                    (e, status, sahara.STATUS_NAMES.get(status, "unknown")),
                    4)
            raise
        self.fh = firehose.FirehoseClient(self.tr, log=self.log)
        # VIP activation when a digest table is supplied
        if a.digest:
            blob = self._read_digest(a.digest)
            try:
                self.fh.vip_enable(blob, sign_bytes=self._maybe(a.sign))
            except DeviceGoneError as e:
                die("%s\n%s" % (e, self._gone_hint()), 3)
            except firehose.FirehoseError as e:
                die("VIP activation failed: %s" % e, 5)
        # configure
        try:
            self.fh.configure(memory=a.memory)
        except firehose.FirehoseError as e:
            die("firehose configure failed: %s\nIf the loader is VIP-enabled "
                "you MUST pass --digest (and possibly --sign)." % e, 5)
        try:
            self.storage = self.fh.getstorageinfo()
        except Exception as e:
            self.log and self.log.warn("getstorageinfo failed: %s" % e)
        self.table = gpt.read_gpt_from_firehose(
            self.fh, sector_size=reference.SECTOR_SIZE, log=self.log)
        return True

    def _read_loader_image(self):
        path = self.args.loader
        if not path:
            die("no programmer given. Use --loader FILE (OPLUS SM8350 "
                "programmer whose root cert matches the device PK hash).")
        with open(path, "rb") as f:
            img = f.read()
        h = hashlib.sha256(img).hexdigest()
        self.log and self.log.info(
            "programmer: %s (%d bytes, sha256 %s)" % (path, len(img), h))
        return img

    def _read_digest(self, path):
        with open(path, "rb") as f:
            data = f.read()
        blob = oplus.extract_digest_blob(data)
        d = oplus.parse_digest(blob)
        self.log and self.log.info(
            "VIP digest table v%d: %d entries (%s...)" %
            (d["version"], d["partition_nums"],
             ", ".join(e.label for e in d["entries"][:5])))
        return blob

    def _maybe(self, path):
        if not path:
            return None
        with open(path, "rb") as f:
            return f.read()

    def _progress(self, done, total):
        pct = 100.0 * done / max(1, total)
        sys.stderr.write("\r  loader: %d / %d bytes (%.1f%%)" %
                         (done, total, pct))
        sys.stderr.flush()
        if done >= total:
            sys.stderr.write("\n")


# ---------------------------------------------------------------- helpers
def fmt_chipinfo(info):
    lines = ["=== chipinfo (Sahara command mode) ==="]
    for k in ("sahara_version", "mode", "serial", "msm_id", "oem_id",
              "model_id", "oem_name", "hw_id", "pk_hash", "sw_version"):
        v = info.get(k)
        if isinstance(v, int):
            lines.append("%-15s: 0x%x (%d)" % (k, v, v))
        else:
            lines.append("%-15s: %s" % (k, v))
    lines.append("pk_hash bytes  : %d" % (len(info.get("pk_hash") or "") // 2))
    ok, notes = reference.matches_device(info)
    lines.append("MT2110 ref     : %s%s" % ("MATCH" if ok else "MISMATCH",
                                            (" (" + "; ".join(notes) + ")") if notes else ""))
    return "\n".join(lines)


def backup_part(sess, name, part):
    bdir = os.path.join(sess.args.backup_dir or "edlt-backups",
                        time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(bdir, exist_ok=True)
    path = os.path.join(bdir, "%s.img" % name)
    buf = io.BytesIO()
    sess.fh.read_sectors(part_lun(sess, name), part["first_lba"],
                         part["sectors"], sess.table.sector_size, buf)
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    print("[backup] %s -> %s (%d bytes, sha256 %s)" %
          (name, path, len(buf.getvalue()),
           hashlib.sha256(buf.getvalue()).hexdigest()))
    return path


def part_lun(sess, name):
    f = sess.table.find(name)
    if not f:
        die("partition %r not found in GPT" % name)
    return f[0]


def find_part(sess, name):
    f = sess.table.find(name)
    if not f:
        die("partition %r not found in GPT. Known:" % name +
            "\n  " + "\n  ".join(
                "%s (lun%d @%d +%d sect)" % (n, lun, s, c)
                for lun, n, s, c in sess.table.names()[:40]))
    lun, p = f
    return lun, p


def gpt_crc_guard(sess, lun):
    """Refuse to act on a LUN whose GPT CRC is invalid (damaged table
    -> wrong sector coordinates). Raises SafetyError."""
    gpt = sess.table.luns.get(lun)
    if gpt is not None and getattr(gpt, "crc_ok", None) is False:
        raise SafetyError(
            "GPT of lun%d has an INVALID CRC32 (header or entries array "
            "is damaged). Acting on a corrupted table can hit the wrong "
            "sectors. Refusing; dump and inspect the table first "
            "(gpt / r gpt)." % lun)


def write_guards(sess, part_name, image_path, image_data):
    """All safety checks for a partition write. Raises SafetyError."""
    a = sess.args
    if not a.i_know_what_i_am_doing:
        raise SafetyError(
            "writes are disabled by default. Add "
            "--i-know-what-i-am-doing (and understand: bad xbl/abl data "
            "can hard-brick the device).")
    lun, part = find_part(sess, part_name)
    # refuse writes from a corrupted partition table: a bad first_lba
    # would hit the wrong sectors on flash
    gpt_crc_guard(sess, lun)
    if len(image_data) > part["sectors"] * sess.table.sector_size:
        raise SafetyError("image (%d B) larger than partition %s (%d B)" %
                          (len(image_data), part_name,
                           part["sectors"] * sess.table.sector_size))
    if len(image_data) % sess.table.sector_size:
        raise SafetyError("image size not a multiple of sector size %d" %
                          sess.table.sector_size)
    # ARB gate for boot-critical partitions
    base = part_name
    critical = False
    for prefix in reference.ARB_CRITICAL:
        if base == prefix or base.startswith(prefix + "_"):
            critical = True
            break
    if critical:
        try:
            img_info = qcomimage.parse_image(image_data)
        except Exception as e:
            raise SafetyError(
                "%s is ARB-critical but the image could not be parsed as a "
                "Qualcomm signed image (%s). Refusing - verify the file "
                "with image-info first." % (part_name, e))
        img_arb = img_info.get("anti_rollback_version")
        cur_arb = None
        try:
            cur = arb_mod.inspect_partition(sess.fh, sess.table, part_name)
            cur_arb = (cur.get("info") or {}).get("anti_rollback_version")
        except Exception as e:
            print("[warn] could not read current %s for ARB compare: %s" %
                  (part_name, e))
        problems = arb_mod.check_write_image(
            part_name, img_info, {"anti_rollback_version": cur_arb} if cur_arb is not None else None,
            allow_rollback=a.allow_rollback_image)
        if problems:
            raise SafetyError("; ".join(problems))
        if img_arb is not None and cur_arb is not None and img_arb > cur_arb and not a.allow_arb_raise:
            raise SafetyError(
                "image ARB %d > on-device ARB %d. Flashing this can "
                "IRREVERSIBLY raise the anti-rollback e-fuse once the OS "
                "boots. Refusing; retry with --allow-arb-raise if that is "
                "really intended." % (img_arb, cur_arb))
        print("[arb] %s: image ARB=%s, on-device ARB=%s%s" %
              (part_name, img_arb, cur_arb,
               "" if img_arb == cur_arb else "  <== DIFFERENT"))
    return lun, part


def confirm_or_yes(sess, prompt):
    if sess.args.yes:
        return
    if not sys.stdin.isatty():
        die("confirmation required, but stdin is not a TTY (this is the "
            "normal case when spawned via termux-usb -e). Re-run with "
            "--yes to confirm non-interactively.", 2)
    ans = input("%s\nType 'YES' to continue: " % prompt)
    if ans != "YES":
        die("aborted by user", 2)


# ---------------------------------------------------------------- commands
def cmd_chipinfo(sess):
    info = sess.chipinfo()
    print(fmt_chipinfo(info))


def cmd_loader(sess):
    sess.load_loader(need_chipinfo=False)
    print("=== firehose up ===")
    print("VIP announced  : %s" % sess.fh.vip_enabled)
    print("storage        : %s" % sess.storage)
    print("GPT LUNs       : %s" % sorted(sess.table.luns))
    for lun, name, s, c in sess.table.names():
        print("  lun%-2d %-28s @LBA %-8d %8d sectors" % (lun, name, s, c))
    print("supported funcs: %s" % (", ".join(sess.fh.supported_functions) or "n/a"))
    print("READ-ONLY check OK. No writes were performed.")


def cmd_gpt(sess):
    sess.load_loader(need_chipinfo=False)
    for lun in sorted(sess.table.luns):
        if getattr(sess.table.luns[lun], "crc_ok", None) is False:
            print("[warn] lun%d: GPT CRC MISMATCH - partition data is "
                  "damaged, treat entries as unreliable; writes are refused"
                  % lun)
    for lun, name, s, c in sess.table.names():
        print("lun%-2d %-28s @LBA %-8d %10d sectors  (%d B)" %
              (lun, name, s, c, c * sess.table.sector_size))
    if sess.args.save:
        os.makedirs(sess.args.save, exist_ok=True)
        for lun, name, s, c in sess.table.names():
            p = find_part(sess, name)
            if not p[1]:
                continue
            buf = io.BytesIO()
            sess.fh.read_sectors(p[0], p[1]["first_lba"], p[1]["sectors"],
                                 sess.table.sector_size, buf)
            with open(os.path.join(sess.args.save, "%s.img" % name), "wb") as f:
                f.write(buf.getvalue())
        print("[saved] partitions dumped to %s" % sess.args.save)


def _ensure_parent(path):
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)


def _do_read(sess, name, out_path):
    lun, part = find_part(sess, name)
    buf = io.BytesIO()
    sess.fh.read_sectors(lun, part["first_lba"], part["sectors"],
                         sess.table.sector_size, buf)
    data = buf.getvalue()
    _ensure_parent(out_path)
    with open(out_path, "wb") as f:
        f.write(data)
    print("[read] %s (lun%d @%d, %d bytes) -> %s  sha256 %s" %
          (name, lun, part["first_lba"], len(data), out_path,
           hashlib.sha256(data).hexdigest()))
    return data


def cmd_r(sess):
    sess.load_loader(need_chipinfo=False)
    _do_read(sess, sess.args.partition, sess.args.out)


def cmd_rl(sess):
    sess.load_loader(need_chipinfo=False)
    d = sess.args.dir
    os.makedirs(d, exist_ok=True)
    parts = (sess.args.parts.split(",") if sess.args.parts
             else list(reference.BOOT_CHAIN))
    for name in parts:
        try:
            _do_read(sess, name, os.path.join(d, "%s.img" % name))
        except SystemExit:
            raise
        except Exception as e:
            print("[warn] %s: %s" % (name, e))


def cmd_rs(sess):
    sess.load_loader(need_chipinfo=False)
    lun, start, cnt = sess.args.lun, sess.args.start, sess.args.count
    buf = io.BytesIO()
    sess.fh.read_sectors(lun, start, cnt, reference.SECTOR_SIZE, buf)
    with open(sess.args.out, "wb") as f:
        f.write(buf.getvalue())
    print("[read] lun%d @%d +%d sectors -> %s" % (lun, start, cnt, sess.args.out))


def cmd_w(sess):
    # writes always bring the session up WITH the identity check first
    sess.load_loader(need_chipinfo=True)
    with open(sess.args.file, "rb") as f:
        data = f.read()
    h = hashlib.sha256(data).hexdigest()
    print("[image] %s: %d bytes, sha256 %s" % (sess.args.file, len(data), h))
    try:
        lun, part = write_guards(sess, sess.args.partition, sess.args.file, data)
    except SafetyError as e:
        die(str(e), 10)
    if not sess.args.no_backup:
        backup_part(sess, sess.args.partition, part)
    confirm_or_yes(sess, "WRITE %d bytes to %s (lun%d @%d)?" %
                   (len(data), sess.args.partition, lun, part["first_lba"]))
    sess.fh.program_sectors(lun, part["first_lba"], data,
                            sess.table.sector_size)
    print("[written] %s" % sess.args.partition)
    # verify
    buf = io.BytesIO()
    sess.fh.read_sectors(lun, part["first_lba"],
                         (len(data) + sess.table.sector_size - 1) // sess.table.sector_size,
                         sess.table.sector_size, buf)
    got = buf.getvalue()
    ok = got[:len(data)] == data
    print("[verify] %s" % ("OK - data matches" if ok else
                           "FAILED - readback differs! Do not reset yet."))
    if not ok:
        sys.exit(11)


def cmd_e(sess):
    sess.load_loader(need_chipinfo=True)
    lun, part = find_part(sess, sess.args.partition)
    if not sess.args.i_know_what_i_am_doing:
        die("erase is disabled by default; add --i-know-what-i-am-doing", 10)
    try:
        gpt_crc_guard(sess, lun)
    except SafetyError as e:
        die(str(e), 10)
    if not sess.args.no_backup:
        backup_part(sess, sess.args.partition, part)
    confirm_or_yes(sess, "ERASE %s (lun%d @%d, %d sectors)?" %
                   (sess.args.partition, lun, part["first_lba"], part["sectors"]))
    sess.fh.erase(lun, part["first_lba"], part["sectors"])
    print("[erased] %s" % sess.args.partition)


def cmd_arb_report(sess):
    sess.load_loader(need_chipinfo=False)
    rep = arb_mod.arb_report(sess.fh, sess.table,
                             stock_dir=sess.args.stock_dir, log=sess.log)
    print(arb_mod.format_report(rep, pk_hash=reference.PK_HASH))


def cmd_slot(sess):
    sess.load_loader(need_chipinfo=False)
    data = _do_read(sess, "misc", os.path.join(
        sess.args.backup_dir or "edlt-backups", "misc.last.img"))
    bc = bootctl.parse_bootctl(data)
    print(bootctl.format_bootctl(bc))


def cmd_setslot(sess):
    if not sess.args.i_know_what_i_am_doing:
        die("setslot is a WRITE to misc; add --i-know-what-i-am-doing", 10)
    sess.load_loader(need_chipinfo=True)
    data = _do_read(sess, "misc", os.path.join(
        sess.args.backup_dir or "edlt-backups", "misc.pre-setslot.img"))
    bc = bootctl.parse_bootctl(data)
    print(bootctl.format_bootctl(bc))
    new = bootctl.set_active_slot(data, sess.args.slot)
    confirm_or_yes(sess, "Set ACTIVE SLOT = %s in misc?" % sess.args.slot)
    lun, part = find_part(sess, "misc")
    try:
        gpt_crc_guard(sess, lun)
    except SafetyError as e:
        die(str(e), 10)
    sess.fh.program_sectors(lun, part["first_lba"], new,
                            sess.table.sector_size)
    # verify
    buf = io.BytesIO()
    sess.fh.read_sectors(lun, part["first_lba"], part["sectors"],
                         sess.table.sector_size, buf)
    bc2 = bootctl.parse_bootctl(buf.getvalue())
    print(bootctl.format_bootctl(bc2))
    print("[setslot] active slot now: %s" % bootctl.active_slot(bc2))


def cmd_misc_dump(sess):
    sess.load_loader(need_chipinfo=False)
    _do_read(sess, "misc", sess.args.out)


def cmd_reset(sess):
    sess.load_loader(need_chipinfo=False)
    sess.fh.reset(mode=sess.args.reset_type or "reset")
    print("[reset] requested. The device will leave EDL (or re-enter). "
          "For a new session: re-run the launcher for a fresh FD.")


def cmd_peek(sess):
    sess.load_loader(need_chipinfo=False)
    data = sess.fh.peek(sess.args.address, sess.args.size)
    from edl_termux.log import hexdump
    print(hexdump(data, limit=4096))


def cmd_poke(sess):
    if not sess.args.i_know_what_i_am_doing:
        die("poke is a WRITE to memory; add --i-know-what-i-am-doing", 10)
    sess.load_loader(need_chipinfo=False)
    sess.fh.poke(sess.args.address, bytes.fromhex(sess.args.hexbytes))
    print("[poke] done")


def cmd_vip_probe(sess):
    sess.load_loader(need_chipinfo=False)
    hits = sess.fh.vip_probe_configure(memory=sess.args.memory)
    print("accepted configure variants: %s" % hits)
    print("hash oracle expected: %s" % sess.fh.expected_hashes)
    print("hash oracle found   : %s" % sess.fh.found_hashes)


# offline commands (no device)
def cmd_image_info(a):
    with open(a.file, "rb") as f:
        data = f.read()
    info = qcomimage.parse_image(data)
    print("file   : %s (%d bytes)" % (a.file, len(data)))
    print("sha256 : %s" % hashlib.sha256(data).hexdigest())
    print(qcomimage.format_info(info, pk_hex=a.pk_hash or reference.PK_HASH))


def cmd_digest_info(a):
    with open(a.file, "rb") as f:
        data = f.read()
    d = oplus.parse_digest(data)
    print(oplus.format_digest(d))


def cmd_gpt_info(a):
    with open(a.file, "rb") as f:
        data = f.read()
    h = gpt.parse_header(data)
    print("GPT header: %s" % h)
    ent_bytes = h["num_entries"] * h["entry_size"]
    print("(entries live at LBA %d - dump them separately)" % h["entries_lba"])


# ------------------------------------------------------------------ parser
def build_parser():
    p = argparse.ArgumentParser(prog="edlt", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--fd", type=int, help="USB fd from termux-usb")
    p.add_argument("--usb-descriptors", action="store_true",
                   help="read/log USB interfaces and endpoints before claim (FD transport only)")
    p.add_argument("--enum", action="store_true", help="libusb enumeration (desktop/root)")
    p.add_argument("--args-file", help="NUL-separated args file (launcher)")
    p.add_argument("--log", help="packet log file")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--loader", help="programmer ELF/MBN to upload")
    p.add_argument("--digest", help="OPLUS VIP digest table (or wrapper)")
    p.add_argument("--sign", help="OPLUS VIP sign blob (optional)")
    p.add_argument("--memory", default="UFS")
    p.add_argument("--force", action="store_true",
                   help="skip device-identity check (writes)")
    p.add_argument("--yes", action="store_true", help="no interactive confirm")
    # safety
    p.add_argument("--i-know-what-i-am-doing", action="store_true")
    p.add_argument("--allow-rollback-image", action="store_true",
                   help="allow image with LOWER arb than on-device")
    p.add_argument("--allow-arb-raise", action="store_true",
                   help="allow image with HIGHER arb (can burn fuse)")
    p.add_argument("--no-backup", action="store_true")
    p.add_argument("--backup-dir", default="edlt-backups")
    # USB identity check (real termux-usb does not expose VID/PID in -l)
    p.add_argument("--vid", type=lambda x: int(x, 0), default=0x05C6,
                   help="expected USB vendor id (default 05c6 Qualcomm)")
    p.add_argument("--pid", type=lambda x: int(x, 0), default=0x9008,
                   help="expected USB product id (default 9008 EDL)")
    p.add_argument("--no-vid-check", action="store_true",
                   help="skip the FD device-descriptor VID/PID check")

    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("chipinfo", help="Sahara command mode info (read-only)")
    s = sub.add_parser("loader", help="upload programmer + bring up firehose (read-only)")
    s = sub.add_parser("gpt", help="read & print GPT (read-only)")
    s.add_argument("--save", help="dump all partitions to this dir")
    s = sub.add_parser("r", help="read partition -> file")
    s.add_argument("partition"); s.add_argument("out")
    s = sub.add_parser("rl", help="read boot chain -> dir")
    s.add_argument("dir"); s.add_argument("--parts", help="comma list (default xbl*/abl*)")
    s = sub.add_parser("rs", help="raw sector read")
    s.add_argument("lun", type=int); s.add_argument("start", type=int)
    s.add_argument("count", type=int); s.add_argument("out")
    s = sub.add_parser("w", help="write file -> partition (guarded)")
    s.add_argument("partition"); s.add_argument("file")
    s = sub.add_parser("e", help="erase partition (guarded)")
    s.add_argument("partition")
    s = sub.add_parser("reset", help="firehose power reset")
    s.add_argument("--reset-type", default="reset")
    s = sub.add_parser("arb-report", help="read xbl*/abl*, report versions+ARB")
    s.add_argument("--stock-dir", help="dir with stock images to compare")
    s = sub.add_parser("slot", help="read bootloader_control from misc")
    s = sub.add_parser("setslot", help="set active slot (write to misc)")
    s.add_argument("slot", choices=["a", "b"])
    s = sub.add_parser("misc-dump", help="dump misc partition")
    s.add_argument("out")
    s = sub.add_parser("peek", help="peek memory (read-only)")
    s.add_argument("address", type=lambda x: int(x, 0))
    s.add_argument("size", type=lambda x: int(x, 0))
    s = sub.add_parser("poke", help="poke memory (guarded)")
    s.add_argument("address", type=lambda x: int(x, 0))
    s.add_argument("hexbytes")
    s = sub.add_parser("vip-probe", help="probe accepted configure strings")
    s = sub.add_parser("image-info", help="offline: parse Qualcomm image")
    s.add_argument("file"); s.add_argument("--pk-hash", help="compare certs to this hash")
    s = sub.add_parser("digest-info", help="offline: parse OPLUS digest table")
    s.add_argument("file")
    s = sub.add_parser("gpt-info", help="offline: parse dumped GPT header sector")
    s.add_argument("file")
    return p


ONLINE_CMDS = {
    "chipinfo": cmd_chipinfo, "loader": cmd_loader, "gpt": cmd_gpt,
    "r": cmd_r, "rl": cmd_rl, "rs": cmd_rs, "w": cmd_w, "e": cmd_e,
    "arb-report": cmd_arb_report, "slot": cmd_slot, "setslot": cmd_setslot,
    "misc-dump": cmd_misc_dump, "reset": cmd_reset, "peek": cmd_peek,
    "poke": cmd_poke, "vip-probe": cmd_vip_probe,
}
OFFLINE_CMDS = {"image-info": cmd_image_info, "digest-info": cmd_digest_info,
                "gpt-info": cmd_gpt_info}


def main():
    argv = sys.argv[1:]
    # find --args-file first (launcher passes everything else via it)
    args_file = None
    for i, a in enumerate(argv):
        if a == "--args-file" and i + 1 < len(argv):
            args_file = argv[i + 1]
            break
    if args_file:
        argv = argv + read_args_file(args_file)
    parser = build_parser()
    args = parser.parse_args(argv)

    log = Logger(verbose=args.verbose and not args.quiet, logfile=args.log)

    if args.cmd in OFFLINE_CMDS:
        OFFLINE_CMDS[args.cmd](args)
        return

    sess = Session(args, log)
    fn = ONLINE_CMDS[args.cmd]
    try:
        fn(sess)
    except DeviceGoneError as e:
        die("%s\n%s" % (e, sess._gone_hint()), 3)
    except TransportError as e:
        die("USB transport error: %s\n%s" % (e, sess._gone_hint()), 3)
    except firehose.FirehoseError as e:
        die("firehose: %s" % e, 5)
    except sahara.SaharaError as e:
        die("sahara: %s" % e, 4)


if __name__ == "__main__":
    main()
