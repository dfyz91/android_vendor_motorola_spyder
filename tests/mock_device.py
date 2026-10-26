"""In-process mock of a OnePlus 9RT in EDL (Qualcomm 9008, Sahara + Firehose).

Reproduces, with the TARGET'S REAL measured values:
  serial 0x0C7096BF, MSM 0x001350E1, OEM 0x0051, MODEL 0x0000,
  PK hash d8e3...ff49 (48 bytes, SHA-384-sized)

Protocol behaviour modelled (per public Sahara/Firehose protocol + OPLUS VIP
flow from OplusEdlTool and bkerler/edl#439):
  HELLO v2 (mode echoed) -> command mode (CMD_READY, EXECUTE_*) or
  image mode (READ_DATA_64 chunks, END_IMAGE_TX, DONE) -> firehose XML:
  <verify ping EnableVip=1> -> "VIP is enabled, receiving the partition
  info of size N" -> raw digest table -> every command's sha256 must be
  in the table (NAK + Expected/Found oracle otherwise).

Failure-injection modes (see --mock-fail):
  eproto_before   EPROTO (-71) right after HELLO_RSP, before any READ_DATA
  eproto_mid      EPROTO halfway through the programmer upload
  timeout         device goes silent (empty reads)
  eio             EIO on read
  disconnect      FD dies
  reject_loader   END_IMAGE_TX status 0x0D (NAK_READ_DATA_ERROR) - the XDA
                  9RT case: PBL refuses the programmer
  reject_auth     END_IMAGE_TX status 0x21 (TARGET_AUTH_FAILURE)
  vip_nak         digest table rejected -> configure NAKs

NOT emulated: real OTG timings, PBL auth code, TZ fuses, UFS controller.
"""
import hashlib
import re
import struct

from edl_termux import gpt, oplus, reference
from edl_termux.firehose import XML_HDR
from edl_termux.usb import DeviceGoneError, TransportError

SECTOR = reference.SECTOR_SIZE
UPLOAD_CHUNK = 0x10000


def synth_mbn_v6(image_id, arb, oem_id=reference.OEM_ID,
                 model_id=reference.MODEL_ID):
    """Synthetic but structurally valid MBN v6 hash segment (48B header +
    40B QTI meta + 120B OEM meta + 48B hash). ARB lands at OEM meta +116."""
    b = bytearray(48 + 40 + 120 + 48)
    struct.pack_into("<HHI", b, 0, 48, 6, image_id)
    struct.pack_into("<IIII", b, 16, 0x40, 0x200, 48, len(b))
    struct.pack_into("<II", b, 40, 40, 120)
    o = 88
    struct.pack_into("<II", b, o + 16, oem_id, model_id)
    struct.pack_into("<I", b, o + 32, 0x00030000)   # soc_hw_version
    struct.pack_into("<I", b, o + 112, 1)            # oem_root_cert_slot
    struct.pack_into("<I", b, o + 116, arb)          # anti_rollback_version
    # 48-byte hash-table filler (deterministic, sha256-based so the TS
    # mirror can reproduce it byte-for-byte; content is irrelevant)
    b[-48:] = (hashlib.sha256(b"mock").digest() * 2)[:48]
    return bytes(b)


def synth_misc(active="a"):
    """misc image (1 sector kept 8 sectors) with bootloader_control@2048."""
    import zlib
    buf = bytearray(8 * SECTOR)
    off = 2048
    buf[off:off + 2] = ("_" + active).encode()
    buf[off + 32:off + 36] = b"BOOT"
    buf[off + 36] = 1                       # version
    buf[off + 37] = 0 if active == "a" else 1
    idx = 0 if active == "a" else 1
    for i in range(2):
        base = off + 40 + i * 4
        buf[base] = 15 if i == idx else 0
        buf[base + 1] = 7 if i == idx else 0
    struct.pack_into("<I", buf, off + 48, zlib.crc32(bytes(buf[off:off + 48])) & 0xFFFFFFFF)
    return bytes(buf)


def default_storage():
    """Two LUNs with a realistic-ish layout and synthetic boot images."""
    abl_a = synth_mbn_v6(image_id=16, arb=0)
    abl_b = synth_mbn_v6(image_id=16, arb=1)
    xbl_a = synth_mbn_v6(image_id=40, arb=0)
    xbl_b = synth_mbn_v6(image_id=40, arb=0)
    xcfg_a = synth_mbn_v6(image_id=41, arb=0)
    xcfg_b = synth_mbn_v6(image_id=41, arb=0)
    SECT = lambda n: n * SECTOR

    lun0_parts = [
        {"name": "abl_a", "first_lba": 1024, "sectors": 64},
        {"name": "abl_b", "first_lba": 1088, "sectors": 64},
        {"name": "boot_a", "first_lba": 2048, "sectors": 256},
        {"name": "boot_b", "first_lba": 2304, "sectors": 256},
        {"name": "vendor_boot_a", "first_lba": 4096, "sectors": 512},
        {"name": "vendor_boot_b", "first_lba": 4608, "sectors": 512},
        {"name": "vbmeta_a", "first_lba": 6144, "sectors": 16},
        {"name": "vbmeta_b", "first_lba": 6160, "sectors": 16},
        {"name": "misc", "first_lba": 8192, "sectors": 16},
    ]
    lun1_parts = [
        {"name": "xbl_a", "first_lba": 64, "sectors": 128},
        {"name": "xbl_b", "first_lba": 192, "sectors": 128},
        {"name": "xbl_config_a", "first_lba": 320, "sectors": 32},
        {"name": "xbl_config_b", "first_lba": 352, "sectors": 32},
        {"name": "xbl_ramdump_a", "first_lba": 384, "sectors": 32},
        {"name": "xbl_ramdump_b", "first_lba": 416, "sectors": 32},
    ]
    storage = {0: bytearray(16384 * SECTOR), 1: bytearray(1024 * SECTOR)}
    for lun, parts in ((0, lun0_parts), (1, lun1_parts)):
        hdr, ents = gpt.build_gpt(parts, total_sectors=len(storage[lun]) // SECTOR)
        storage[lun][SECTOR:2 * SECTOR] = hdr
        storage[lun][2 * SECTOR:2 * SECTOR + len(ents)] = ents
        for p in parts:
            data = {"abl_a": abl_a, "abl_b": abl_b}.get(p["name"])
            if data is None:
                data = {"xbl_a": xbl_a, "xbl_b": xbl_b,
                        "xbl_config_a": xcfg_a, "xbl_config_b": xcfg_b}.get(
                        p["name"], b"\x00" * (p["sectors"] * SECTOR))
            storage[lun][p["first_lba"] * SECTOR:
                         p["first_lba"] * SECTOR + len(data)] = data
    storage[0][8192 * SECTOR:8192 * SECTOR + len(synth_misc())] = synth_misc()
    return storage


class MockDevice:
    """Plug into PipeTransport (in-process). host_read()/host_write()."""

    def __init__(self, storage=None, fail_mode=None, digest_len=None,
                 vip_required=True, loader_sha=None,
                 hello_after_switch=False, read64_len=0x1C):
        self.rx = b""
        self.buf = b""
        self.state = "start"
        self.fail_mode = fail_mode
        self.storage = storage if storage is not None else default_storage()
        self.uploaded = b""
        self.expect_raw = None
        self.loader_sha = loader_sha
        self.digest_len = digest_len
        self.read64_len = read64_len  # 0x1C (image_id u32) or 0x20 (u64)
        self.digest_raw = b""
        self.pending_program = None
        self.vip_required = vip_required
        self.vip_active = False
        self.vip_bad = False
        self.hello_after_switch = hello_after_switch
        self.allowed_hashes = []
        self.reset_seen = False
        self._queue_hello()

    # ------------------------------------------------------------- helpers
    def _send(self, data):
        self.rx += bytes(data)

    def _queue_hello(self):
        hello = struct.pack("<IIIIII" + "I" * 6, 1, 0x30, 2, 1, 0x200, 0,
                            0, 0, 0, 0, 0, 0)   # HELLO v2, mode 0
        self._send(hello)

    def _xml_log(self, value):
        self._send(("%s<data><log value=\"%s\"/></data>" % (XML_HDR, value)).encode())

    def _ack(self, ok=True, raw=""):
        v = "ACK" if ok else "NAK"
        extra = ' rawmode="%s"' % raw if raw else ""
        self._send(("%s<data><response value=\"%s\"%s/></data>"
                    % (XML_HDR, v, extra)).encode())

    # ------------------------------------------------------------- host io
    def host_read(self, size):
        if self.fail_mode == "timeout" and self.state in ("upload",
                                                          "wait_done"):
            return b""
        if self.fail_mode in ("eproto_before", "eproto_mid", "eio",
                              "disconnect"):
            if self._fail_point_reached():
                errno = 5 if self.fail_mode == "eio" else None
                raise DeviceGoneError("mock %s (simulated usb error)" %
                                     self.fail_mode, errno)
        out, self.rx = self.rx[:size], self.rx[size:]
        return out

    def _fail_point_reached(self):
        if self.fail_mode == "eproto_before":
            return self.state == "upload"
        if self.fail_mode in ("eproto_mid", "disconnect"):
            return self.state == "upload" and len(self.uploaded) >= UPLOAD_CHUNK
        if self.fail_mode == "eio":
            return self.state in ("upload", "firehose") and \
                len(self.uploaded) >= UPLOAD_CHUNK
        return False

    def host_write(self, data):
        if self._fail_point_reached():
            raise DeviceGoneError("mock %s (simulated usb error)" % self.fail_mode)
        self.buf += bytes(data)
        self._drain()

    # ------------------------------------------------------------- sahara
    # ------------------------------------------------------------- sahara
    def _drain(self):
        while True:
            if self.state in ("start", "command"):
                if len(self.buf) < 8:
                    return
                cmd, ln = struct.unpack_from("<II", self.buf, 0)
                if len(self.buf) < max(ln, 8):
                    return
                pkt, self.buf = self.buf[:ln], self.buf[ln:]
                self._sahara_pkt(cmd, pkt)
            elif self.state == "upload":
                if self.expect_raw is not None:
                    if len(self.buf) < self.expect_raw:
                        return
                    chunk, self.buf = self.buf[:self.expect_raw], \
                        self.buf[self.expect_raw:]
                    self.uploaded += chunk
                    self.expect_raw = None
                    self._request_chunk()
                else:
                    if len(self.buf) < 8:
                        return
                    cmd, ln = struct.unpack_from("<II", self.buf, 0)
                    if len(self.buf) < max(ln, 8):
                        return
                    pkt, self.buf = self.buf[:ln], self.buf[ln:]
                    self._sahara_pkt(cmd, pkt)
            elif self.state == "wait_done":
                if len(self.buf) < 8:
                    return
                cmd, ln = struct.unpack_from("<II", self.buf, 0)
                if len(self.buf) < max(ln, 8):
                    return
                pkt, self.buf = self.buf[:ln], self.buf[ln:]
                self._sahara_pkt(cmd, pkt)
            elif self.state == "program_payload":
                if self.pending_program is None:
                    self.state = "firehose"
                    continue
                self._drain_payload()
                return
            elif self.state == "firehose":
                self._firehose_drain()
                return
            elif self.state == "digest_wait":
                need = self.digest_len or len(self.digest_raw)
                if self.digest_len and len(self.buf) >= self.digest_len:
                    self.digest_raw, self.buf = self.buf[:self.digest_len], self.buf[self.digest_len:]
                    self._digest_received()
                return
            else:
                return

    def _sahara_pkt(self, cmd, pkt):
        if cmd == 2:  # HELLO_RSP
            mode = struct.unpack_from("<I", pkt, 20)[0]
            if mode == 3:
                self.state = "command"
                self._send(struct.pack("<II", 0x0B, 8))  # CMD_READY
            else:
                self.state = "upload"
                self._request_chunk()
        elif cmd == 0x0D:  # EXECUTE_REQ
            cid = struct.unpack_from("<I", pkt, 8)[0]
            if cid == 1:
                data = struct.pack("<I", reference.SERIAL)
            elif cid == 2:
                data = struct.pack("<IHH", reference.MSM_ID,
                                   reference.OEM_ID, reference.MODEL_ID)
            elif cid == 3:
                data = bytes.fromhex(reference.PK_HASH)
            elif cid == 7:
                data = struct.pack("<I", 0)
            else:
                data = b""
            self._send(struct.pack("<IIII", 0x0E, 0x10, cid, len(data)))
            if data:
                self._send(data)
        elif cmd == 5:  # DONE_REQ
            if self.state in ("upload", "wait_done"):
                self.state = "firehose"
                self._send(struct.pack("<III", 6, 0x0C, 1))  # DONE_RSP IMAGE_TX_COMPLETE
                self._xml_log("INFO: Waiting for firehose commands")
            else:
                self._send(struct.pack("<III", 6, 0x0C, 1))
        elif cmd == 7:  # RESET_REQ
            self._send(struct.pack("<II", 8, 8))
            self.state = "dead"
        elif cmd == 0x0C:  # SWITCH_MODE
            mode = struct.unpack_from("<I", pkt, 12)[0]
            if mode == 3:
                self.state = "command"
            else:
                self.state = "upload"
            self._send(struct.pack("<II", 0x0B, 8))  # CMD_READY
            if self.state == "upload":
                if self.hello_after_switch:
                    # fresh HELLO_REQ; the chunk request only comes after
                    # the host re-answers the handshake
                    self._queue_hello()
                else:
                    self._request_chunk()
        else:
            self._send(struct.pack("<IIII", 4, 0x10, 13, 1))  # invalid cmd

    def _request_chunk(self):
        if self.fail_mode in ("reject_loader", "reject_auth") and \
                len(self.uploaded) >= UPLOAD_CHUNK:
            status = 0x0D if self.fail_mode == "reject_loader" else 0x21
            self._send(struct.pack("<IIII", 4, 0x10, 13, status))
            self.state = "dead"
            return
        off = len(self.uploaded)
        if off >= 2 * UPLOAD_CHUNK:
            self._send(struct.pack("<IIII", 4, 0x10, 13, 0))  # END ok
            self.state = "wait_done"
            return
        self.expect_raw = UPLOAD_CHUNK
        if self.read64_len == 0x20:
            # variant used by bkerler/edl + QFirehose: image_id is u64
            self._send(struct.pack("<IIQQQ", 0x12, 0x20,
                                   reference.PROGRAMMER_IMAGE_ID,
                                   off, UPLOAD_CHUNK))
        elif self.read64_len == "bad":
            # deliberately unknown length: client must fail loudly
            self._send(struct.pack("<III", 0x12, 0x1D,
                                   reference.PROGRAMMER_IMAGE_ID) +
                       struct.pack("<QQ", off, UPLOAD_CHUNK)[:5] +
                       b"\x00" * 12)  # pad so the packet is complete (29B)
        else:
            self._send(struct.pack("<IIIQQ", 0x12, 0x1C,
                                   reference.PROGRAMMER_IMAGE_ID,
                                   off, UPLOAD_CHUNK))

    # ----------------------------------------------------------- firehose
    def _firehose_drain(self):
        while True:
            i = self.buf.find(b"</data>")
            if i < 0:
                return
            doc = self.buf[:i + len(b"</data>")]
            self.buf = self.buf[i + len(b"</data>"):]
            self._firehose_doc(doc)

    def _doc_ok(self, doc):
        if self.vip_bad:
            return False
        if not (self.vip_required and self.vip_active):
            return True
        h = hashlib.sha256(doc).hexdigest()
        return h in self.allowed_hashes

    def _firehose_doc(self, doc):
        text = doc.decode(errors="replace")
        m = re.search(r"<data>(.*)</data>", text, re.S)
        inner = m.group(1) if m else text

        if '<verify value="ping" EnableVip="1"' in inner:
            if not self._doc_ok(doc):
                self._nak_hash(doc)
                return
            self._ack()
            n = self.digest_len
            if n is None:
                n = 27700
            self._xml_log("INFO: VIP is enabled, receiving the partition "
                          "info of size %d" % n)
            self.state = "digest_wait"
            self.digest_len = n
            return

        if not self._doc_ok(doc):
            self._nak_hash(doc)
            return

        if "<configure" in inner:
            # real firehose emits INFO logs BEFORE the ACK response
            self._xml_log("INFO: Supported Functions: configure, program, "
                          "erase, read, getstorageinfo, power, peek, poke, "
                          "ufs, setbootablestoragedrive")
            self._ack()
            return
        if "<getstorageinfo" in inner:
            self._xml_log("INFO: StorageType = UFS")
            self._xml_log("INFO: TotalBlocks = 16384")
            self._xml_log("INFO: BlockSize = %d" % SECTOR)
            self._xml_log("INFO: MaxTransferSize = 1048576")
            self._ack()
            return
        if "<read" in inner:
            self._read_cmd(inner)
            return
        if "<program" in inner:
            self._program_cmd(inner)
            return
        if "<erase" in inner:
            mm = re.search(r'physical_partition_number="(\d+)"\s*'
                           r'start_sector="(\d+)"\s*'
                           r'num_partition_sectors="(\d+)"', inner) or \
                 re.search(r'start_sector="(\d+)"[^/]*'
                           r'physical_partition_number="(\d+)"', inner)
            self._ack()
            return
        if "<power" in inner:
            self._ack()
            self._xml_log("INFO: Powering off")
            self.state = "dead"
            self.reset_seen = True
            return
        if "<peek" in inner or "<poke" in inner:
            self._ack()
            return
        self._ack()

    def _nak_hash(self, doc):
        h = hashlib.sha256(doc).hexdigest()
        exp = self.allowed_hashes[0] if self.allowed_hashes else ("0" * 64)
        self._xml_log("ERROR: Hash value mismatch. Rejecting this packet. "
                      "Expected: %s  Found instead: %s" % (exp, h))
        self._ack(ok=False)

    def _read_cmd(self, inner):
        ss = int(re.search(r'SECTOR_SIZE_IN_BYTES="(\d+)"', inner).group(1))
        cnt = int(re.search(r'sector_count="(\d+)"', inner).group(1))
        start = int(re.search(r'start_sector="(\d+)"', inner).group(1))
        lun = int(re.search(r'physical_partition_number="(\d+)"', inner).group(1))
        st = self.storage.get(lun)
        if st is None or (start + cnt) * ss > len(st):
            self._xml_log("ERROR: Invalid start sector or partition number")
            self._ack(ok=False)
            return
        self._send(bytes(st[start * ss:(start + cnt) * ss]))
        self._ack()

    def _program_cmd(self, inner):
        ss = int(re.search(r'SECTOR_SIZE_IN_BYTES="(\d+)"', inner).group(1))
        cnt = int(re.search(r'num_partition_sectors="(\d+)"', inner).group(1))
        start = int(re.search(r'start_sector="(\d+)"', inner).group(1))
        lun = int(re.search(r'physical_partition_number="(\d+)"', inner).group(1))
        self.pending_program = (lun, start, cnt, ss)
        self.state = "program_payload"
        self._ack()

    def _drain_payload(self):
        """Consume the raw payload queued by a <program> command."""
        lun, start, cnt, ss = self.pending_program
        need = cnt * ss
        if len(self.buf) < need:
            return
        data, self.buf = self.buf[:need], self.buf[need:]
        st = self.storage.get(lun)
        st[start * ss:(start + cnt) * ss] = data
        self.pending_program = None
        self.state = "firehose"
        self._ack()

    # ------------------------------------------------------------- digest
    def _digest_received(self):
        self.state = "firehose"
        try:
            d = oplus.parse_digest(self.digest_raw)
            self.allowed_hashes = [e.sha256 for e in d["entries"] if e.sha256 != "0" * 64]
        except Exception:
            self.allowed_hashes = []
            self.vip_bad = True
            self._xml_log("ERROR: bad digest table")
            return
        self.vip_active = True
        self._xml_log("INFO: VIP table accepted (%d entries)" %
                      len(self.allowed_hashes))
