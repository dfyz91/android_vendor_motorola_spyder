"""Sahara protocol (Qualcomm EDL), v1/v2, image + command modes.

Packet formats (public Sahara protocol, same as used by linux-msm/qdl and
bkerler/edl - reimplemented here from scratch):

  HELLO_REQ  (0x01, 0x30 bytes):  cmd, len, version, min_version,
                                  max_cmd_len, mode, reserved[6]*4
  HELLO_RSP  (0x02, 0x30 bytes): same shape
  READ_DATA  (0x03, 0x14): cmd, len, image_id, offset(u32), size(u32)
  READ_DATA_64 (0x12, 0x1C or 0x20): cmd, len, image_id(u32 or u64),
                                  offset(u64), size(u64); both variants
                                  exist in the wild (edl/QFirehose use
                                  u64 image_id, others u32) - the packet
                                  length field tells them apart
  END_IMAGE_TX (0x04, 0x10): cmd, len, image_id, status
  DONE_REQ (0x05, 0x08), DONE_RSP (0x06, 0x0C): cmd, len[, status]
  RESET_REQ (0x07, 0x08), RESET_RSP (0x08, 0x08)
  CMD_READY (0x0B, 0x08)
  SWITCH_MODE (0x0C, 0x10): cmd, len, reserved, mode
  EXECUTE_REQ (0x0D, 0x0C): cmd, len, client_cmd_id
  EXECUTE_RSP (0x0E, 0x10): cmd, len, client_cmd_id, response_len
  EXECUTE_DATA (0x0F): raw data
"""
import struct

HELLO_LEN = 0x30

CMD_HELLO_REQ = 0x01
CMD_HELLO_RSP = 0x02
CMD_READ_DATA = 0x03
CMD_END_TRANSFER = 0x04
CMD_DONE_REQ = 0x05
CMD_DONE_RSP = 0x06
CMD_RESET_REQ = 0x07
CMD_RESET_RSP = 0x08
CMD_CMD_READY = 0x0B
CMD_SWITCH_MODE = 0x0C
CMD_EXECUTE_REQ = 0x0D
CMD_EXECUTE_RSP = 0x0E
CMD_EXECUTE_DATA = 0x0F
CMD_READ_DATA_64 = 0x12

MODE_IMAGE_TX_PENDING = 0
MODE_IMAGE_TX_COMPLETE = 1
MODE_MEMORY_DEBUG = 2
MODE_COMMAND = 3

EXEC_SERIAL_NUM_READ = 0x01
EXEC_MSM_HW_ID_READ = 0x02
EXEC_OEM_PK_HASH_READ = 0x03
EXEC_GET_SOFTWARE_VERSION_SBL = 0x07
EXEC_GET_TRAINING_DATA = 0x09
EXEC_READ_CHIP_ID_V3 = 0x0A

STATUS_NAMES = {
    0x00: "SUCCESS",
    0x01: "NAK_INVALID_CMD",
    0x02: "NAK_PROTOCOL_MISMATCH",
    0x03: "NAK_INVALID_TARGET_PROTOCOL",
    0x04: "NAK_INVALID_HOST_PROTOCOL",
    0x05: "NAK_INVALID_PACKET_SIZE",
    0x06: "NAK_UNEXPECTED_IMAGE_ID",
    0x07: "NAK_INVALID_HEADER_SIZE",
    0x08: "NAK_INVALID_DATA_SIZE",
    0x09: "NAK_INVALID_IMAGE_TYPE",
    0x0A: "NAK_INVALID_TX_LENGTH",
    0x0B: "NAK_INVALID_RX_LENGTH",
    0x0C: "NAK_GENERAL_TX_RX_ERROR",
    0x0D: "NAK_READ_DATA_ERROR",
    0x0E: "NAK_UNSUPPORTED_NUM_PHDRS",
    0x0F: "NAK_INVALID_PHDR_SIZE",
    0x10: "NAK_MULTIPLE_SHARED_ELF_SEG",
    0x11: "NAK_UNINIT_PHDR_LOC",
    0x12: "NAK_INVALID_DEST_ADDR",
    0x13: "NAK_INVALID_IMG_HDR_DATA_SIZE",
    0x14: "NAK_INVALID_ELF_HDR",
    0x15: "NAK_UNKNOWN_HOST_ERROR",
    0x16: "NAK_TIMEOUT_RX",
    0x17: "NAK_TIMEOUT_TX",
    0x18: "NAK_INVALID_HOST_MODE",
    0x19: "NAK_INVALID_MEMORY_READ",
    0x1A: "NAK_INVALID_DATA_SIZE_REQUEST",
    0x1B: "NAK_MEMORY_DEBUG_NOT_SUPPORTED",
    0x1C: "NAK_INVALID_MODE_SWITCH",
    0x1D: "NAK_INVALID_PARSER_ELFTYPE",
    0x1E: "NAK_INVALID_PARSER_PHASE",
    0x1F: "NAK_INVALID_IMG_HASH_TABLE",
    0x20: "NAK_INVALID_IMG_SECURITY_MODE",
    0x21: "NAK_TARGET_AUTH_FAILURE",
    0x22: "NAK_INVALID_NUM_HASH_ENTRIES",
    0x23: "NAK_HASH_VERIFY_ERROR",
    0x24: "NAK_AUTH_DAT_SEG_MISSING",
    0x25: "NAK_INVALID_SAU_SIZE",
    0x26: "NAK_FW_SIGNATURE_MISMATCH",
}

OEM_NAMES = {0x0051: "OPPO/OPLUS/OnePlus"}


class SaharaError(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


class SaharaPacket:
    def __init__(self, cmd, raw):
        self.cmd = cmd
        self.raw = raw


def parse_hello(raw):
    if len(raw) < 0x28:
        raise SaharaError("HELLO too short (%d)" % len(raw))
    cmd, length, ver, minver, max_len, mode = struct.unpack_from("<IIIIII", raw, 0)
    return {"cmd": cmd, "len": length, "version": ver, "min_version": minver,
            "max_cmd_len": max_len, "mode": mode}


def build_hello_rsp(mode, version=2, min_version=1, max_cmd_len=0x200):
    """Build the standard 48-byte HELLO_RESPONSE.

    max_cmd_len remains in the signature for compatibility with older callers,
    but it is a HELLO_REQ field, not a HELLO_RESPONSE field.  The response
    fields after the header are version, compatible, status, mode, reserved[6].
    """
    try:
        version = int(version)
        if not 1 <= version <= 0xFFFFFFFF:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        version = 2

    try:
        min_version = int(min_version)
        if not 1 <= min_version <= version:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        min_version = 1

    mode = int(mode)
    return struct.pack(
        "<12I",
        CMD_HELLO_RSP, HELLO_LEN,
        version, min_version, 0, mode,
        0, 0, 0, 0, 0, 0,
    )


class SaharaClient:
    def __init__(self, transport, log=None, verbose=True):
        self.tr = transport
        self.log = log
        self.verbose = verbose
        self.bit64 = False
        self.hello = None
        self._rxbuf = b""

    # ------------------------------------------------------------------ io
    def _read_pkt(self, timeout=10000):
        """Read the next complete Sahara packet. USB bulk reads may coalesce
        several packets, so leftovers are kept in a buffer."""
        while True:
            if len(self._rxbuf) >= 8:
                cmd, length = struct.unpack_from("<II", self._rxbuf, 0)
                if length < 8 or length > 0x10000:
                    raise SaharaError("invalid Sahara packet length %d (cmd=0x%02x)" % (length, cmd))
                need = length
                if len(self._rxbuf) >= need:
                    raw = self._rxbuf[:need]
                    self._rxbuf = self._rxbuf[need:]
                    self._pkt("RX", raw, "cmd=0x%02x len=%d" % (cmd, length))
                    return cmd, length, raw
            data = self.tr.read(0x400, timeout)
            if not data:
                raise SaharaError("device sent no data (timeout)")
            if b"<?xml" in data[:16]:
                raise SaharaError("firehose XML while in sahara (device "
                                  "already running a programmer; skip loader)")
            self._rxbuf += data

    def _read_exact(self, n, timeout=10000):
        while len(self._rxbuf) < n:
            data = self.tr.read(n - len(self._rxbuf), timeout)
            if not data:
                raise SaharaError("device sent no data (timeout)")
            self._rxbuf += data
        out, self._rxbuf = self._rxbuf[:n], self._rxbuf[n:]
        return out

    def _pkt(self, d, data, note=""):
        if self.log:
            self.log.pkt(d, data, note)

    # --------------------------------------------------------------- hello
    def connect(self, want_mode=None):
        """Wait for HELLO_REQ and answer with HELLO_RSP.

        want_mode: None = echo device mode, else force mode (e.g. MODE_COMMAND).
        Returns parsed hello dict."""
        cmd, length, raw = self._read_pkt(timeout=15000)
        if cmd != CMD_HELLO_REQ:
            raise SaharaError("expected HELLO_REQ, got cmd=0x%02x" % cmd)
        hello = parse_hello(raw)
        self.hello = hello
        mode = hello["mode"] if want_mode is None else want_mode
        # Match upstream linux-msm/qdl: command-mode discovery selects the
        # device's advertised Sahara version; image transfer negotiates the
        # host's supported v2 protocol. Compatibility is 1 in both cases.
        rsp_version = hello["version"] if mode == MODE_COMMAND else 2
        rsp = build_hello_rsp(mode, version=rsp_version, min_version=1)
        if self.log:
            self.log.info(
                "HELLO_REQ: device_version=%s device_compat=%s max_cmd_len=0x%x "
                "device_mode=%s; HELLO_RSP: version=%s compat=1 status=0 mode=%s"
                % (hello["version"], hello["min_version"], hello["max_cmd_len"],
                   hello["mode"], rsp_version, mode)
            )
        self._pkt("TX", rsp, "HELLO_RSP mode=%d" % mode)
        self.tr.write(rsp)
        return hello

    # ------------------------------------------------------------ commands
    def cmd_ready(self):
        cmd, length, raw = self._read_pkt()
        if cmd != CMD_CMD_READY:
            raise SaharaError("expected CMD_READY, got 0x%02x" % cmd)
        return True

    def exec_cmd(self, client_cmd_id):
        req = struct.pack("<III", CMD_EXECUTE_REQ, 0x0C, client_cmd_id)
        self._pkt("TX", req, "EXECUTE_REQ 0x%x" % client_cmd_id)
        self.tr.write(req)
        cmd, length, raw = self._read_pkt()
        if cmd != CMD_EXECUTE_RSP:
            raise SaharaError("expected EXECUTE_RSP, got 0x%02x" % cmd)
        _c, _l, cid, rlen = struct.unpack_from("<IIII", raw, 0)
        if cid != client_cmd_id:
            raise SaharaError("EXECUTE_RSP client_cmd mismatch")
        if rlen == 0:
            return b""
        data = self._read_exact(rlen)
        self._pkt("RX", data, "EXECUTE_DATA (%d bytes)" % len(data))
        return data

    def switch_mode(self, mode):
        pkt = struct.pack("<IIII", CMD_SWITCH_MODE, 0x10, 0, mode)
        self._pkt("TX", pkt, "SWITCH_MODE %d" % mode)
        self.tr.write(pkt)
        return self.cmd_ready()

    # ------------------------------------------------------------- chipinfo
    def chipinfo(self):
        hello = self.connect(want_mode=MODE_COMMAND)
        self.cmd_ready()
        serial = self.exec_cmd(EXEC_SERIAL_NUM_READ)
        hwid = self.exec_cmd(EXEC_MSM_HW_ID_READ)
        pkhash = self.exec_cmd(EXEC_OEM_PK_HASH_READ)
        try:
            swver = self.exec_cmd(EXEC_GET_SOFTWARE_VERSION_SBL)
        except Exception:
            swver = b""
        msm_id = oem_id = model_id = None
        if len(hwid) >= 12:
            msm_id, oem_id, model_id = struct.unpack("<III", hwid[:12])
        elif len(hwid) >= 8:
            # 8-byte variant: MSM_ID u32, OEM_ID u16, MODEL_ID u16
            msm_id, oem_id, model_id = struct.unpack("<IHH", hwid[:8])
        info = {
            "sahara_version": hello["version"],
            "mode": hello["mode"],
            "serial": struct.unpack("<I", serial[:4])[0] if len(serial) >= 4 else None,
            "msm_id": msm_id,
            "oem_id": oem_id,
            "model_id": model_id,
            "oem_name": OEM_NAMES.get(oem_id, "unknown"),
            "pk_hash": pkhash.hex(),
            "sw_version": swver.hex() if swver else None,
            "hw_id": ("%08x%04x%04x" % (msm_id or 0, oem_id or 0, model_id or 0)
                      if msm_id is not None else None),        }
        return info

    # -------------------------------------------------------- image upload
    def _send_image_chunk(self, image, off, size, label):
        """Send exactly the range requested by the device, with diagnostics."""
        if off < 0 or size <= 0 or off > len(image) or size > len(image) - off:
            raise SaharaError(
                "%s request out of bounds: offset=0x%x size=0x%x image_size=0x%x"
                % (label, off, size, len(image))
            )
        chunk = image[off:off + size]
        self._pkt("TX", chunk, "%s off=0x%x requested=0x%x" % (label, off, size))
        written = self.tr.write(chunk)
        if written != size:
            raise SaharaError(
                "%s short USB write at offset=0x%x: requested=%d actual=%d"
                % (label, off, size, written)
            )
        if self.log:
            self.log.info(
                "%s TX complete: offset=0x%x requested=%d actual=%d next_offset=0x%x"
                % (label, off, size, written, off + written)
            )
        return written

    def upload_image(self, image, image_id=13, progress_cb=None,
                     need_connect=True):
        """Transfer a programmer. image: bytes. Returns after DONE_RSP.

        The device drives the transfer with READ_DATA / READ_DATA_64 requests.
        If the device rejects the image it sends END_IMAGE_TX with a NAK
        status - we raise SaharaError with that status so callers can tell a
        rejected loader apart from a transport failure (which surfaces as
        DeviceGoneError from the transport layer).
        need_connect=False: reuse an existing session (e.g. after
        switch_mode() from command mode; self.hello must already be set)."""
        if need_connect:
            hello = self.connect(want_mode=MODE_IMAGE_TX_PENDING)
            if hello["mode"] != MODE_IMAGE_TX_PENDING:
                raise SaharaError("device not in image-transfer mode (mode=%d)"
                                  % hello["mode"])
        elif self.hello is None:
            raise SaharaError("upload_image(need_connect=False) but no hello")
        sent = 0
        end_status = None
        while True:
            cmd, length, raw = self._read_pkt()
            if cmd == CMD_READ_DATA:
                self.bit64 = False
                _c, _l, img_id, off, size = struct.unpack_from("<IIIII", raw, 0)
                if img_id != image_id:
                    raise SaharaError("device asked for image_id=%d, we serve %d"
                                      % (img_id, image_id))
                sent += self._send_image_chunk(image, off, size, "READ_DATA")
                if progress_cb:
                    progress_cb(sent, len(image))
            elif cmd == CMD_READ_DATA_64:
                self.bit64 = True
                # Sources disagree on the image_id field width of the
                # 64-bit read-data request: bkerler/edl and Quectel
                # QFirehose parse a 64-bit image_id (packet len 0x20),
                # other implementations use a 32-bit image_id (len 0x1C).
                # The packet's own length field is authoritative - accept
                # both, fail loudly on anything else.
                if length == 0x1C:
                    _c, _l, img_id, off, size = struct.unpack_from("<IIIQQ", raw, 0)
                elif length == 0x20:
                    _c, _l, img_id, off, size = struct.unpack_from("<IIQQQ", raw, 0)
                else:
                    raise SaharaError("unexpected READ_DATA_64 packet length "
                                      "%d (neither 0x1C nor 0x20)" % length)
                if img_id != image_id:
                    raise SaharaError("device asked for image_id=%d, we serve %d"
                                      % (img_id, image_id))
                sent += self._send_image_chunk(image, off, size, "READ_DATA64")
                if progress_cb:
                    progress_cb(sent, len(image))
            elif cmd == CMD_HELLO_REQ:
                # Some PBLs send a fresh HELLO after SWITCH_MODE to image
                # mode instead of going straight to READ_DATA. Answer it
                # with image-transfer mode and continue.
                hello = parse_hello(raw)
                if self.log:
                    self.log.info(
                        "mid-upload HELLO_REQ: device_version=%s device_compat=%s "
                        "max_cmd_len=0x%x mode=%s"
                        % (hello["version"], hello["min_version"],
                           hello["max_cmd_len"], hello["mode"])
                    )
                # Same response policy as QDL's normal image-transfer path.
                rsp = build_hello_rsp(MODE_IMAGE_TX_PENDING, version=2,
                                      min_version=1)
                self._pkt("TX", rsp, "HELLO_RSP (mid-upload, mode=0)")
                self.tr.write(rsp)
            elif cmd == CMD_END_TRANSFER:
                _c, _l, img_id, status = struct.unpack_from("<IIII", raw, 0)
                end_status = status
                break
            else:
                raise SaharaError("unexpected packet cmd=0x%02x during upload" % cmd)
        if end_status is None or end_status != 0:
            name = STATUS_NAMES.get(end_status, "UNKNOWN(0x%02x)" % end_status)
            raise SaharaError("device REJECTED the image: END_IMAGE_TX status=0x%02x (%s)"
                              % (end_status, name), status=end_status)
        done = struct.pack("<II", CMD_DONE_REQ, 0x08)
        self._pkt("TX", done, "DONE_REQ")
        self.tr.write(done)
        cmd, length, raw = self._read_pkt()
        if cmd != CMD_DONE_RSP:
            raise SaharaError("expected DONE_RSP, got 0x%02x" % cmd)
        _c, _l, status = struct.unpack_from("<III", raw, 0)
        # Per Sahara/QDL: 0 means IMAGE_TX_PENDING (more images may follow),
        # 1 means IMAGE_TX_COMPLETE. Do not mistake pending for a successful
        # handoff to Firehose when this client only serves one image.
        if status == 0:
            raise SaharaError(
                "DONE_RSP status=0 (IMAGE_TX_PENDING): target may require another "
                "Sahara image; single-image loader handoff is not confirmed"
            )
        if status != 1:
            raise SaharaError("DONE_RSP invalid status=%s" % STATUS_NAMES.get(status, hex(status)))
        if self.log:
            self.log.info("DONE_RSP status=1 (IMAGE_TX_COMPLETE)")
        return True

    def reset(self):
        pkt = struct.pack("<II", CMD_RESET_REQ, 0x08)
        self._pkt("TX", pkt, "RESET_REQ")
        self.tr.write(pkt)
        try:
            cmd, length, raw = self._read_pkt()
        except Exception:
            pass
        return True
