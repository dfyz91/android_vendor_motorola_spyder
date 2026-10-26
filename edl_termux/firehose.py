"""Firehose XML protocol client.

Wire format: XML documents over the same bulk endpoints. The host appends a
zero-length packet when a raw payload write is a multiple of the USB maxpacket
(512). The device answers every command with `response value="ACK|NAK"` and
may emit `log value="..."` lines.

All reads go through a persistent RX buffer so that several packets
delivered inside one USB bulk read are not lost (this is a real-world case
and also bit the original QDL-style clients).

OPLUS VIP notes (from public logs in bkerler/edl issue #439 and the
OplusEdlTool flow):
 - host sends <verify value="ping" EnableVip="1"/>
 - loader logs: "VIP is enabled, receiving the partition info of size N"
 - the host then writes the SIGNED DIGEST TABLE as raw bytes on the OUT ep
 - afterwards EVERY firehose command must match a sha256 from the table;
   mismatched commands get:  ERROR: Hash value mismatch. Rejecting this
   packet. Expected: <sha256>  Found instead: <sha256> ... response NAK
This client exposes that oracle via the parsed log lines, and `vip-probe`
in the CLI uses it to discover the exact accepted command strings.
"""
import hashlib
import re
import time

XML_HDR = '<?xml version="1.0" encoding="UTF-8" ?>'


def xml_cmd(inner):
    return ("%s<data>%s</data>" % (XML_HDR, inner)).encode()


class FirehoseError(Exception):
    pass


class FirehoseClient:
    def __init__(self, transport, log=None, verbose=True):
        self.tr = transport
        self.log = log
        self.verbose = verbose
        self.supported_functions = []
        self.logs = []
        self.vip_enabled = False
        self.expected_hashes = []     # sha256 hex expected by VIP table
        self.found_hashes = []
        self._rxbuf = b""

    # ---------------------------------------------------------------- io
    def _handle_doc(self, doc):
        text = doc.decode(errors="replace")
        self._pkt("RX", doc)
        for m in re.finditer(r'<log value="([^"]*)"\s*/>', text):
            val = m.group(1)
            self.logs.append(val)
            if self.log:
                self.log.info("FH log: %s" % val)
            if "VIP is enabled" in val:
                self.vip_enabled = True
            em = re.match(r"Expected:\s*([0-9A-Fa-f]+)", val)
            if em:
                self.expected_hashes.append(em.group(1).lower())
            fm = re.match(r"Found instead:\s*([0-9A-Fa-f]+)", val)
            if fm:
                self.found_hashes.append(fm.group(1).lower())

    def _pkt(self, d, data, note=""):
        if self.log:
            self.log.pkt(d, data, note)

    def send_raw(self, data):
        """Raw OUT write (used for the VIP digest table)."""
        self._pkt("TX", data, "raw (%d bytes)" % len(data))
        return self.tr.write_zlp_if_needed(data)

    def _next_doc(self, timeout=15000):
        """Return the next complete XML document from the RX buffer."""
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout / 1000.0:
            start = self._rxbuf.find(b"<?xml")
            end = self._rxbuf.find(b"</data>", start if start >= 0 else 0)
            if start >= 0 and end >= 0:
                doc = self._rxbuf[start:end + len(b"</data>")]
                self._rxbuf = self._rxbuf[end + len(b"</data>"):]
                return doc
            data = self.tr.read(0x1000)
            if data:
                self._rxbuf += data
        raise FirehoseError("timeout waiting for XML document")

    def cmd(self, inner, timeout=15000):
        """Send one XML command; return (ack_value, raw)."""
        doc = xml_cmd(inner)
        self._pkt("TX", doc, inner[:80])
        self.tr.write_zlp_if_needed(doc)
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout / 1000.0:
            try:
                doc2 = self._next_doc(timeout)
            except FirehoseError:
                raise FirehoseError("timeout waiting for ACK after: %s"
                                   % inner[:80])
            self._handle_doc(doc2)
            m = re.search(r'<response value="(ACK|NAK)"([^/]*)/>',
                          doc2.decode(errors="replace"))
            if m:
                return m.group(1), m.group(2)
        raise FirehoseError("timeout waiting for ACK after: %s" % inner[:80])

    # ------------------------------------------------------------ commands
    def configure(self, memory="UFS", max_payload=1048576, skip_write=0):
        inner = ('<configure MemoryName="%s" Verbose="0" AlwaysValidate="0" '
                 'MaxDigestTableSizeInBytes="8192" '
                 'MaxPayloadSizeToTargetInBytes="%d" ZLPAwareHost="1" '
                 'SkipStorageInit="0" SkipWrite="%d"/>'
                 % (memory, max_payload, skip_write))
        ack, raw = self.cmd(inner)
        if ack != "ACK":
            raise FirehoseError("configure NAK (VIP? run loader with "
                                "--digest, or vip-probe)")
        for v in self.logs:
            m = re.search(r"Supported Functions:\s*(.+)", v)
            if m:
                self.supported_functions = [x.strip() for x in
                                           m.group(1).split(",") if x.strip()]
        return True

    def getstorageinfo(self):
        ack, raw = self.cmd('<getstorageinfo physical_partition_number="0"/>')
        info = {}
        for v in self.logs[-8:]:
            m = re.search(r"(TotalBlocks|BlockSize|MaxTransferSize|StorageType)"
                          r"\s*=\s*(\d+)", v)
            if m:
                info[m.group(1)] = int(m.group(2))
        return info

    def read_sectors(self, lun, start_sector, num_sectors, sector_size, out,
                     timeout=30000):
        """Raw sector read: <read .../> then num_sectors*sector_size raw
        bytes then an ACK. out: file-like writer.

        The device may NAK instead of sending data (invalid LUN/sector, VIP
        hash rejection): the first chunk is inspected - if it looks like an
        XML response we parse documents and raise with the NAK reason."""
        inner = ('<read SECTOR_SIZE_IN_BYTES="%d" sector_count="%d" '
                 'start_sector="%d" physical_partition_number="%d"/>'
                 % (sector_size, num_sectors, start_sector, lun))
        doc = xml_cmd(inner)
        self._pkt("TX", doc, inner)
        self.tr.write_zlp_if_needed(doc)
        total = num_sectors * sector_size
        remaining = total
        t0 = time.monotonic()
        while remaining > 0:
            if time.monotonic() - t0 > timeout / 1000.0:
                raise FirehoseError("timeout in raw read (%d/%d bytes)"
                                   % (total - remaining, total))
            data = self.tr.read(min(0x10000, remaining))
            if not data:
                continue
            if data[:5] == b"<?xml" and b"<response" in data[:400]:
                # NAK (or unexpected XML) instead of raw data
                self._rxbuf += data
                while remaining > 0:
                    try:
                        d2 = self._next_doc(timeout)
                    except FirehoseError:
                        raise FirehoseError("XML instead of raw data in read "
                                            "(timeout waiting for response)")
                    self._handle_doc(d2)
                    text = d2.decode(errors="replace")
                    if '"NAK"' in text:
                        raise FirehoseError("read NAK: %s" % text[-300:])
                    if '"ACK"' in text:
                        raise FirehoseError("device ACK'd without sending "
                                            "raw data (count mismatch?)")
                raise FirehoseError("read: unexpected XML stream")
            if len(data) > remaining:
                self._rxbuf += data[remaining:]
                data = data[:remaining]
            out.write(data)
            remaining -= len(data)
        # then the ACK
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout / 1000.0:
            try:
                doc2 = self._next_doc(timeout)
            except FirehoseError:
                raise FirehoseError("no ACK after read")
            self._handle_doc(doc2)
            text = doc2.decode(errors="replace")
            if '"ACK"' in text:
                return True
            if '"NAK"' in text:
                raise FirehoseError("read NAK: %s" % text[-300:])
        raise FirehoseError("no ACK after read")

    def program_sectors(self, lun, start_sector, data, sector_size,
                        sparse=False):
        if len(data) % sector_size:
            raise FirehoseError("program data not sector-aligned")
        num = len(data) // sector_size
        inner = ('<program SECTOR_SIZE_IN_BYTES="%d" file_sector_offset="0" '
                 'filename="raw.bin" label="edlt" num_partition_sectors="%d" '
                 'physical_partition_number="%d" start_sector="%d" '
                 'SparseFileScrolling="%s"/>'
                 % (sector_size, num, lun, start_sector,
                    "1" if sparse else "0"))
        ack, raw = self.cmd(inner)
        if ack != "ACK":
            raise FirehoseError("program NAK")
        sent = 0
        CH = 0x10000
        while sent < len(data):
            chunk = data[sent:sent + CH]
            self.tr.write_zlp_if_needed(chunk)
            sent += len(chunk)
        # final ACK
        t0 = time.monotonic()
        while time.monotonic() - t0 < 30.0:
            try:
                doc2 = self._next_doc(30000)
            except FirehoseError:
                raise FirehoseError("no final ACK after program payload")
            self._handle_doc(doc2)
            text = doc2.decode(errors="replace")
            if '"ACK"' in text:
                return True
            if '"NAK"' in text:
                raise FirehoseError("program payload NAK")
        raise FirehoseError("no final ACK after program payload")

    def erase(self, lun, start_sector, num_sectors):
        inner = ('<erase SECTOR_SIZE_IN_BYTES="4096" '
                 'num_partition_sectors="%d" physical_partition_number="%d" '
                 'start_sector="%d"/>' % (num_sectors, lun, start_sector))
        ack, raw = self.cmd(inner)
        if ack != "ACK":
            raise FirehoseError("erase NAK")
        return True

    def peek(self, addr, size):
        ack, raw = self.cmd('<peek address="0x%x" size="0x%x"/>'
                            % (addr, size))
        if ack != "ACK":
            raise FirehoseError("peek NAK")
        data = b""
        while len(data) < size:
            d = self.tr.read(size - len(data))
            if d:
                data += d
        return data

    def poke(self, addr, data):
        ack, raw = self.cmd('<poke address="0x%x" size="0x%x"/>'
                            % (addr, len(data)))
        if ack != "ACK":
            raise FirehoseError("poke NAK")
        self.tr.write_zlp_if_needed(data)
        return True

    def reset(self, mode="reset"):
        inner = '<power ResetType="%s"/>' % mode
        try:
            ack, raw = self.cmd(inner)
        except Exception:
            pass
        return True

    # --------------------------------------------------------------- VIP
    def vip_enable(self, digest_bytes, sign_bytes=None, timeout=15000):
        """OPLUS VIP activation, as reconstructed from the OplusEdlTool flow
        (QSaharaServer -> fh_loader --signeddigests --testvipimpact) and
        public logs (bkerler/edl issue #439):

          1. <verify value="ping" EnableVip="1"/>
          2. loader logs: "VIP is enabled, receiving the partition info
             of size N"
          3. host sends the N raw digest-table bytes
          4. afterwards every command XML must hash-match the table

        UNVERIFIED detail kept configurable: some flows also append the
        sign blob (e.g. Chimera_Sign.bin). Try digest-only first.
        """
        ack, raw = self.cmd('<verify value="ping" EnableVip="1"/>',
                            timeout=timeout)
        if ack != "ACK":
            raise FirehoseError("verify ping NAK - loader may not support VIP")
        want = None
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout / 1000.0:
            for v in self.logs[-6:]:
                m = re.search(r"receiving the partition info of size (\d+)", v)
                if m:
                    want = int(m.group(1))
                    break
            if want is not None or self.vip_enabled:
                break
            try:
                self._handle_doc(self._next_doc(timeout))
            except FirehoseError:
                break
        if want is None:
            if self.log:
                self.log.warn("no 'receiving the partition info' log seen")
        elif want != len(digest_bytes):
            if self.log:
                self.log.warn("loader expects %d digest bytes, table has %d - "
                              "sending anyway" % (want, len(digest_bytes)))
        self.send_raw(digest_bytes)
        if sign_bytes:
            self.send_raw(sign_bytes)
        self.vip_enabled = True
        return True

    def vip_probe_configure(self, memory="UFS"):
        """Use the loader's hash-mismatch oracle to find the exact configure
        string accepted by its VIP table. Returns a list of candidate hits."""
        order1 = ["MemoryName", "Verbose", "AlwaysValidate",
                  "MaxDigestTableSizeInBytes", "MaxPayloadSizeToTargetInBytes",
                  "ZLPAwareHost", "SkipStorageInit", "SkipWrite"]
        order2 = ["MemoryName", "Verbose", "AlwaysValidate",
                  "MaxDigestTableSizeInBytes", "MaxPayloadSizeToTargetInBytes",
                  "ZLPAwareHost", "SkipStorageInit"]
        base = {
            "MemoryName": memory, "Verbose": "0", "AlwaysValidate": "0",
            "MaxDigestTableSizeInBytes": "8192",
            "MaxPayloadSizeToTargetInBytes": "1048576",
            "ZLPAwareHost": "1", "SkipStorageInit": "0", "SkipWrite": "0",
        }
        variants = []
        for order in (order1, order2):
            inner = "<configure " + " ".join(
                '%s="%s"' % (k, base[k]) for k in order) + "/>"
            variants.append(inner)
        hits = []
        for inner in variants:
            try:
                ack, raw = self.cmd(inner)
                if ack == "ACK":
                    hits.append(inner)
                    return hits
            except FirehoseError:
                pass
            if self.log:
                self.log.info("probe NAK; expected=%s found=%s (hash oracle)"
                              % (self.expected_hashes[-1:],
                                 self.found_hashes[-1:]))
        return hits
