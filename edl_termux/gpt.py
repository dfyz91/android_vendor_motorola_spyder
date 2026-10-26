"""EFI GPT parsing (UFS multi-LUN aware, 4096-byte sectors)."""
import struct
import zlib

SECTOR = 4096
GPT_SIG = b"EFI PART"


def parse_header(data):
    """data: one sector containing the GPT header (LBA 1 of a LUN)."""
    if len(data) < 92:
        raise ValueError("GPT header data too short")
    if data[:8] != GPT_SIG:
        raise ValueError("bad GPT signature: %r" % data[:8])
    _rev, _hs, crc, _res, my_lba, alt_lba, first_usable, last_usable = struct.unpack_from("<IIIIQQQQ", data, 8)
    # UEFI spec: header CRC32 is computed over bytes 0..91 with the CRC
    # field itself zeroed. A mismatch means the table is damaged - the
    # write path refuses to use such a GPT (see cli.write_guards).
    scratch = bytearray(data[:92])
    scratch[16:20] = b"\x00" * 4
    crc_ok = (zlib.crc32(bytes(scratch)) & 0xFFFFFFFF) == crc
    disk_guid = data[56:72]
    entries_lba, nentries, esize, ecrc = struct.unpack_from("<QIII", data, 72)
    return {"crc": crc, "crc_ok": crc_ok, "my_lba": my_lba, "alt_lba": alt_lba,
            "first_usable": first_usable, "last_usable": last_usable,
            "disk_guid": disk_guid.hex(), "entries_lba": entries_lba,
            "num_entries": nentries, "entry_size": esize, "entries_crc": ecrc}


def parse_entries(data, nentries, esize):
    parts = []
    for i in range(nentries):
        e = data[i * esize:(i + 1) * esize]
        if len(e) < 128:
            break
        if e[:16] == b"\x00" * 16:
            continue  # unused entry
        first, last, attrs = struct.unpack_from("<QQQ", e, 32)
        name = e[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
        parts.append({"index": i, "type_guid": e[:16].hex(), "unique_guid": e[16:32].hex(),
                      "first_lba": first, "last_lba": last,
                      "sectors": last - first + 1 if last >= first else 0,
                      "attrs": attrs, "name": name})
    return parts


class Gpt:
    """Parsed GPT of one LUN."""

    def __init__(self, header, parts):
        self.header = header
        self.parts = parts
        # True when BOTH the header CRC and the entries-array CRC of this
        # LUN verified (set by read_gpt_from_firehose; None = unchecked)
        self.crc_ok = header.get("crc_ok")

    def find(self, name):
        for p in self.parts:
            if p["name"].lower() == name.lower():
                return p
        return None

    def __repr__(self):
        return "Gpt(%d parts)" % len(self.parts)


class GptTable:
    """GPTs of all LUNs of a storage."""

    def __init__(self, sector_size=SECTOR):
        self.luns = {}
        self.sector_size = sector_size

    def add(self, lun, gpt):
        self.luns[lun] = gpt

    def find(self, name):
        """-> (lun, part) or None"""
        for lun in sorted(self.luns):
            p = self.luns[lun].find(name)
            if p:
                return lun, p
        return None

    def names(self):
        out = []
        for lun in sorted(self.luns):
            for p in self.luns[lun].parts:
                out.append((lun, p["name"], p["first_lba"], p["sectors"]))
        return out


def read_gpt_from_firehose(fh, luns=(0, 1, 2, 3, 4, 5, 6), sector_size=SECTOR, log=None):
    """Read the GPT of every LUN via firehose raw sector reads."""
    table = GptTable(sector_size)
    for lun in luns:
        import io
        buf = io.BytesIO()
        try:
            fh.read_sectors(lun, 1, 1, sector_size, buf)  # header at LBA1
        except Exception as e:
            if log:
                log.info("LUN %d: no GPT (%s)" % (lun, e))
            continue
        hdr = buf.getvalue()
        try:
            h = parse_header(hdr)
        except ValueError as e:
            if log:
                log.info("LUN %d: %s" % (lun, e))
            continue
        ent_bytes = h["num_entries"] * h["entry_size"]
        ent_start = h["entries_lba"]
        ent_sectors = (ent_bytes + sector_size - 1) // sector_size
        buf = io.BytesIO()
        fh.read_sectors(lun, ent_start, ent_sectors, sector_size, buf)
        ent_data = buf.getvalue()
        ecrc_ok = ((zlib.crc32(ent_data[:ent_bytes]) & 0xFFFFFFFF)
                   == h["entries_crc"])
        parts = parse_entries(ent_data, h["num_entries"], h["entry_size"])
        g = Gpt(h, parts)
        g.crc_ok = h["crc_ok"] and ecrc_ok
        table.add(lun, g)
        if log:
            log.info("LUN %d: %d partitions%s" %
                     (lun, len(parts),
                      "" if g.crc_ok else "  [WARN: GPT CRC MISMATCH]"))
    return table


# ------------------------------------------------------------------ builder
def build_gpt(parts, total_sectors=0x100000, sector_size=SECTOR, first_usable=34):
    """Build raw GPT bytes (header sector + entry sectors) for tests/mocks.
    parts: list of dicts {name, first_lba, sectors}. Returns (header_bytes,
    entries_bytes)."""
    nentries = 128
    esize = 128
    entries = b""
    used_end = first_usable
    for p in parts:
        e = bytearray(esize)
        e[0:16] = bytes.fromhex("a2a0d0eb" "e5b9" "3344" "87c0" "68b6b72699c7")  # Linux FS type guid (synthetic)
        e[16:32] = b"\x11" * 16
        struct.pack_into("<QQQ", e, 32, p["first_lba"], p["first_lba"] + p["sectors"] - 1, 0)
        nm = p["name"].encode("utf-16-le")
        e[56:56 + len(nm)] = nm
        entries += bytes(e)
        used_end = max(used_end, p["first_lba"] + p["sectors"])
    while len(entries) < nentries * esize:
        entries += b"\x00" * esize
    ent_sectors = len(entries) // sector_size
    hdr = bytearray(sector_size)
    hdr[0:8] = GPT_SIG
    struct.pack_into("<II", hdr, 8, 0x00010000, 92)  # revision 1.0, header size
    # crc @16 filled in below; reserved @20 stays 0
    struct.pack_into("<QQQQ", hdr, 24, 1, total_sectors - 1, first_usable,
                     total_sectors - first_usable - ent_sectors - 1)
    hdr[56:72] = b"\x22" * 16
    struct.pack_into("<QIII", hdr, 72, 2, nentries, esize, 0)
    struct.pack_into("<I", hdr, 16, zlib.crc32(bytes(hdr[:92])) & 0xFFFFFFFF)
    return bytes(hdr), entries
