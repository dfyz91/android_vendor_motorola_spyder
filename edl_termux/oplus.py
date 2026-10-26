"""OPLUS signed-digest ("VIP") table parsing.

Format per the public parser JacksonOnly/OplusDigestUtils
(github.com/JacksonOnly/OplusDigestUtils), OplusDigestReader.cs:
  - wrapper ELF: digest blob at offset 0xE8, length = u16 at 0x98
  - wrapper MBN: digest blob at offset 0xA8, length = u32 at 0x14
  - table header (32 bytes): magic u32@0 = 0x7CEF0312, version u32@4,
    header_size u32@8, partition_nums u32@12, partition_total_length u32@16,
    partition_length u32@20, reserved u64@24
  - entry (132 bytes): label[32]@0, filename[32]@0x20, allow_read u32@0x40,
    allow_write u32@0x44, start_sector u64@0x54, sectors u64@0x5C,
    sha256[32]@0x64
Offsets 0x48..0x53 are of unknown purpose (NOT VERIFIED).
"""
import struct

MAGIC = 0x7CEF0312


class DigestEntry:
    def __init__(self, label, filename, allow_read, allow_write,
                 start_sector, sectors, sha256):
        self.label = label
        self.filename = filename
        self.allow_read = allow_read
        self.allow_write = allow_write
        self.start_sector = start_sector
        self.sectors = sectors
        self.sha256 = sha256  # hex

    def __repr__(self):
        return "DigestEntry(%s, r=%d w=%d @%d+%d)" % (
            self.label, self.allow_read, self.allow_write,
            self.start_sector, self.sectors)


def extract_digest_blob(data):
    """Strip the ELF/MBN wrapper, return the raw digest table bytes."""
    data = bytes(data)
    if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == MAGIC:
        return data  # already a raw table
    if data[:4] == b"\x7fELF":
        ln, = struct.unpack_from("<H", data, 0x98)
        return data[0xE8:0xE8 + ln]
    if len(data) > 0xA8:
        ln, = struct.unpack_from("<I", data, 0x14)
        blob = data[0xA8:0xA8 + ln]
        if len(blob) == ln:
            return blob
    return data


def parse_digest(data):
    """data: raw digest table (or wrapper - auto-stripped)."""
    blob = extract_digest_blob(bytes(data))
    if len(blob) < 32:
        raise ValueError("digest too short")
    magic, version, header_size, nums, total_len, part_len = struct.unpack_from("<IIIIII", blob, 0)
    if magic != MAGIC:
        raise ValueError("bad digest magic 0x%08x (expected 0x%08x)" % (magic, MAGIC))
    entries = []
    entry_size = 132
    # try to auto-detect stride if 132 does not tile
    if header_size and nums and (len(blob) - header_size) % 132 != 0:
        for cand in (136, 128, 140):
            if (len(blob) - header_size) % cand == 0:
                entry_size = cand
                break
    for i in range(nums):
        off = header_size + i * entry_size
        if off + entry_size > len(blob):
            break
        label = blob[off:off + 32].split(b"\x00")[0].decode(errors="replace")
        fname = blob[off + 0x20:off + 0x40].split(b"\x00")[0].decode(errors="replace")
        ar, aw = struct.unpack_from("<II", blob, off + 0x40)
        ss, sc = struct.unpack_from("<QQ", blob, off + 0x54)
        sha = blob[off + 0x64:off + 0x84].hex()
        entries.append(DigestEntry(label, fname, ar, aw, ss, sc, sha))
    return {"version": version, "header_size": header_size,
            "partition_nums": nums, "total_length": total_len,
            "partition_length": part_len, "entries": entries, "raw_len": len(blob)}


def format_digest(d):
    lines = ["OPLUS digest table v%d, %d entries, blob %d bytes"
             % (d["version"], d["partition_nums"], d["raw_len"]),
             "label              allow_r allow_w  start_sector  sectors  sha256"]
    for e in d["entries"]:
        lines.append("%-18s %-7d %-7d %-13d %-9d %s" %
                     (e.label, e.allow_read, e.allow_write, e.start_sector,
                      e.sectors, e.sha256[:24] + "..."))
    return "\n".join(lines)


# ------------------------------------------------------------------ builder
def build_digest(entry_tuples, version=2, header_size=32):
    """Build a synthetic digest table for tests.
    entry_tuples: list of (label, filename, allow_read, allow_write,
    start_sector, sectors, sha256_hex)."""
    nums = len(entry_tuples)
    body = b""
    for (label, fname, ar, aw, ss, sc, sha) in entry_tuples:
        e = bytearray(132)
        e[0:len(label)] = label.encode()
        e[0x20:0x20 + len(fname)] = fname.encode()
        struct.pack_into("<II", e, 0x40, ar, aw)
        struct.pack_into("<QQ", e, 0x54, ss, sc)
        e[0x64:0x84] = bytes.fromhex(sha)
        body += bytes(e)
    hdr = struct.pack("<IIIIII", MAGIC, version, header_size, nums,
                     header_size + len(body), 132) + b"\x00" * 8
    return hdr + body
