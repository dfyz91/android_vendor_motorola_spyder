"""A/B bootloader control block, stored in the `misc` partition at offset
2048 (the standard Android A/B bootloader_control / boot_control HAL v1
struct, also used by bkerler/edl for setslot).

Layout (bootloader_control, 52 bytes):
  char     slot_suffix[32]                                  @0
  uint8_t  magic[4] = 'B','O','O','T'                        @32
  uint8_t  version                                          @36
  uint8_t  nb_slot (active slot index on many OEMs)         @37
  uint8_t  recovery_trying                                  @38
  uint8_t  merge_status                                     @39
  struct { uint8 priority, tries_remaining,
           successful_boot, verity_corrupted } slot_info[2] @40
  uint32_t crc32_le (IEEE, over bytes 0..47)                 @48
"""
import struct
import zlib

MAGIC = b"BOOT"
OFFSET_IN_MISC = 2048


class BootControlError(Exception):
    pass


def parse_bootctl(misc_bytes):
    data = misc_bytes[OFFSET_IN_MISC:OFFSET_IN_MISC + 52]
    if len(data) < 52:
        raise BootControlError("misc slice too short")
    suffix = data[0:32].split(b"\x00")[0].decode(errors="replace")
    magic = data[32:36]
    if magic != MAGIC:
        raise BootControlError("bad magic %r (no bootloader_control at 2048?)" % magic)
    version, nb_slot, recovery_trying, merge_status = struct.unpack_from("<BBBB", data, 36)
    slots = []
    for i in range(2):
        prio, tries, ok, verity = struct.unpack_from("<BBBB", data, 40 + i * 4)
        slots.append({"priority": prio, "tries_remaining": tries,
                      "successful_boot": ok, "verity_corrupted": verity})
    crc, = struct.unpack_from("<I", data, 48)
    calc = zlib.crc32(data[:48]) & 0xFFFFFFFF
    return {"slot_suffix": suffix, "magic": magic, "version": version,
            "nb_slot": nb_slot, "recovery_trying": recovery_trying,
            "merge_status": merge_status, "slots": slots,
            "crc": crc, "crc_calc": calc, "crc_ok": crc == calc,
            "raw": data.hex()}


def active_slot(bc):
    """Best-effort active slot detection: suffix first, then priorities."""
    if bc["slot_suffix"] in ("_a", "a"):
        return "a"
    if bc["slot_suffix"] in ("_b", "b"):
        return "b"
    pa, pb = bc["slots"][0]["priority"], bc["slots"][1]["priority"]
    if pa != pb:
        return "a" if pa > pb else "b"
    return None


def set_active_slot(misc_bytes, slot, dry_run=False):
    """Return a new misc image with the given slot made active.
    Sets: suffix '_a'/'_b', active slot priority 15 / other 0,
    successful_boot cleared, tries_remaining 7, CRC recomputed."""
    if slot not in ("a", "b"):
        raise BootControlError("slot must be a or b")
    buf = bytearray(misc_bytes)
    d = buf[OFFSET_IN_MISC:OFFSET_IN_MISC + 52]
    if len(d) < 52:
        raise BootControlError("misc too short")
    if bytes(d[32:36]) != MAGIC:
        raise BootControlError("bad magic - refusing")
    # slot_suffix
    buf[OFFSET_IN_MISC:OFFSET_IN_MISC + 32] = b"\x00" * 32
    buf[OFFSET_IN_MISC:OFFSET_IN_MISC + 2] = ("_" + slot).encode()
    # priorities
    idx = 0 if slot == "a" else 1
    for i in range(2):
        base = OFFSET_IN_MISC + 40 + i * 4
        prio = 15 if i == idx else 0
        tries = 7 if i == idx else 0
        ok = 0
        ver = buf[base + 3]  # keep verity_corrupted
        buf[base:base + 4] = bytes([prio, tries, ok, ver])
    # nb_slot: on many OEMs this byte holds the active slot index (NOT VERIFIED
    # for MT2110; keep original value unless it looks like 0/1)
    if buf[OFFSET_IN_MISC + 37] in (0, 1):
        buf[OFFSET_IN_MISC + 37] = idx
    # crc
    crc = zlib.crc32(bytes(buf[OFFSET_IN_MISC:OFFSET_IN_MISC + 48])) & 0xFFFFFFFF
    struct.pack_into("<I", buf, OFFSET_IN_MISC + 48, crc)
    return bytes(buf)


def format_bootctl(bc):
    act = active_slot(bc)
    lines = ["bootloader_control @misc+2048:",
          "  magic          : %s" % bc["magic"],
          "  version        : %d" % bc["version"],
          "  slot_suffix    : %r" % bc["slot_suffix"],
          "  nb_slot        : %d%s" % (bc["nb_slot"], " (active-slot byte?)" if bc["nb_slot"] in (0, 1) else ""),
          "  crc            : 0x%08x (calc 0x%08x, %s)" % (bc["crc"], bc["crc_calc"], "OK" if bc["crc_ok"] else "MISMATCH"),
          "  active slot    : %s" % act]
    for i, s in enumerate(bc["slots"]):
        lines.append("  slot %s: priority=%d tries=%d successful=%d verity_corrupted=%d"
                     % ("ab"[i], s["priority"], s["tries_remaining"],
                        s["successful_boot"], s["verity_corrupted"]))
    return "\n".join(lines)
