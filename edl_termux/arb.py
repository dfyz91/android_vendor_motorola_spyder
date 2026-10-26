"""ARB (anti-rollback) inspection of on-device and stock images.

Reads the boot-chain partitions through firehose, parses each as a Qualcomm
signed image and compares image versions / rollback indices between slots
and against stock images supplied on disk.
"""
import hashlib
import os

from . import qcomimage
from . import reference


class ArbError(Exception):
    pass


def _read_partition(fh, table, name, log=None):
    f = table.find(name)
    if not f:
        raise ArbError("partition %s not found in GPT" % name)
    lun, part = f
    import io
    buf = io.BytesIO()
    fh.read_sectors(lun, part["first_lba"], part["sectors"],
                    table.sector_size, buf)
    data = buf.getvalue()
    # partition may be padded to block size; report size + sha256
    return {"name": name, "lun": lun, "first_lba": part["first_lba"],
            "sectors": part["sectors"], "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "data": data}


def inspect_partition(fh, table, name, log=None):
    r = _read_partition(fh, table, name, log)
    try:
        r["info"] = qcomimage.parse_image(r["data"])
    except Exception as e:
        r["info"] = None
        r["parse_error"] = str(e)
    r.pop("data")
    return r


def arb_report(fh, table, parts=reference.BOOT_CHAIN, stock_dir=None, log=None):
    """Read and analyze the boot chain. Returns report dict."""
    on_dev = []
    for p in parts:
        try:
            on_dev.append(inspect_partition(fh, table, p, log))
        except ArbError as e:
            on_dev.append({"name": p, "error": str(e)})
        except Exception as e:
            on_dev.append({"name": p, "error": "%s: %s" % (type(e).__name__, e)})

    stock = []
    if stock_dir:
        for fn in sorted(os.listdir(stock_dir)):
            path = os.path.join(stock_dir, fn)
            if not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                data = f.read()
            entry = {"file": fn, "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            try:
                entry["info"] = qcomimage.parse_image(data)
            except Exception as e:
                entry["info"] = None
                entry["parse_error"] = str(e)
            stock.append(entry)

    return {"partitions": on_dev, "stock": stock,
            "sector_size": table.sector_size}


def _arb(info):
    if info and isinstance(info, dict):
        return info.get("anti_rollback_version")
    return None


def _ver(info):
    if info and isinstance(info, dict):
        return info.get("sw_id")
    return None


def format_report(rep, pk_hash=None):
    L = []
    L.append("=" * 72)
    L.append("ARB report (boot chain, on-device)")
    L.append("=" * 72)
    for p in rep["partitions"]:
        if "error" in p:
            L.append("%-16s ERROR: %s" % (p["name"], p["error"]))
            continue
        L.append("%-16s lun%d @LBA %d (%d sectors, %d bytes)" %
                 (p["name"], p["lun"], p["first_lba"], p["sectors"], p["size"]))
        L.append("                 sha256 %s" % p["sha256"])
        if p.get("parse_error"):
            L.append("                 parse: FAILED (%s)" % p["parse_error"])
        info = p.get("info")
        if info:
            L.append("                 MBN v%d image_id=%d sw_id=%s oem_id=%s model_id=%s" %
                     (info.get("version") or -1, info.get("image_id") or -1,
                      hex(info.get("sw_id") or 0), hex(info.get("oem_id") or 0),
                      hex(info.get("model_id") or 0)))
            arb = info.get("anti_rollback_version")
            note = info.get("anti_rollback_note") or ""
            L.append("                 ARB = %s   (%s)" % (arb, note))
            if pk_hash:
                m = qcomimage.match_pk_hash(info, pk_hash)
                L.append("                 PK hash cert match: %s" % (m if m else "none"))
    # slot comparison
    pairs = {}
    for p in rep["partitions"]:
        name = p["name"]
        # strict _a/_b suffix matching - rstrip("_ab") would mangle any
        # name that merely ends in 'a' or 'b' (e.g. "metadata")
        if len(name) > 2 and name.endswith(("_a", "_b")):
            base, slot = name[:-2], name[-1]
            pairs.setdefault(base, {})[slot] = p
    L.append("-" * 72)
    for base, slots in sorted(pairs.items()):
        a, b = slots.get("a"), slots.get("b")
        if not a or not b:
            continue
        aa, ba = _arb(a.get("info")), _arb(b.get("info"))
        if aa is not None and ba is not None and aa != ba:
            L.append("! %-14s slots DIFFER: ARB a=%s b=%s" % (base, aa, ba))
        elif aa is not None:
            L.append("  %-14s slots same: ARB a=b=%s" % (base, aa))
    L.append("-" * 72)
    L.append("NOTE: fuse/RPMB rollback index is NOT readable via EDL.")
    L.append("      A lower-ARB image may be rejected even if both slots")
    L.append("      contain it, because the burned fuse value is unknown.")
    if rep["stock"]:
        L.append("-" * 72)
        L.append("Stock images in --stock-dir:")
        for s in rep["stock"]:
            L.append("  %-24s %8d bytes  ARB=%s" %
                     (s["file"], s["size"], _arb(s.get("info"))))
    return "\n".join(L)


def check_write_image(part_name, image_info, current_info=None,
                      allow_rollback=False):
    """Safety gate for writing ARB-critical partitions.
    Returns list of problems (empty = allowed)."""
    for prefix in reference.ARB_CRITICAL:
        if part_name == prefix or part_name.startswith(prefix + "_"):
            break
    else:
        return []  # not ARB-critical
    img_arb = image_info.get("anti_rollback_version") if image_info else None
    if img_arb is None:
        return ["image is ARB-critical but its rollback index could not be "
                "parsed (unknown header version or corrupt image); refusing. "
                "Use image-info on the file and proceed manually if certain."]
    problems = []
    cur_arb = None
    if current_info:
        cur_arb = (current_info.get("anti_rollback_version")
                   if isinstance(current_info, dict) else current_info)
    if cur_arb is not None and img_arb < cur_arb and not allow_rollback:
        problems.append(
            "image ARB %d < on-device ARB %d: rollback images are rejected by "
            "the device once the fuse is burned; refusing (override with "
            "--allow-rollback-image only if you KNOW the fuse is not raised)"
            % (img_arb, cur_arb))
    return problems
