"""Qualcomm signed image (MBN v3/v4/v5/v6/v7 inside an ELF) static parser.

Extracts: header version, image_id, OEM metadata (sw_id/hw_id/oem_id/
model_id/soc_hw_version/anti_rollback_version) and the certificate chain,
then computes SHA-256/384/512 candidates for matching against the Sahara
OEM PK hash.

Header layouts follow the public parser JacksonOnly/QualcommImageUtils
(github.com/JacksonOnly/QualcommImageUtils), HashSegmentReader.cs, as
re-derived in research for this project:
  common:  u16 md_size@0, u16 version@2, u32 image_id@4
  v6:      header 48 bytes; sizes at 16 (qti sig), 20 (qti cert),
           24 (hash table), 28 (total); QTI meta size@40, OEM meta size@44.
           After the header: QTI meta, OEM meta (120 bytes:
           sw_id@+8, hw_id@+12, oem_id@+16, model_id@+20,
           soc_hw_version@+32, oem_root_cert_slot@+112,
           anti_rollback_version@+116), hash table (SHA-384 entries), sigs.
  v7:      header 40 bytes; size fields commonMeta@8, qtiMeta@12, oemMeta@16,
           hash@20, qtiSig@24, qtiCert@28, oemSig@32, oemCert@36.
           v7 OEM-meta ARB offset: NOT VERIFIED - we dump the raw OEM meta.

Cert-chain boundaries are not trusted from header size fields alone: the
whole hash segment is scanned for DER certificates, which is robust.

The Sahara PK hash of this target is 48 bytes = SHA-384 (see README), so all
of sha256/384/512 are computed over several candidate byte ranges (whole
cert DER, SubjectPublicKeyInfo DER, raw RSA modulus). Offsets marked
NOT VERIFIED must be treated as best-effort.
"""
import hashlib
import struct

SEG_FLAG_HASH = 2  # segment type in p_flags: bits 27..24 or bits 31..30 == 2


def _find_elf_hash_segment(data):
    if data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    if is64:
        e_phoff, = struct.unpack_from("<Q", data, 0x20)
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
        segs = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_flags = struct.unpack_from("<II", data, off)
            p_offset, _, _, p_filesz = struct.unpack_from("<QQQQ", data, off + 8)
            segs.append((p_offset, p_filesz, p_flags))
        for off, size, flags in segs:
            # Check Qualcomm hash segment flag in both 2-bit top layout ((flags >> 30) & 0x3)
            # and 4-bit segment-type field ((flags >> 24) & 0x0F)
            if ((flags & 0xC0000000) >> 30 == SEG_FLAG_HASH) or (((flags >> 24) & 0x0F) == SEG_FLAG_HASH):
                return off, size
    return None


# ------------------------------------------------------------------ mini DER
def _der_read_tlv(data, pos):
    if pos >= len(data):
        return None
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        return None  # multi-byte tags unsupported (not used in X.509)
    p = pos + 1
    if p >= len(data):
        return None
    b = data[p]
    if b < 0x80:
        ln = b
        p += 1
    elif b == 0x80:
        return None  # indefinite
    else:
        n = b & 0x7F
        if n > 4 or p + n > len(data):
            return None
        ln = int.from_bytes(data[p + 1:p + 1 + n], "big")
        p += 1 + n
    if p + ln > len(data):
        return None
    return (tag, p, ln)


def _der_children(data, start, length):
    """Iterate TLVs inside the constructed value at [start, start+length)."""
    out = []
    pos = start
    end = start + length
    while pos < end:
        t = _der_read_tlv(data, pos)
        if not t:
            break
        tag, vpos, vlen = t
        out.append((tag, vpos, vlen))
        pos = vpos + vlen
    return out


def _der_spki(cert_der):
    """Return (spki_der, key_modulus_bytes_or_None, alg_oid_hex_or_None) or (None, None, None)."""
    t = _der_read_tlv(cert_der, 0)
    if not t or t[0] != 0x30:
        return None, None, None
    body = _der_children(cert_der, t[1], t[2])
    if len(body) < 3:
        return None, None, None
    # body: tbs(0x30), sigalg(0x30), sig(0x03)
    tbs_tag, tbs_pos, tbs_len = body[0]
    tbs = _der_children(cert_der, tbs_pos, tbs_len)
    # tbs: [0] version?, serial(0x02), sigalg(0x30), issuer(0x30),
    #      validity(0x30), subject(0x30), spki(0x30)
    idx = 0
    if idx < len(tbs) and tbs[idx][0] == 0xA0:
        idx += 1
    # skip serial, sigalg, issuer, validity, subject -> spki expected
    idx += 5
    if idx >= len(tbs) or tbs[idx][0] != 0x30:
        return None, None, None
    st, spos, slen = tbs[idx]
    spki = cert_der[spos - 2: spos + slen]  # includes tag+len
    # RSA: SPKI -> SEQ{ SEQ{OID rsaEncryption, NULL}, BITSTRING{ SEQ{n, e} } }
    modulus = None
    alg_oid = None
    sp = _der_children(cert_der, spos, slen)
    if len(sp) >= 2:
        at, apos, alen = sp[0]
        aseq = _der_children(cert_der, apos, alen)
        if aseq and aseq[0][0] == 0x06:
            alg_oid = cert_der[aseq[0][1]:aseq[0][1] + aseq[0][2]].hex()
        bt, bpos, blen = sp[1]
        if bt == 0x03 and blen >= 2:
            bits = cert_der[bpos + 1:bpos + blen]  # skip unused-bits count
            it = _der_read_tlv(bits, 0)
            if it and it[0] == 0x30:
                kids = _der_children(bits, it[1], it[2])
                if kids and kids[0][0] == 0x02:
                    m = bits[kids[0][1]:kids[0][1] + kids[0][2]]
                    modulus = m.lstrip(b"\x00") or b"\x00"
    return spki, modulus, alg_oid


def scan_certs(data):
    """Scan a byte range for DER X.509 certificates (0x30 0x82 ..)."""
    certs = []
    i = 0
    while True:
        i = data.find(b"\x30\x82", i)
        if i < 0:
            break
        t = _der_read_tlv(data, i)
        if t and t[0] == 0x30 and t[2] > 40:
            der = data[i:t[1] + t[2]]
            spki, modulus, oid = _der_spki(der)
            if spki:
                certs.append({"offset": i, "der": der, "spki": spki,
                              "modulus": modulus, "key_oid": oid})
                i = t[1] + t[2]
                continue
        i += 1
    return certs


def hash_candidates(blob):
    if blob is None:
        return {}
    return {"sha256": hashlib.sha256(blob).hexdigest(),
            "sha384": hashlib.sha384(blob).hexdigest(),
            "sha512": hashlib.sha512(blob).hexdigest()}


# ------------------------------------------------------------------ headers
def parse_hash_segment(seg):
    """seg: bytes of the hash segment. Returns info dict."""
    if len(seg) < 48:
        raise ValueError("hash segment too short (%d)" % len(seg))
    md_size, version = struct.unpack_from("<HH", seg, 0)
    image_id, = struct.unpack_from("<I", seg, 4)
    info = {"md_size": md_size, "version": version, "image_id": image_id,
            "anti_rollback_version": None, "anti_rollback_note": None,
            "oem_id": None, "model_id": None, "sw_id": None, "hw_id": None,
            "soc_hw_version": None, "oem_meta_raw": None, "certs": []}

    if version == 6:
        sig_size, cert_size, hash_size, total_size = struct.unpack_from("<IIII", seg, 16)
        meta_qti, meta_oem = struct.unpack_from("<II", seg, 40)
        info.update({"qti_sig_size": sig_size, "qti_cert_size": cert_size,
                     "hash_size": hash_size, "total_size": total_size,
                     "meta_qti_size": meta_qti, "meta_oem_size": meta_oem})
        oem_off = 48 + meta_qti
        if meta_oem >= 120 and oem_off + meta_oem <= len(seg):
            oem = seg[oem_off:oem_off + meta_oem]
            info["oem_meta_raw"] = oem.hex()
            # offsets per JacksonOnly/QualcommImageUtils (v6, 120-byte block)
            o = oem_off
            info["sw_id"], info["hw_id"] = struct.unpack_from("<II", seg, o + 8)
            info["oem_id"], info["model_id"] = struct.unpack_from("<II", seg, o + 16)
            info["soc_hw_version"], = struct.unpack_from("<I", seg, o + 32)
            info["oem_root_cert_slot"], = struct.unpack_from("<I", seg, o + 112)
            info["anti_rollback_version"], = struct.unpack_from("<I", seg, o + 116)
            info["anti_rollback_note"] = "MBN v6 OEM meta anti_rollback@+116"
    elif version == 7:
        (cm, qm, om, hs, qs, qc, os_, oc) = struct.unpack_from("<IIIIIIII", seg, 8)
        info.update({"common_meta_size": cm, "qti_meta_size": qm,
                     "oem_meta_size": om, "hash_size": hs,
                     "qti_sig_size": qs, "qti_cert_size": qc,
                     "oem_sig_size": os_, "oem_cert_size": oc})
        # common meta: sw_id u64@0, hw_id u64@8, oem_id u32@16, model_id u32@20
        if cm >= 24 and 40 + cm <= len(seg):
            info["sw_id"], info["hw_id"] = struct.unpack_from("<QQ", seg, 40)
            info["oem_id"], info["model_id"] = struct.unpack_from("<II", seg, 56)
        oem_off = 40 + cm + qm
        if om and oem_off + om <= len(seg):
            info["oem_meta_raw"] = seg[oem_off:oem_off + om].hex()
            info["anti_rollback_note"] = ("v7 OEM meta present; ARB offset "
                                          "NOT VERIFIED - raw dumped")
    elif version in (3, 4, 5):
        f = struct.unpack_from("<" + "I" * 6, seg, 8)
        info["fields_8_28"] = list(f)
        # v5: qti_sig@8, qti_cert@12, oem sig@16?, oem cert@20?, hash@24, total@28
        info["anti_rollback_note"] = "v%d image: no OEM metadata ARB (pre-v6)" % version
    else:
        info["anti_rollback_note"] = "unknown header version %d" % version

    info["certs"] = scan_certs(seg)
    # pretty per-cert hash candidates
    for c in info["certs"]:
        c["cert_hashes"] = hash_candidates(c["der"])
        c["spki_hashes"] = hash_candidates(c["spki"])
        c["modulus_hashes"] = hash_candidates(c["modulus"])
    return info


def parse_image(data):
    """data: whole file bytes (ELF or raw MBN). Returns info dict."""
    if data[:4] == b"\x7fELF":
        seg = _find_elf_hash_segment(data)
        if not seg:
            raise ValueError("ELF has no hash segment")
        off, size = seg
        info = parse_hash_segment(data[off:off + size])
        info["elf_hash_seg_offset"] = off
        info["elf_hash_seg_size"] = size
        return info
    return parse_hash_segment(data)


def match_pk_hash(info, pk_hex):
    """Check whether any cert in the image matches the device PK hash.
    pk_hex: hex string of the Sahara OEM PK hash. Returns list of matches."""
    pk = pk_hex.lower().replace(":", "").strip()
    matches = []
    for c in info["certs"]:
        for what in ("cert_hashes", "spki_hashes", "modulus_hashes"):
            for algo, h in c[what].items():
                if h == pk:
                    matches.append({"algo": algo, "of": what, "offset": c["offset"]})
    return matches


def format_info(info, pk_hex=None):
    lines = []
    lines.append("md_size        : %d" % info["md_size"])
    lines.append("MBN version    : %s" % info["version"])
    lines.append("image_id       : 0x%08x (%d)" % (info["image_id"], info["image_id"]))
    if info.get("sw_id") is not None:
        lines.append("sw_id          : 0x%08x" % info["sw_id"])
    if info.get("hw_id") is not None:
        lines.append("hw_id          : 0x%08x" % info["hw_id"])
    if info.get("oem_id") is not None:
        lines.append("oem_id         : 0x%08x" % info["oem_id"])
    if info.get("model_id") is not None:
        lines.append("model_id       : 0x%08x" % info["model_id"])
    if info.get("soc_hw_version") is not None:
        lines.append("soc_hw_version : 0x%08x" % info["soc_hw_version"])
    if info.get("anti_rollback_version") is not None:
        lines.append("ARB (anti_rollback_version): %d" % info["anti_rollback_version"])
    if info.get("anti_rollback_note"):
        lines.append("ARB note       : %s" % info["anti_rollback_note"])
    if info.get("elf_hash_seg_offset") is not None:
        lines.append("ELF hash seg   : offset 0x%x size 0x%x" %
                     (info["elf_hash_seg_offset"], info["elf_hash_seg_size"]))
    if pk_hex:
        m = match_pk_hash(info, pk_hex)
        if m:
            lines.append("PK hash MATCH  : %s" % m)
        else:
            lines.append("PK hash match  : NONE of %d certs matches" % len(info["certs"]))
    for i, c in enumerate(info["certs"]):
        lines.append("cert[%d] @0x%x key_oid=%s" % (i, c["offset"], c["key_oid"]))
        for what in ("cert_hashes", "spki_hashes", "modulus_hashes"):
            if c[what]:
                lines.append("    %s: %s" % (what, " ".join(
                    "%s=%s" % (a, h[:16] + "...") for a, h in c[what].items())))
    if info.get("oem_meta_raw"):
        lines.append("oem_meta raw   : %s" % info["oem_meta_raw"][:256])
    return "\n".join(lines)
