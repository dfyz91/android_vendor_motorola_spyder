"""Reference values for the target device (OnePlus 9RT, MT2110, SM8350).

These are the values the real target reported over Sahara (measured on the
user's device with QDL v2.8, commit ced92634). They are used to:
 - validate the mock device in tests (tests reproduce these exact values),
 - warn when a different device is attached before any write.
They are NOT a guarantee that every MT2110 unit has the same PK hash.
"""

SERIAL = 0x0C7096BF
MSM_ID = 0x001350E1
OEM_ID = 0x0051
MODEL_ID = 0x0000
HW_ID = 0x001350E100510000

# 48 bytes = SHA-384-sized OEM PK hash reported by the target's PBL.
PK_HASH = ("d8e3b5a8dada006de3600d3489af632f"
           "62511e17bc2f0834ccd8855294b3eaea"
           "5806184aac7bf6fd5def121311a5ff49")

# Programmer (Firehose) is uploaded as Sahara image id 13
# (OplusEdlTool: QSaharaServer -s 13:prog.elf).
PROGRAMMER_IMAGE_ID = 13

SECTOR_SIZE = 4096

# Boot-chain partitions whose writes are ARB-guarded (Qualcomm SM8350 A/B).
ARB_CRITICAL = ("xbl", "xbl_config", "xbl_ramdump", "abl", "aop", "aop_config",
                "tz", "tz_config", "hyp", "devcfg", "keymaster", "km",
                "modem", "multiimgoem", "qupfw", "imagefv", "shrm", "oplusstanvbk")

# Partitions to read by default in read-boot-chain / arb-report.
BOOT_CHAIN = ("xbl_a", "xbl_b", "xbl_config_a", "xbl_config_b",
              "abl_a", "abl_b")

KNOWN_DEVICES = [{
    "name": "OnePlus 9RT 5G (MT2110, martini, SM8350)",
    "msm_id": MSM_ID, "oem_id": OEM_ID, "model_id": MODEL_ID,
    "pk_hash": PK_HASH, "serial": SERIAL,
}]


def matches_device(info):
    """info: dict from SaharaClient.chipinfo(). -> (bool, notes)"""
    notes = []
    ok = True
    for d in KNOWN_DEVICES:
        if info.get("msm_id") != d["msm_id"]:
            notes.append("MSM_ID %s != expected %s" %
                         (hex(info.get("msm_id") or 0), hex(d["msm_id"])))
            ok = False
        if info.get("oem_id") != d["oem_id"]:
            notes.append("OEM_ID %s != expected %s" %
                         (hex(info.get("oem_id") or 0), hex(d["oem_id"])))
            ok = False
        if info.get("pk_hash", "").lower() != d["pk_hash"].lower():
            notes.append("PK hash mismatch with reference MT2110 value")
            ok = False
    return ok, notes
