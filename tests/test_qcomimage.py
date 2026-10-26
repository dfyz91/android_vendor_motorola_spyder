"""Unit tests for qcomimage ELF static parser."""
import unittest
import os
from edl_termux import qcomimage

ATTACHMENTS_DIR = os.environ.get("ATTACHMENTS_DIR", "/tmp/file_attachments/OP9RT")
PK_HASH = "d8e3b5a8dada006de3600d3489af632f62511e17bc2f0834ccd8855294b3eaea5806184aac7bf6fd5def121311a5ff49"


class TestQcomImage(unittest.TestCase):

    def test_parse_elf_9rt_5g(self):
        elf_path = os.path.join(ATTACHMENTS_DIR, "9RT_5G.elf")
        if not os.path.exists(elf_path):
            self.skipTest(f"{elf_path} not available")
        with open(elf_path, "rb") as f:
            data = f.read()

        info = qcomimage.parse_image(data)
        self.assertEqual(info["elf_hash_seg_offset"], 0x1000)
        matches = qcomimage.match_pk_hash(info, PK_HASH)
        self.assertTrue(len(matches) > 0)
        formatted = qcomimage.format_info(info, PK_HASH)
        self.assertIn("PK hash MATCH", formatted)

    def test_parse_elf_chimera(self):
        elf_path = os.path.join(ATTACHMENTS_DIR, "OPPO_SM8350_New_Chimera_V2.6.elf")
        if not os.path.exists(elf_path):
            self.skipTest(f"{elf_path} not available")
        with open(elf_path, "rb") as f:
            data = f.read()

        info = qcomimage.parse_image(data)
        self.assertEqual(info["elf_hash_seg_offset"], 0x1000)
        matches = qcomimage.match_pk_hash(info, PK_HASH)
        self.assertTrue(len(matches) > 0)

    def test_non_elf_and_invalid(self):
        with self.assertRaises(ValueError):
            qcomimage.parse_image(b"\x7fELF" + b"\x00" * 100)


if __name__ == "__main__":
    unittest.main()
