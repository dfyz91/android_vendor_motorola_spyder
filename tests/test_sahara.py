"""Unit tests for Sahara protocol client and packet handling."""
import unittest
from edl_termux import sahara
from tests.mock_device import MockDevice
from tests.test_transports import PipeTransport


class TestSahara(unittest.TestCase):

    def test_build_hello_rsp(self):
        rsp = sahara.build_hello_rsp(mode=0, version=2)
        self.assertEqual(len(rsp), 0x30)
        self.assertEqual(rsp[:4], sahara.CMD_HELLO_RSP.to_bytes(4, "little"))

    def test_parse_hello(self):
        raw = sahara.CMD_HELLO_REQ.to_bytes(4, "little") + (0x30).to_bytes(4, "little") + (2).to_bytes(4, "little") + (1).to_bytes(4, "little") + (0x200).to_bytes(4, "little") + (0).to_bytes(4, "little") + b"\x00" * 24
        hello = sahara.parse_hello(raw)
        self.assertEqual(hello["version"], 2)
        self.assertEqual(hello["mode"], 0)

    def test_mock_device_upload_flow(self):
        mock = MockDevice()
        tr = PipeTransport(mock)
        sc = sahara.SaharaClient(tr)

        info = sc.chipinfo()
        self.assertEqual(info["serial"], 0x0C7096BF)
        self.assertEqual(info["msm_id"], 0x001350E1)

        sc.switch_mode(sahara.MODE_IMAGE_TX_PENDING)
        res = sc.upload_image(b"\x00" * 0x20000, need_connect=False)
        self.assertTrue(res)

    def test_invalid_packet_length(self):
        from edl_termux.usb import BaseTransport
        class DummyTr(BaseTransport):
            def __init__(self):
                pass
            def read(self, size, timeout=10000):
                # Return cmd=1, length=2 (invalid, < 8)
                return (1).to_bytes(4, "little") + (2).to_bytes(4, "little")

        sc = sahara.SaharaClient(DummyTr())
        with self.assertRaises(sahara.SaharaError) as ctx:
            sc._read_pkt()
        self.assertIn("invalid Sahara packet length", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
