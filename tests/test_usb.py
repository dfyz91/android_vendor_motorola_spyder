"""Unit tests for USB error classification and transports."""
import unittest
from edl_termux import usb


class TestUsbErrors(unittest.TestCase):

    def setUp(self):
        self.dev = usb.LibusbBase.__new__(usb.LibusbBase)

    def test_libusb_error_io(self):
        with self.assertRaises(usb.TransportError) as ctx:
            self.dev._err(-1, "bulk_read", transferred=64)
        err = ctx.exception
        self.assertNotIsInstance(err, usb.DeviceGoneError)
        self.assertEqual(err.rc, -1)
        self.assertEqual(err.transferred, 64)
        self.assertEqual(err.errno, 5)

    def test_libusb_error_no_device(self):
        with self.assertRaises(usb.DeviceGoneError) as ctx:
            self.dev._err(-4, "bulk_read", transferred=0)
        err = ctx.exception
        self.assertEqual(err.rc, -4)
        self.assertEqual(err.errno, 19)

    def test_libusb_error_pipe(self):
        with self.assertRaises(usb.TransportError) as ctx:
            self.dev._err(-9, "bulk_write", transferred=0)
        err = ctx.exception
        self.assertNotIsInstance(err, usb.DeviceGoneError)
        self.assertEqual(err.rc, -9)
        self.assertEqual(err.errno, 32)

    def test_libusb_error_timeout(self):
        with self.assertRaises(usb.TransportError) as ctx:
            self.dev._err(-7, "bulk_read", transferred=0)
        err = ctx.exception
        self.assertEqual(err.rc, -7)
        self.assertEqual(err.errno, 110)


if __name__ == "__main__":
    unittest.main()
