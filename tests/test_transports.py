"""Test transports for mock and shim testing.

- PipeTransport: in-process mock transport.
- RawFdTransport: plain os.read/os.write on an inherited fd (socket/pipe).
"""
import os
from edl_termux.usb import BaseTransport, DeviceGoneError, TIMEOUT_MS


class PipeTransport(BaseTransport):
    """In-process mock: writes go to the mock device, reads come back."""

    def __init__(self, mock):
        self.mock = mock

    def read(self, size, timeout=TIMEOUT_MS):
        return self.mock.host_read(size)

    def write(self, data, timeout=TIMEOUT_MS):
        data = bytes(data)
        result = self.mock.host_write(data)
        return len(data) if result is None else result

    def close(self):
        pass


class RawFdTransport(BaseTransport):
    """os.read/os.write on an inherited fd (mock/shim tests ONLY)."""

    def __init__(self, fd):
        self.fd = int(fd)

    def read(self, size, timeout=TIMEOUT_MS):
        try:
            data = os.read(self.fd, size)
        except OSError as e:
            raise DeviceGoneError("raw fd read failed: %s" % e, e.errno) from e
        if not data:
            raise DeviceGoneError("fd at EOF (device reset/disconnected)", 19)
        return data

    def write(self, data, timeout=TIMEOUT_MS):
        try:
            return os.write(self.fd, bytes(data))
        except OSError as e:
            raise DeviceGoneError("raw fd write failed: %s" % e, e.errno) from e

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass
