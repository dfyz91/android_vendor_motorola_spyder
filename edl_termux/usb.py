"""USB transports.

- LibusbFdTransport: real device, FD handed over by termux-usb, via
  libusb_wrap_sys_device() (ctypes, libusb 1.0).
- EnumTransport: normal libusb enumeration (works on desktop Linux / rooted
  hosts; kept so the non-Termux mode is not broken).
"""
import ctypes
import ctypes.util
import os
import sys

EP_IN = 0x81
EP_OUT = 0x01
QDL_VID = 0x05C6
QDL_PID = 0x9008
IFACE = 1
TIMEOUT_MS = 10000

LIBUSB_ERRORS = {
    -1: "LIBUSB_ERROR_IO",
    -2: "LIBUSB_ERROR_INVALID_PARAM",
    -3: "LIBUSB_ERROR_ACCESS",
    -4: "LIBUSB_ERROR_NO_DEVICE (device gone - run termux-usb again)",
    -5: "LIBUSB_ERROR_NOT_FOUND",
    -6: "LIBUSB_ERROR_BUSY",
    -7: "LIBUSB_ERROR_TIMEOUT",
    -8: "LIBUSB_ERROR_OVERFLOW",
    -9: "LIBUSB_ERROR_PIPE (endpoint stalled)",
    -10: "LIBUSB_ERROR_INTERRUPTED",
    -11: "LIBUSB_ERROR_NO_MEM",
    -12: "LIBUSB_ERROR_NOT_SUPPORTED",
}

# ctypes mirrors of libusb-1.0 descriptor structs. These are read-only
# descriptor views; they do not claim an interface or change its altsetting.
class _LibusbEndpointDescriptor(ctypes.Structure):
    _fields_ = [
        ("bLength", ctypes.c_uint8),
        ("bDescriptorType", ctypes.c_uint8),
        ("bEndpointAddress", ctypes.c_uint8),
        ("bmAttributes", ctypes.c_uint8),
        ("wMaxPacketSize", ctypes.c_uint16),
        ("bInterval", ctypes.c_uint8),
        ("bRefresh", ctypes.c_uint8),
        ("bSynchAddress", ctypes.c_uint8),
        ("extra", ctypes.POINTER(ctypes.c_ubyte)),
        ("extra_length", ctypes.c_int),
    ]


class _LibusbInterfaceDescriptor(ctypes.Structure):
    _fields_ = [
        ("bLength", ctypes.c_uint8),
        ("bDescriptorType", ctypes.c_uint8),
        ("bInterfaceNumber", ctypes.c_uint8),
        ("bAlternateSetting", ctypes.c_uint8),
        ("bNumEndpoints", ctypes.c_uint8),
        ("bInterfaceClass", ctypes.c_uint8),
        ("bInterfaceSubClass", ctypes.c_uint8),
        ("bInterfaceProtocol", ctypes.c_uint8),
        ("iInterface", ctypes.c_uint8),
        ("endpoint", ctypes.POINTER(_LibusbEndpointDescriptor)),
        ("extra", ctypes.POINTER(ctypes.c_ubyte)),
        ("extra_length", ctypes.c_int),
    ]


class _LibusbInterface(ctypes.Structure):
    _fields_ = [
        ("altsetting", ctypes.POINTER(_LibusbInterfaceDescriptor)),
        ("num_altsetting", ctypes.c_int),
    ]


class _LibusbConfigDescriptor(ctypes.Structure):
    _fields_ = [
        ("bLength", ctypes.c_uint8),
        ("bDescriptorType", ctypes.c_uint8),
        ("wTotalLength", ctypes.c_uint16),
        ("bNumInterfaces", ctypes.c_uint8),
        ("bConfigurationValue", ctypes.c_uint8),
        ("iConfiguration", ctypes.c_uint8),
        ("bmAttributes", ctypes.c_uint8),
        ("MaxPower", ctypes.c_uint8),
        ("interface", ctypes.POINTER(_LibusbInterface)),
        ("extra", ctypes.POINTER(ctypes.c_ubyte)),
        ("extra_length", ctypes.c_int),
    ]


# errno-style names for messages shown to the user
ERRNO_NAMES = {71: "EPROTO", 5: "EIO", 19: "ENODEV", 110: "ETIMEDOUT", 16: "EBUSY"}


class TransportError(Exception):
    def __init__(self, msg, errno=None, rc=None, transferred=0):
        super().__init__(msg)
        self.errno = errno
        self.rc = rc
        self.transferred = transferred


class DeviceGoneError(TransportError):
    """FD is dead (device reset/disconnected): a NEW termux-usb FD is needed."""


class BaseTransport:
    def read(self, size, timeout=TIMEOUT_MS):  # -> bytes
        raise NotImplementedError

    def write(self, data, timeout=TIMEOUT_MS):  # -> int
        raise NotImplementedError

    def close(self):
        pass

    def write_zlp_if_needed(self, data, maxpacket=512, timeout=TIMEOUT_MS):
        """Firehose requires a ZLP when a raw write is a multiple of maxpacket."""
        n = self.write(data, timeout)
        if len(data) and len(data) % maxpacket == 0:
            self.write(b"", timeout)
        return n




def load_libusb():
    """Load libusb-1.0.
    Termux quirk (v0.1.2): when this process is spawned by termux-usb
    (-e), dlopen by bare soname can fail (different linker namespace /
    LD_LIBRARY_PATH). Absolute $PREFIX/lib paths are tried FIRST;
    relative find_library() results are resolved against $PREFIX/lib."""
    prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    names = []
    for p in (os.path.join(prefix, "lib", "libusb-1.0.so"),
              os.path.join(prefix, "lib", "libusb-1.0.so.0")):
        if os.path.exists(p):
            names.append(p)
    if hasattr(ctypes.util, "find_library"):
        for cand in ("usb-1.0", "libusb-1.0", "usb"):
            n = ctypes.util.find_library(cand)
            if n:
                if not os.path.isabs(n):
                    for base in (os.path.join(prefix, "lib"),
                                 "/usr/lib/aarch64-linux-gnu",
                                 "/usr/lib/x86_64-linux-gnu",
                                 "/lib/aarch64-linux-gnu"):
                        cand_path = os.path.join(base, n)
                        if os.path.exists(cand_path):
                            n = cand_path
                            break
                names.append(n)
    names += ["libusb-1.0.so", "libusb-1.0.so.0", "libusb.so.1", "libusb.so"]
    seen = set()
    ordered = []
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        ordered.append(n)
    for n in ordered:
        try:
            return ctypes.CDLL(n)
        except OSError:
            continue
    raise TransportError("libusb-1.0 not found. In Termux: pkg install libusb")


class LibusbBase(BaseTransport):
    def __init__(self, log=None):
        self.lib = load_libusb()
        self.log = log
        self.handle = None
        self.ctx = ctypes.c_void_p()
        rc = self.lib.libusb_init(ctypes.byref(self.ctx))
        if rc != 0:
            raise TransportError("libusb_init failed rc=%d" % rc)
        try:
            self.lib.libusb_set_option(self.ctx, 1, 1)  # LIBUSB_OPTION_LOG_LEVEL
        except Exception:
            pass
        # these return raw pointers: without c_void_p restype, ctypes
        # truncates them to int on 64-bit builds (silent corruption)
        try:
            self.lib.libusb_get_device.restype = ctypes.c_void_p
            self.lib.libusb_ref_device.restype = ctypes.c_void_p
            self.lib.libusb_get_device_list.restype = ctypes.c_int
            self.lib.libusb_get_device_descriptor.restype = ctypes.c_int
            self.lib.libusb_free_device_list.restype = None
            self.lib.libusb_unref_device.restype = None
            # int libusb_wrap_sys_device(ctx, intptr_t sys_dev, handle **).
            # intptr_t is pointer-sized; c_int truncates FDs on some ABIs.
            self.lib.libusb_wrap_sys_device.argtypes = [
                ctypes.c_void_p, ctypes.c_ssize_t, ctypes.POINTER(ctypes.c_void_p)]
            self.lib.libusb_wrap_sys_device.restype = ctypes.c_int
            self.lib.libusb_get_active_config_descriptor.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.POINTER(_LibusbConfigDescriptor))]
            self.lib.libusb_get_active_config_descriptor.restype = ctypes.c_int
            self.lib.libusb_get_config_descriptor.argtypes = [
                ctypes.c_void_p, ctypes.c_uint8,
                ctypes.POINTER(ctypes.POINTER(_LibusbConfigDescriptor))]
            self.lib.libusb_get_config_descriptor.restype = ctypes.c_int
            self.lib.libusb_free_config_descriptor.argtypes = [
                ctypes.POINTER(_LibusbConfigDescriptor)]
            self.lib.libusb_free_config_descriptor.restype = None
        except AttributeError:
            pass

    def _err(self, rc, what, transferred=0):
        name = LIBUSB_ERRORS.get(rc, "LIBUSB_ERROR_%d" % rc)
        if rc == -4:  # LIBUSB_ERROR_NO_DEVICE
            raise DeviceGoneError("%s failed: %s (rc=%d)" % (what, name, rc), errno=19, rc=rc, transferred=transferred)
        if rc == -7:  # LIBUSB_ERROR_TIMEOUT
            raise TransportError("%s: %s (rc=%d)" % (what, name, rc), errno=110, rc=rc, transferred=transferred)
        if rc == -9:  # LIBUSB_ERROR_PIPE
            raise TransportError("%s: %s (endpoint stalled, rc=%d)" % (what, name, rc), errno=32, rc=rc, transferred=transferred)
        if rc == -1:  # LIBUSB_ERROR_IO
            raise TransportError("%s: %s (rc=%d, transferred=%d)" % (what, name, rc, transferred), errno=5, rc=rc, transferred=transferred)
        raise TransportError("%s failed: %s (rc=%d)" % (what, name, rc), rc=rc, transferred=transferred)

    def dump_usb_descriptors(self, expected_in=EP_IN, expected_out=EP_OUT):
        """Log interface/alternate-setting/endpoint descriptors without writes.

        Called before claiming the interface. If the active configuration
        cannot be queried, the first descriptor configuration is inspected as
        a fallback; this does not select or change a USB configuration.
        """
        def emit(message, warning=False):
            if self.log:
                (self.log.warn if warning else self.log.info)(message)
            else:
                print(message, file=sys.stderr)

        try:
            dev_value = self.lib.libusb_get_device(self.handle)
            if not dev_value:
                emit("USB descriptors: libusb_get_device returned NULL", warning=True)
                return False
            dev = ctypes.c_void_p(dev_value)
            cfg_ptr = ctypes.POINTER(_LibusbConfigDescriptor)()
            rc = self.lib.libusb_get_active_config_descriptor(dev, ctypes.byref(cfg_ptr))
            source = "active configuration"
            if rc != 0:
                emit("USB descriptors: active config unavailable (rc=%d); trying config index 0" % rc,
                     warning=True)
                rc = self.lib.libusb_get_config_descriptor(dev, 0, ctypes.byref(cfg_ptr))
                source = "configuration index 0 fallback"
            if rc != 0 or not cfg_ptr:
                emit("USB descriptors: cannot read configuration descriptors (rc=%d)" % rc,
                     warning=True)
                return False

            found = {}
            try:
                cfg = cfg_ptr.contents
                emit("USB descriptors (%s): bConfigurationValue=%d num_interfaces=%d" %
                     (source, cfg.bConfigurationValue, cfg.bNumInterfaces))
                for i in range(cfg.bNumInterfaces):
                    iface = cfg.interface[i]
                    emit("  interface[%d] num_altsettings=%d" % (i, iface.num_altsetting))
                    for j in range(iface.num_altsetting):
                        alt = iface.altsetting[j]
                        key = (alt.bInterfaceNumber, alt.bAlternateSetting)
                        emit("    iface=%d alt=%d endpoints=%d class=0x%02x subclass=0x%02x protocol=0x%02x" %
                             (alt.bInterfaceNumber, alt.bAlternateSetting,
                              alt.bNumEndpoints, alt.bInterfaceClass,
                              alt.bInterfaceSubClass, alt.bInterfaceProtocol))
                        for k in range(alt.bNumEndpoints):
                            ep = alt.endpoint[k]
                            addr = int(ep.bEndpointAddress)
                            direction = "IN" if addr & 0x80 else "OUT"
                            transfer_type_id = int(ep.bmAttributes) & 0x03
                            transfer_type = {0: "control", 1: "isochronous",
                                             2: "bulk", 3: "interrupt"}.get(
                                                 transfer_type_id, "unknown")
                            packet = int(ep.wMaxPacketSize)
                            emit("      ep=0x%02x dir=%s type=%s wMaxPacketSize=%d (0x%04x)" %
                                 (addr, direction, transfer_type, packet, packet))
                            if addr in (expected_in, expected_out) and transfer_type == "bulk":
                                found.setdefault(key, set()).add(addr)
                pairs = [key for key, eps in found.items()
                         if expected_in in eps and expected_out in eps]
                if pairs:
                    emit("USB endpoint pair found in same altsetting: IN=0x%02x OUT=0x%02x at %s" %
                         (expected_in, expected_out, ", ".join(
                             "iface=%d alt=%d" % k for k in pairs)))
                else:
                    emit("WARNING: bulk endpoint pair IN=0x%02x / OUT=0x%02x not found in the same altsetting" %
                         (expected_in, expected_out), warning=True)
                return bool(pairs)
            finally:
                self.lib.libusb_free_config_descriptor(cfg_ptr)
        except Exception as exc:
            emit("USB descriptors: inspection failed: %s" % exc, warning=True)
            return False

    def _claim(self, iface=IFACE):
        # auto-detach kernel driver where supported (harmless on Android)
        try:
            self.lib.libusb_set_auto_detach_kernel_driver(self.handle, 1)
        except Exception:
            pass
        rc = self.lib.libusb_claim_interface(self.handle, iface)
        if rc == 0:
            if self.log:
                self.log.info("claimed USB interface %d" % iface)
            return 0
        # Preserve the existing fallback, but make it visible in diagnostics.
        if self.log:
            self.log.warn("claim_interface(%d) failed (rc=%d); trying interface 0" %
                          (iface, rc))
        if iface != 0:
            rc2 = self.lib.libusb_claim_interface(self.handle, 0)
            if rc2 == 0:
                if self.log:
                    self.log.info("claimed USB interface 0 (fallback)")
                return 0
        self._err(rc, "claim_interface(%d)" % iface)

    def read(self, size, timeout=TIMEOUT_MS):
        buf = ctypes.create_string_buffer(size)
        done = ctypes.c_int(0)
        rc = self.lib.libusb_bulk_transfer(self.handle, EP_IN, buf, size,
                                           ctypes.byref(done), timeout)
        if rc == 0:
            return buf.raw[:done.value]
        self._err(rc, "bulk_read", transferred=done.value)

    def write(self, data, timeout=TIMEOUT_MS):
        data = bytes(data)
        n = len(data)
        buf = (ctypes.c_ubyte * n)(*data) if n else None
        done = ctypes.c_int(0)
        rc = self.lib.libusb_bulk_transfer(self.handle, EP_OUT, buf, n,
                                           ctypes.byref(done), timeout)
        if rc == 0:
            return done.value
        self._err(rc, "bulk_write", transferred=done.value)

    def close(self):
        if self.handle:
            try:
                self.lib.libusb_close(self.handle)
            except Exception:
                pass
            self.handle = None
        try:
            self.lib.libusb_exit(self.ctx)
        except Exception:
            pass


class LibusbFdTransport(LibusbBase):
    """Real device over a termux-usb FD (libusb_wrap_sys_device)."""

    def __init__(self, fd, log=None, iface=IFACE, dump_descriptors=False):
        super().__init__(log=log)
        self.fd = int(fd)
        self.handle = ctypes.c_void_p()
        rc = self.lib.libusb_wrap_sys_device(self.ctx, self.fd,
                                            ctypes.byref(self.handle))
        if rc != 0:
            self._err(rc, "libusb_wrap_sys_device(fd=%d)" % self.fd)
        # Descriptor inspection is read-only and is deliberately done before
        # claiming any interface. It never changes configuration/altsetting.
        if dump_descriptors:
            self.dump_usb_descriptors()
        self._claim(iface)

    def get_vid_pid(self):
        """Read the device descriptor of the wrapped FD and return
        (vid, pid). Used to verify the FD really is a Qualcomm 9008
        device before any Sahara traffic is attempted."""
        dev = ctypes.c_void_p(self.lib.libusb_get_device(self.handle))
        if not dev:
            raise TransportError("libusb_get_device failed (no device?)")
        desc = (ctypes.c_ubyte * 18)()
        rc = self.lib.libusb_get_device_descriptor(dev, desc)
        if rc != 0:
            self._err(rc, "libusb_get_device_descriptor")
        vid = desc[8] | (desc[9] << 8)
        pid = desc[10] | (desc[11] << 8)
        return vid, pid


class EnumTransport(LibusbBase):
    """Normal enumeration mode (desktop Linux, or Termux with root)."""

    def __init__(self, vid=QDL_VID, pid=QDL_PID, log=None, iface=IFACE):
        super().__init__(log=log)
        lst = ctypes.c_void_p()
        cnt = self.lib.libusb_get_device_list(self.ctx, ctypes.byref(lst))
        if cnt < 0:
            self._err(cnt, "get_device_list")
        dev = ctypes.c_void_p()
        found = False
        for i in range(cnt):
            d = ctypes.c_void_p(self.lib.libusb_ref_device(
                ctypes.c_void_p(ctypes.cast(lst, ctypes.POINTER(ctypes.c_void_p))[i])))
            desc = (ctypes.c_ubyte * 18)()
            rc = self.lib.libusb_get_device_descriptor(d, desc)
            if rc != 0:
                continue
            dvid = desc[8] | (desc[9] << 8)
            dpid = desc[10] | (desc[11] << 8)
            if dvid == vid and dpid == pid:
                rc = self.lib.libusb_open(d, ctypes.byref(dev))
                if rc == 0:
                    found = True
                    break
        self.lib.libusb_free_device_list(lst, 1)
        if not found:
            self.lib.libusb_exit(self.ctx)
            raise TransportError("no USB device %04x:%04x found" % (vid, pid))
        self.handle = dev
        try:
            self.lib.libusb_set_configuration(self.handle, -1)
        except Exception:
            pass
        self._claim(iface)
