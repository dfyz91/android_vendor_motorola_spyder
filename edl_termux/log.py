"""Logging helpers: timestamped packet logging with hexdump."""
import sys
import time


def now_ms():
    return (time.monotonic() * 1000.0)


def hexdump(data, limit=64):
    if not isinstance(data, (bytes, bytearray)):
        data = bytes(data)
    n = len(data)
    out = []
    for off in range(0, min(n, limit), 16):
        chunk = data[off:off + 16]
        hx = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("    %04x  %-47s  %s" % (off, hx, asc))
    if n > limit:
        out.append("    ... (%d bytes total, %d shown)" % (n, limit))
    return "\n".join(out)


class Logger:
    def __init__(self, verbose=True, logfile=None):
        self.verbose = verbose
        self.t0 = now_ms()
        self.fh = open(logfile, "a") if logfile else None

    def _fmt(self, tag, msg):
        return "[%8.1f ms] %s %s" % (now_ms() - self.t0, tag, msg)

    def info(self, msg):
        print(self._fmt("[*]", msg), file=sys.stderr)
        if self.fh:
            print(self._fmt("[*]", msg), file=self.fh, flush=True)

    def warn(self, msg):
        print(self._fmt("[!]", msg), file=sys.stderr)
        if self.fh:
            print(self._fmt("[!]", msg), file=self.fh, flush=True)

    def error(self, msg):
        print(self._fmt("[E]", msg), file=sys.stderr)
        if self.fh:
            print(self._fmt("[E]", msg), file=self.fh, flush=True)

    def pkt(self, direction, data, note=""):
        """direction: 'RX'/'TX'."""
        if not self.verbose:
            return
        head = self._fmt("[%s]" % direction, "(%d bytes) %s" % (len(data), note))
        print(head, file=sys.stderr)
        print(hexdump(data), file=sys.stderr)
        if self.fh:
            print(head, file=self.fh, flush=True)
            print(hexdump(data), file=self.fh, flush=True)
