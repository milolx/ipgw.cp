# vim: sts=4 sw=4 et

import struct
import time

from lib.packet.packet_base import packet_base
from lib.packet.packet_utils import *

class res(packet_base):
    "resource request/release packet struct"

    MIN_LEN = 4

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.xid = (int(time.time()) + 1) & 0xffff
        self.site = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[RES: x:%02x s:%s]' % (self.xid, self.site)
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < res.MIN_LEN:
            self.msg('(res parse) warning packet res too short to parse header: res len %u' % dlen)
            return

        (self.xid, self.site) \
            = struct.unpack('!HH', raw[:res.MIN_LEN])

        self.parsed = True

    def hdr(self, payload):
        return struct.pack('!HH', self.xid, self.site)

