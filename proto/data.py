# vim: sts=4 sw=4 et

import struct

from lib.packet.packet_base import packet_base
from lib.packet.packet_utils import *

class data(packet_base):
    "data packet struct"

    MIN_LEN = 8

    SRVC_DATA_NONE      = 0
    SRVC_DATA_UNICAST   = 1
    SRVC_DATA_MULTICAST = 2
    SRVC_DATA_BROADCAST = 3

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.type = data.SRVC_DATA_NONE
        self.len = 0
        self.site = 0       # dst site
        self.next = b''

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[DATA: t:%02x l:%s s:%s]' % (self.type, self.len, self.site)
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < data.MIN_LEN:
            self.msg('(data parse) warning packet data too short to parse header: data len %u' % dlen)
            return

        (self.type, _, _, _, self.len, self.site) \
            = struct.unpack('!BBBBHH', raw[:data.MIN_LEN])

        if self.len != dlen - data.MIN_LEN:
            self.msg('(data parse) warning invalid data len: exp(%d) get(%d)' % (self.len, dlen-data.MIN_LEN))
            return

        self.payload = raw[data.MIN_LEN:]

        self.parsed = True

    def hdr(self, payload):
        self.len = len(payload)
        return struct.pack('!BBBBHH', self.type, 0, 0, 0, self.len, self.site)
