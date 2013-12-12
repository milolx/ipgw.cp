# vim: sts=4 sw=4 et

import struct

from lib.packet.packet_base import packet_base
from lib.packet.packet_utils import *

class ack(packet_base):
    "ack packet struct"

    MIN_LEN = 8

    SRVC_RSLT_NONE  = 0
    SRVC_RSLT_OK    = 1
    SRVC_RSLT_ERR   = 2

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.result= ack.SRVC_RSLT_NONE
        self.xid = (int(time.time()) + 1) & 0xffff

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[ACK: r:%02x x:%02x]' % (self.result, self.for_xid)
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < ack.MIN_LEN:
            self.msg('(ack parse) warning packet ack too short to parse header: ack len %u' % dlen)
            return

        (self.result, _, self.xid) \
            = struct.unpack('!BBH', raw[:ack.MIN_LEN])

        self.parsed = True

    def hdr(self, payload):
        return struct.pack('!BBH', self.result, 0, self.xid)
