# vim: sts=4 sw=4 et

import struct

from lib.packet.packet_base import packet_base
from lib.packet.packet_utils import *

class pkt_in(packet_base):
    "pkt_in packet struct"

    MIN_LEN = 12

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.buf_id = 0
        self.len = 0
        self.in_port = 0    #not used yet
        self.reason = 0     #not used yet

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[PKTIN: id:%08x l:%s p:%s r:%s]' % (
            self.buf_id,
            self.len,
            self.in_port,
            self.reason)
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < pkt_in.MIN_LEN:
            self.msg('(pkt_in parse) warning packet pkt_in too short to parse header: pkt_in len %u' % dlen)
            return

        (self.buf_id, self.len, self.in_port, self.reason, _, _) \
            = struct.unpack('!LHHHBB', raw[:pkt_in.MIN_LEN])

        self.parsed = True

        if self.len < dlen - pkt_in.MIN_LEN:
            self.msg('(pkt_in parse) warning invalid PKTIN len %u' % self.len)
            return

        self.payload = raw[pkt_in.MIN_LEN:]


    def hdr(self, payload):
        return struct.pack('!LHHHBB', self.buf_id, self.len, self.in_port, self.reason, 0, 0)
