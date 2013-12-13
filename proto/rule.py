# vim: sts=4 sw=4 et

import struct

from lib.packet.packet_base import packet_base
from lib.packet.packet_utils import *

from lib.addresses import IPAddr, IP_ANY, IP_BROADCAST

class rule(packet_base):
    "rule packet struct"

    MIN_LEN = 16

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.ip = IP_ANY
        self.mask = 0
        self.site = 0
        self.idle_to = 0    #idle timeout
        self.hard_to = 0    #hard timeout

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[RULE: ip:%s m:%s s:%s i:%s h:%s]' % (
            self.ip,
            self.mask,
            self.site,
            self.idle_to,
            self.hard_to)
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < rule.MIN_LEN:
            self.msg('(rule parse) warning packet rule too short to parse header: rule len %u' % dlen)
            return

        (self.ip, self.mask, _, _, _, self.site, _, _, self.idle_to, self.hard_to) \
            = struct.unpack('!LBBBBHBBHH', raw[:rule.MIN_LEN])

        self.ip = IPAddr(self.ip)

        self.parsed = True

    def hdr(self, payload):
        return struct.pack('!LBBBBHBBHH', self.ip.toUnsigned(), self.mask, 0, 0, 0, self.site, 0, 0, self.idle_to, self.hard_to)
