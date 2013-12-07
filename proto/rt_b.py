# vim: sts=4 sw=4 et

#   +++++++++++++++++++++++++++++
# 0 |  Ver |  Num |  StationID  |
#   +------+------+------+------+
# 4 |     Dest Network IP1      |
#   +------+------+------+------+
# 8 | Mask1+        Pad         |
#   +------+------+------+------+
#12 |     Dest Network IP2      |
#   +------+------+------+------+
#16 | Mask2+        Pad         |
#   +------+------+------+------+
#20 |          ...              |

import struct

from lib.packet.packet_base import packet_base
from lib.packet.packet_utils import *

class rt_b(packet_base):
    "route broadcast packet struct"

    MIN_LEN = 4
    VER = 1

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.ver = rt_b.VER
        self.num = 0
        self.id = 0
        self.dn = set()

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[RTB: v:%02x n:%s i:%s]' % (self.ver, self.num, self.id)
        for k in self.dn:
            dest, mask = k
            s += '    (%s/%s)' % (dest, mask)
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < rt_b.MIN_LEN:
            self.msg('(rt_b parse) warning packet rt_b too short to parse header: rt_b len %u' % dlen)
            return

        (self.ver, self.num, self.id) \
            = struct.unpack('!BBH', raw[:rt_b.MIN_LEN])
        if dlen < rt_b.MIN_LEN+self.num*8:
            self.msg('(rt_b parse) warning packet rt_b too short to parse dest nets: rt_b::num %u' % self.num)
            return
        for i in range(self.num):
            (ip, mask) = struct.unpack('!LB', raw[rt_b.MIN_LEN+i*8:rt_b.MIN_LEN+(i+1)*8])
            ip = IPAddr(ip)
            self.dn.add((ip,mask))

        self.parsed = True

    def hdr(self):
        return struct.pack('!BBH', self.ver, self.num, self.id)

    @property
    def payload (self):
        p = b''
        for k in self.dn:
            dest, mask = k
            p += struct.pack('LBBBB', dest, mask, 0, 0, 0)
        return p

    def add(self, ip, mask):
        if isinstance(ip, IPAddr):
            ip = IPAddr(ip)
        self.dn.add((ip,mask))
        self.num += 1

    def remove(self, ip, mask):
        if isinstance(ip, IPAddr):
            ip = IPAddr(ip)
        self.dn.remove((ip,mask))
        self.num -= 1

