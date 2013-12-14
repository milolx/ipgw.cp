# vim: sts=4 sw=4 et

#   +++++++++++++++++++++++++++++
# 0 |  Ver |  Num |  StationID  |
#   +------+------+------+------+
# 4 | Payload len |     Pad     |
#   +------+------+------+------+
# 8 |     Dest Network IP1      |
#   +------+------+------+------+
#12 | Mask1|        Pad         |
#   +------+------+------+------+
#16 |     Dest Network IP2      |
#   +------+------+------+------+
#20 | Mask2|        Pad         |
#   +------+------+------+------+
#24 |          ...              |

import struct

from lib.packet.packet_base import packet_base
from lib.packet.packet_utils import *

from lib.addresses import IPAddr, IP_ANY, IP_BROADCAST

class rt_b(packet_base):
    "route broadcast packet struct"

    MIN_LEN = 8
    VER = 1

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.ver = rt_b.VER
        self.num = 0
        self.site = 0
        self.len = 0
        self.dn = set()

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[RTB: v:%02x n:%s i:%s l:%s]\n' % (self.ver, self.num, self.site, self.len)
        for k in self.dn:
            dest, mask = k
            s += '    (%s/%s)\n' % (dest, mask)
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < rt_b.MIN_LEN:
            self.msg('(rt_b parse) warning packet rt_b too short to parse header: rt_b len %u' % dlen)
            return

        (self.ver, self.num, self.site, self.len, _) \
            = struct.unpack('!BBHHH', raw[:rt_b.MIN_LEN])
        if dlen < rt_b.MIN_LEN+self.num*8:
            self.msg('(rt_b parse) warning packet rt_b too short to parse dest nets: rt_b::num %u' % self.num)
            return
        for i in range(self.num):
            (ip, mask, _, _) = struct.unpack('!LBBH', raw[rt_b.MIN_LEN+i*8:rt_b.MIN_LEN+(i+1)*8])
            ip = IPAddr(ip)
            self.dn.add((ip,mask))

        self.parsed = True

    def hdr(self, payload):
        self.num = len(self.dn)
        return struct.pack('!BBHHH', self.ver, self.num, self.site, self.len, 0)

    def set_dest_nets(self, dn):
        self.dn = dn
        self.form_payload()

    def form_payload(self):
        self.num = len(self.dn)
        self.len = self.num*8

        p = b''
        for k in self.dn:
            dest, mask = k
            p += struct.pack('!LBBH', dest.toUnsigned(), mask, 0, 0)
        self.next = p

        self.parsed = True

        return p

    def add(self, ip, mask):
        if not isinstance(ip, IPAddr):
            ip = IPAddr(ip)
        self.dn.add((ip,mask))
        self.num += 1

    def remove(self, ip, mask):
        if not isinstance(ip, IPAddr):
            ip = IPAddr(ip)
        self.dn.remove((ip,mask))
        self.num -= 1

