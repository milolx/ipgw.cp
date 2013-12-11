# vim: sts=4 sw=4 et

import struct
from pkt_in import *
from rule import *
from ctrl_frm import *

from lib.packet.packet_base import packet_base
from lib.packet.packet_utils import *

class ctrl_frm(packet_base):
    "ctrl_frm packet struct"

    MIN_LEN = 4
    VER = 1

    IPGW_NONE       = 0
    IPGW_PACKET_IN  = 1
    IPGW_RULE_ADD   = 2
    IPGW_RULE_RM    = 3
    IPGW_SERVICE    = 4

    #ip_id = int(time.time())

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.ver   = ctrl_frm.VER
        self.type  = ctrl_frm.IPGW_NONE
        self.len   = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[CTRL (v:%02x t:%s l:%s x:%02x)]" % (
            self.ver,
            self.type,
            self.len)

        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        dlen = len(raw)
        if dlen < ctrl_frm.MIN_LEN:
            self.msg('warning CTRL packet data too short to parse header: data len %u' % (dlen,))
            return

        (self.ver, self.type, self.len) \
             = struct.unpack('!BBH', raw[:ctrl_frm.MIN_LEN])

        if self.v != ctrl_frm.VER:
            self.msg('(ctrl_frm parse) warning version %u not exp(%u)' % (self.v, ctrl_frm.VER))
            return

        # At this point, we are reasonably certain that we have an ctrl_frm
        # packet
        self.parsed = True

        length = self.len + ctrl_frm.MIN_LEN
        if length > dlen:
            length = dlen   # Clamp to what we've got
        if self.type == ctrl_frm.IPGW_PACKET_IN:
            self.next = pkt_in(raw=raw[ctrl_frm.MIN_LEN:length], prev=self)
        elif self.type == ctrl_frm.IPGW_RULE_ADD or self.type == ctrl_frm.IPGW_RULE_RM:
            self.next = rule(raw=raw[ctrl_frm.MIN_LEN:length], prev=self)
        elif self.type == ctrl_frm.IPGW_SERVICE:
            self.next = service(raw=raw[ctrl_frm.MIN_LEN:length], prev=self)
        elif dlen - ctrl_frm.MIN_LEN < self.len:
            self.msg('(ctrl_frm parse) warning packet data shorter than len: %u < %u' % (dlen-ctrl_frm.MIN_LEN, self.len))
        else:
            self.next =  raw[ctrl_frm.MIN_LEN:length]

        if isinstance(self.next, packet_base) and not self.next.parsed:
            self.next = raw[ctrl_frm.MIN_LEN:length]

    def hdr(self):
        return struct.pack('!BBH', (self.ver, self.type self.len))
