# vim: sts=4 sw=4 et

import struct
from res import *
from ack import *
from notify import *
from data import *

from lib.packet.packet_base import packet_base
from lib.packet.packet_utils import *

class service(packet_base):
    "service packet struct"

    MIN_LEN = 4
    VER = 1

    SRVC_NONE     = 0
    SRVC_RES_REQ  = 1
    SRVC_RES_REL  = 2
    SRVC_ACK      = 3
    SRVC_NOTIFY   = 4
    SRVC_CTRL     = 5
    SRVC_DATA     = 6

    #ip_id = int(time.time())

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.ver   = service.VER
        self.type  = service.SRVC_NONE
        self.len   = 0
        self.next  = b''

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[SERVICE (v:%02x t:%s l:%s)]" % (
            self.ver,
            self.type
            self.len)

        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        dlen = len(raw)
        if dlen < service.MIN_LEN:
            self.msg('warning SERVICE packet data too short to parse header: data len %u' % (dlen,))
            return

        (self.ver, self.type, self.len) \
             = struct.unpack('!BBH', raw[:service.MIN_LEN])

        if self.v != service.VER:
            self.msg('(service parse) warning version %u not exp(%u)' % (self.v, service.VER))
            return

        # At this point, we are reasonably certain that we have an service
        # packet
        self.parsed = True

        length = self.len + service.MIN_LEN
        if length > dlen:
            length = dlen   # Clamp to what we've got
        if self.type == service.SRVC_RES_REQ or self.type == service.SRVC_RES_REL:
            self.next = res(raw=raw[service.MIN_LEN:length], prev=self)
        elif self.type == service.SRVC_ACK:
            self.next = ack(raw=raw[service.MIN_LEN:length], prev=self)
        elif self.type == service.SRVC_NOTIFY:
            self.next = notify(raw=raw[service.MIN_LEN:length], prev=self)
        elif self.type == service.SRVC_CTRL:
            self.next = rt_b(raw=raw[service.MIN_LEN:length], prev=self)
        elif self.type == service.SRVC_DATA:
            self.next = data(raw=raw[service.MIN_LEN:length], prev=self)
        elif dlen-service.MIN_LEN < self.len:
            self.msg('(service parse) warning packet data shorter than len: %u < %u' % (dlen-service.MIN_LEN, self.len))
        else:
            self.next =  raw[service.MIN_LEN:length]

        if isinstance(self.next, packet_base) and not self.next.parsed:
            self.next = raw[service.MIN_LEN:length]

    def hdr(self):
        return struct.pack('!BBH', (self.ver, self.type self.len))
