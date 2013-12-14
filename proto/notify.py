# vim: sts=4 sw=4 et

import struct

from lib.packet.packet_base import packet_base
from lib.packet.packet_utils import *

class notify(packet_base):
    "notify packet struct"

    MIN_LEN = 4

    SRVC_NOTIFY_NONE    = 0
    SRVC_NOTIFY_LOGOUT  = 1
    SRVC_NOTIFY_ERR     = 2

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.site = 0
        self.type = notify.SRVC_NOTIFY_NONE

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[NOTIFY: s:%s t:%02x]' % (self.site, self.type)
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < notify.MIN_LEN:
            self.msg('(notify parse) warning packet notify too short to parse header: notify len %u' % dlen)
            return

        (self.site, self.type, _) \
            = struct.unpack('!HBB', raw[:notify.MIN_LEN])

        self.parsed = True

    def hdr(self, payload):
        return struct.pack('!HBB',self.site, self.type, 0)
