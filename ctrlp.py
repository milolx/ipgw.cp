#!/bin/sh -
# vim: sts=4 sw=4 et

from lib.daemon import *
from lib.vlog import *
from lib.stream import *
from lib.poller import *

from proto.ctrl_frm import *

route_table = set()

def parse_in(ctrl):
    if ctrl.type == ctrl_frm.IPGW_PACKET_IN:
    elif ctrl.type == ctrl_frm.IPGW_SERVICE:
        s = ctrl.next
        if s.type == service.SRVC_ACK:
            pass
        elif s.type == service.SRVC_NOTIFY:
            pass
        elif s.type == service.SRVC_CTRL:
            rt = s.next
            if isinstance(rt, packet_base) and not rt.parsed:
                print "Err:route table data is unable to be parsed"
    else:
        print "Err: should not recv this type:%d" % ctrl.type

def main():
    lib.vlog.Vlog.init()
    #set_detach()
    #set_monitor()
    daemonize_start()
    daemonize_complete()

    poller = Poller()
    error, server = PassiveStream.open("punix:/tmp/ctrl.sock")
    connected = False
    pkt = b''
    exp_len = ctrl_frm.MIN_LEN
    while True:
        if not connected:
            error, conn = server.accept()
            print conn
            if conn == None:
                server.wait(poller)
            else:
                connected = True
        if connected:
            error, data = conn.recv(exp_len-len(pkt))
            pkt += data
            if len(pkt) == ctrl_frm.MIN_LEN:
                hdr = ctrl_frm(pkt)
                if hdr.parsed:
                    exp_len = ctrl_frm.MIN_LEN + hdr.len
            elif len(pkt) == exp_len:
                ctrl = ctrl_frm(pkt)
                pkt = b''
                exp_len = ctrl_frm.MIN_LEN
                parse_in(ctrl)
            conn.recv_wait(poller)
        poller.block()
        print "unblocked..."
    

if __name__ == '__main__':
    main()
