#!/bin/sh -
# vim: sts=4 sw=4 et

import subprocess
import logging
logging.basicConfig()

from lib.daemon import *
from lib.vlog import *
from lib.stream import *
from lib.poller import *
from lib.dbg import *
from lib import timeval

from proto.ctrl_frm import *
from proto.service import *

TIMER_INTERVAL = 2000

def main():
    lib.vlog.Vlog.init()
    #set_detach()
    #set_monitor()
    daemonize_start()
    daemonize_complete()

    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_SERVICE
    ctrl.next = service()
    ctrl.next.type = service.SRVC_CTRL
    ctrl.next.next = rt_b()
    ctrl.next.next.site = 1234
    dn = set()
    dn.add((IPAddr('172.16.0.0'),16))
    dn.add((IPAddr('10.6.0.0'),18))
    dn.add((IPAddr('192.168.1.0'),24))
    ctrl.next.next.set_dest_nets(dn)
    print ctrl.next.next
    print ctrl.next.next.len
    ctrl.next.len = rt_b.MIN_LEN + ctrl.next.next.len
    ctrl.len = service.MIN_LEN + ctrl.next.len
    print ctrl.len

    '''
    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_SERVICE
    ctrl.next = service()
    ctrl.next.type = service.SRVC_DATA
    ctrl.next.next = data()
    ctrl.next.next.to_site = 1234
    ctrl.next.len = data.MIN_LEN + ctrl.next.next.len
    ctrl.len = service.MIN_LEN + ctrl.next.len
    '''

    poller = Poller()
    connected = False
    #pkt = b''
    #timer_expire = timeval.msec() + TIMER_INTERVAL
    #poller.timer_wait(TIMER_INTERVAL)
    while True:
        if not connected:
            err, conn = Stream.open("unix:/tmp/ctrl.sock")
            if conn != None:
                connected = True
        if connected:
            e = conn.send(ctrl.pack())
            print "len=%d"%len(ctrl.pack())
            hexdump(ctrl.pack())
            #hex_chars = map(hex, map(ord,ctrl.pack()))
            #print "pkt->%s",hex_chars
            #print "send out->%d"%e
            if e < 0:
                print "err->%d"%e

        #conn.recv_wait(poller)

        #if timeval.msec() >= timer_expire:
        #    timer_expire = timeval.msec() + TIMER_INTERVAL
        #    poller.timer_wait(TIMER_INTERVAL)
        #    print "timer..."

        poller.block()
        print "unblocked..."
    

if __name__ == '__main__':
    main()
