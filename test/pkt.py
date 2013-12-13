#!/bin/sh -
# vim: sts=4 sw=4 et

import subprocess
import logging
logging.basicConfig()

from lib.daemon import *
from lib.vlog import *
from lib.stream import *
from lib.poller import *
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
    ctrl.next.type = service.SRVC_ACK
    ctrl.next.next = ack()
    xid = ctrl.next.next
    ctrl.next.next.result = ack.SRVC_RSLT_OK
    ctrl.next.len = ack.MIN_LEN
    ctrl.len = service.MIN_LEN + ctrl.next.len

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
            if e < 0:
                print e

        #conn.recv_wait(poller)

        #if timeval.msec() >= timer_expire:
        #    timer_expire = timeval.msec() + TIMER_INTERVAL
        #    poller.timer_wait(TIMER_INTERVAL)
        #    print "timer..."

        poller.block()
        print "unblocked..."
    

if __name__ == '__main__':
    main()
