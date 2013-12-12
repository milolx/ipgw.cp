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

TIMER_INTERVAL = 2000

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
    timer_expire = timeval.msec() + TIMER_INTERVAL
    poller.timer_wait(TIMER_INTERVAL)
    while True:
        if not connected:
            error, conn = server.accept()
            if conn == None:
                server.wait(poller)
            else:
                connected = True
        print "hello"
        if connected:
            error, data = conn.recv(exp_len-len(pkt))
            pkt += data
            if len(pkt) == 8:
                print pkt

            conn.recv_wait(poller)

        if timeval.msec() >= timer_expire:
            timer_expire = timeval.msec() + TIMER_INTERVAL
            poller.timer_wait(TIMER_INTERVAL)
            print "timer..."

        poller.block()
        print "unblocked..."
    

if __name__ == '__main__':
    main()
