#!/bin/sh -
# vim: sts=4 sw=4 et

import socket
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

#from lib.addresses import IPAddr, IP_ANY, IP_BROADCAST

TIMER_INTERVAL = 2000

def get_exception_errno(e):
    """A lot of methods on Python socket objects raise socket.error, but that
    exception is documented as having two completely different forms of
    arguments: either a string or a (errno, string) tuple.  We only want the
    errno."""
    if type(e.args) == tuple:
        return e.args[0]
    else:
        return errno.EPROTO

def set_nonblocking(sock):
    try:
        sock.setblocking(0)
    except socket.error, e:
        vlog.err("could not set nonblocking mode on socket: %s"
                 % os.strerror(get_exception_errno(e)))

def inet_open_dgram(default_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    except socket.error, e:
        return get_exception_errno(e), None

    try:
        set_nonblocking(sock)
        return 0, sock
    except socket.error, e:
        sock.close()
        return get_exception_errno(e), None

def main():
    lib.vlog.Vlog.init()
    #set_detach()
    #set_monitor()
    daemonize_start()
    daemonize_complete()

    '''
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

    '''
    srvc = service()
    srvc.type = service.SRVC_DATA
    srvc.next = data()
    srvc.next.to_site = 1234
    srvc.len = data.MIN_LEN + srvc.next.len
    '''

    srvc = service()
    srvc.type = service.SRVC_CTRL
    srvc.next = rt_b()
    srvc.next.add("172.16.0.0",16)
    srvc.next.add("192.168.0.0",24)
    srvc.next.add("10.128.0.0",9)
    srvc.next.form_payload()
    srvc.len = rt_b.MIN_LEN + srvc.next.len

    poller = Poller()
    connected = False
    #pkt = b''
    timer_expire = timeval.msec() + TIMER_INTERVAL
    poller.timer_wait(TIMER_INTERVAL)
    while True:
        if not connected:
            #err, conn = Stream.open("unix:/tmp/ctrl.sock")
            err, conn = inet_open_dgram(9999)
            if conn != None:
                connected = True
        if connected:
            #e = conn.send(ctrl.pack())
            #e = conn.sendto(ctrl.pack(), ("10.0.8.66",6667))
            e = conn.sendto(srvc.pack(), ("10.0.8.66",6667))
            #print "len=%d"%len(ctrl.pack())
            #hexdump(ctrl.pack())
            hexdump(srvc.pack())
            #hex_chars = map(hex, map(ord,ctrl.pack()))
            #print "pkt->%s",hex_chars
            #print "send out->%d"%e
            if e < 0:
                print "err->%d"%e

        #conn.recv_wait(poller)

        if timeval.msec() >= timer_expire:
            timer_expire = timeval.msec() + TIMER_INTERVAL
            poller.timer_wait(TIMER_INTERVAL)
            print "timer..."

        poller.block()
        print "unblocked..."
    

if __name__ == '__main__':
    main()
