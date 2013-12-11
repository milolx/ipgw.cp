#!/bin/sh -
# vim: sts=4 sw=4 et

import subprocess

from lib.daemon import *
from lib.vlog import *
from lib.stream import *
from lib.poller import *

from proto.ctrl_frm import *

STATE_NOT_CONNECTED = 0
STATE_IN_PROGRESS   = 1
STATE_CONNECTED     = 2

SOFT_TIMEOUT = 30
HARD_TIMEOUT = 0

site_dic = {}
state_dic = {}
route_dic = {}
ctrl_pkt_list = []

def enqueue_ctrl_pkt(ctrl):
    ctrl_pkt_list.append(ctrl.pack())

def rule_add(dn, site, idle, hard)
    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_RULE_ADD
    ctrl.next = rule();
    ctrl.next.ip = dn[0]
    ctrl.next.mask = dn[1]
    ctrl.next.site = site
    ctrl.next.idle_to = idle
    ctrl.next.hard_to = hard
    ctrl.len = rule.MIN_LEN
    enqueue_ctrl_pkt(ctrl)

def rule_rm(dn)
    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_RULE_RM
    ctrl.next = rule();
    ctrl.next.ip = dn[0]
    ctrl.next.mask = dn[1]
    ctrl.len = rule.MIN_LEN
    enqueue_ctrl_pkt(ctrl)

def rm_route(s, id):
    for k in s:
        if route_dic[k] != id:  # route is not via id
            continue

        # find out if this dest network is reachable via any other site
        find = False
        for id in site_dic:
            if k in site_dic[id]:
                find = True
                if state_dic[route_dic[k]] == STATE_CONNECTED:
                    rule_rm(k)
                if state_dic[id] == STATE_CONNECTED:
                    rule_add(k, id, SOFT_TIMEOUT, HARD_TIMEOUT)
                route_dic[k] = id
                break
        # if no other site reachable, just remove the static route
        # dp route will be removed when soft_to reach
        if not find:
            del route_dic[k]
            cmd = "ip route del %s/%d dev tun0" % (k[0], k[1])
            os.system(cmd)

def add_route(s, id):
    for k in s:
        if not k in route_dic:
            route_dic[k] = id
            cmd = "ip route add %s/%d dev tun0" % (k[0], k[1])
            os.system(cmd)

def process_srvc_ctrl(rt):
    if not isinstance(rt, packet_base) or (isinstance(rt, packet_base) and not rt.parsed):
        print "Err:route table data is unable to be parsed"
        return
    if rt.id in site_dic:
        add_set = rt.dn - site_dic[rt.id]
        rm_set = site_dic[rt.id] - rt.dn
        if len(add_set) > 0 or len(rm_set) > 0:
            site_dic[rt.id] = rt.dn
        rm_route(rm_set, rt.id)
        add_route(add_set, rt.id)
    else:
        site_dic[rt.id] = rt.dn
        add_route(rt.dn, rt.id)
        state_dic[rt.id] = STATE_NOT_CONNECTED

def req_conn(site):
    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_RULE_RM
    ctrl.next = res();
    ctrl.next.site = site
    ctrl.len = res.MIN_LEN
    enqueue_ctrl_pkt(ctrl)

def lpm_route(ip_pkt):
    for cm in sorted(set(m for n,m in route_dic), reverse=True):
        m = (1 << cm) - 1
        m = v << (32-cm)
        t = (ip_pkt.dstip.toUnsigned() & m, cm)
        if t in route_dic:
            s = route_dic[t]
            if state_dic[s] == STATE_NOT_CONNECTED:
                req_conn(s)
            elif state_dic[s] == STATE_IN_PROGRESS:
                pass
            elif state_dic[s] == STATE_CONNECTED:
                rule_add(t, route_dic[t], SOFT_TIMEOUT, HARD_TIMEOUT)
            else:
                print "Err: unknown site state"
            return

def process_packet_in(inp):
    if not isinstance(inp, packet_base) or (isinstance(inp, packet_base) and not inp.parsed):
        print "Err:pkt_in packet is unable to be parsed"
        return
    ip_pkt = ipv4(inp.payload)
    if ip_pkt.parsed:
        print "Err:pkt_in data is not a ipv4 packet"
        return
    lpm_route(ip_pkt)

def process_srvc_ack(a):
    pass

def process_srvc_notify(n):
    pass

def process_in(ctrl):
    if ctrl.type == ctrl_frm.IPGW_PACKET_IN:
        process_packet_in(ctrl.next)
    elif ctrl.type == ctrl_frm.IPGW_SERVICE:
        s = ctrl.next
        if s.type == service.SRVC_ACK:
            process_srvc_ack(s.next)
        elif s.type == service.SRVC_NOTIFY:
            process_srvc_notify(s.next)
        elif s.type == service.SRVC_CTRL:
            process_srvc_ctrl(s.next)
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
                process_in(ctrl)
            conn.recv_wait(poller)
        poller.block()
        print "unblocked..."
    

if __name__ == '__main__':
    main()
