#!/bin/sh -
# vim: sts=4 sw=4 et

import subprocess
import logging
#logging.basicConfig(filename='debug.log',level=logging.DEBUG)
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('ctrlplane')

from lib.daemon import *
from lib.vlog import *
from lib.stream import *
from lib.poller import *
from lib.socket_util import *
from lib import timeval

from proto.ctrl_frm import *
from proto.service import *

MYID                = 1

VTYSH_ROUTE_CMD     = 'vtysh -c "show ip route" | sed -n "/^..\*.*/p" | cut -d "*" -f 2 | cut -d " " -f 2'
STATE_NOT_CONNECTED = 0
STATE_IN_PROGRESS   = 1
STATE_CONNECTED     = 2
TIMER_INTERVAL      = 5000     # in ms
PARSE_HDR           = 0
PARSE_BODY          = 1

SOFT_TIMEOUT = 30
HARD_TIMEOUT = 0

site_dic = {}
state_dic = {}
route_dic = {}
ctrl_pkt_list = []
conn_dic = {}
xid_dic = {}

def enqueue_ctrl_pkt(ctrl):
    ctrl_pkt_list.append(ctrl.pack())

def rule_add(dn, site, idle, hard):
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

def rule_rm(dn):
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
            cmd = "ip route del %s/%d dev sat_tun" % (k[0], k[1])
            os.system(cmd)

def add_route(s, id):
    for k in s:
        if not k in route_dic:
            route_dic[k] = id
            cmd = "ip route add %s/%d dev sat_tun" % (k[0], k[1])
            os.system(cmd)

def process_srvc_ctrl(rt):
    if not isinstance(rt, packet_base) or (isinstance(rt, packet_base) and not rt.parsed):
        log.error("route table data is unable to be parsed")
        return
    if rt.site in site_dic:
        add_set = rt.dn - site_dic[rt.site]
        rm_set = site_dic[rt.site] - rt.dn
        if len(add_set) > 0 or len(rm_set) > 0:
            site_dic[rt.site] = rt.dn
        rm_route(rm_set, rt.site)
        add_route(add_set, rt.site)
    else:
        site_dic[rt.site] = rt.dn
        add_route(rt.dn, rt.site)
        state_dic[rt.site] = STATE_NOT_CONNECTED

def req_conn(site):
    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_SERVICE
    ctrl.next = service()
    ctrl.next.type = service.SRVC_RES_REQ
    ctrl.next.next = res()
    xid = ctrl.next.next
    ctrl.next.next.site = site
    ctrl.next.len = res.MIN_LEN
    ctrl.len = service.MIN_LEN + ctrl.next.len
    enqueue_ctrl_pkt(ctrl)
    return xid

def srvc_ctrl(n):
    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_SERVICE
    ctrl.next = service()
    ctrl.next.len = service.MIN_LEN
    ctrl.next.next = rt_b()
    ctrl.next.next.id = MYID
    ctrl.next.next.set_dest_nets(n)
    ctrl.next.len = rt_b.MIN_LEN + ctrl.next.next.len
    ctrl.len = service.MIN_LEN + ctrl.next.len
    enqueue_ctrl_pkt(ctrl)

def lpm_route(ip_pkt):
    for cm in sorted(set(m for n,m in route_dic), reverse=True):
        m = (1 << cm) - 1
        m = v << (32-cm)
        t = (ip_pkt.dstip.toUnsigned() & m, cm)
        if t in route_dic:
            s = route_dic[t]
            if state_dic[s] == STATE_NOT_CONNECTED:
                xid = req_conn(s)
                xid_dic[xid] = s

                conn_dic[s] = {}
                conn_dic[s]['timestamp'] = timeval.msec()
                conn_dic[s]['list'] = []
                conn_dic[s]['list'].append((ip_pkt,t))
                state_dic[site] = STATE_IN_PROGRESS
            elif state_dic[s] == STATE_IN_PROGRESS:
                conn_dic[s]['list'].append((ip_pkt,t))
            elif state_dic[s] == STATE_CONNECTED:
                rule_add(t, route_dic[t], SOFT_TIMEOUT, HARD_TIMEOUT)
            else:
                log.error("unknown site state")
            return

def process_packet_in(inp):
    if not isinstance(inp, packet_base) or (isinstance(inp, packet_base) and not inp.parsed):
        log.error("pkt_in packet is unable to be parsed")
        return
    ip_pkt = ipv4(inp.payload)
    if ip_pkt.parsed:
        log.error("pkt_in data is not a ipv4 packet")
        return
    lpm_route(ip_pkt)

def process_srvc_ack(a):
    if not isinstance(a, packet_base) or (isinstance(a, packet_base) and not a.parsed):
        log.error("ack pkt is unable to be parsed")
        return
    if not a.xid in xid_dic:
        log.error("xid is not expected(%d)" % a.xid)
        return

    xid = a.xid
    site = xid_dic[xid]
    if a.result == ack.SRVC_RSLT_ERR:
        log.warning("conn to site(%d) failed" % site)
        state_dic[site] = STATE_NOT_CONNECTED
    elif a.result == ack.SRVC_RSLT_OK:
        for pkt,t in conn_dic[site]['list']:
            rule_add(t, route_dic[t], SOFT_TIMEOUT, HARD_TIMEOUT)
        state_dic[site] == STATE_CONNECTED
    else:
        log.error("ack result's unknown(%d)" % a.result)
    xid_dic.remove(xid)
    conn_dic.remove(site)

def process_srvc_notify(n):
    log.warning("process_srvc_notify not implemente yet")
    pass

def process_in(ctrl):
    if ctrl.type == ctrl_frm.IPGW_PACKET_IN:
        process_packet_in(ctrl.next)
    elif ctrl.type == ctrl_frm.IPGW_SERVICE:
        s = ctrl.next
        if isinstance(s, service):
            if s.type == service.SRVC_ACK:
                process_srvc_ack(s.next)
            elif s.type == service.SRVC_NOTIFY:
                process_srvc_notify(s.next)
            elif s.type == service.SRVC_CTRL:
                process_srvc_ctrl(s.next)
            else:
                log.error("cant parse this kind of service pkt:%d" % s.type)
        else:
            log.error("cant parse service payload")
    else:
        log.error("should not recv this type:%d" % ctrl.type)

def process_timer():
    proc = subprocess.Popen(VTYSH_ROUTE_CMD,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True)
    out,err = proc.communicate()
    if not '/' in out:
        log.warning("no route found")
        return
    nets = out.split("\n")
    reachable_set = set()
    for net in nets:
        if len(net) == 0:
            continue
        ip,mask = net.split("/")
        reachable_set.add((IPAddr(ip), mask))
    srvc_ctrl(reachable_set)

def send_out_ququed_pkt(conn):
    for p in ctrl_pkt_list:
        conn.send(p)
        ctrl_pkt_list.remove(p)

def main():
    lib.vlog.Vlog.init()
    #set_detach()
    #set_monitor()
    daemonize_start()
    daemonize_complete()

    poller = Poller()
    error, server = PassiveStream.open("punix:/tmp/ctrl.sock")
    hdr = ctrl_frm()
    connected = False
    pkt = b''
    exp_len = ctrl_frm.MIN_LEN
    parse_state = PARSE_HDR
    timer_expire = timeval.msec() + TIMER_INTERVAL
    poller.timer_wait(TIMER_INTERVAL)
    while True:
        if not connected:
            error, conn = server.accept()
            if conn == None:
                server.wait(poller)
            else:
                log.warning("connection established...")
                connected = True
        if connected:
            error, data = conn.recv(exp_len-len(pkt))
            if len(data) > 0:
                log.debug("exp %d read %d, get %d" % (exp_len, exp_len-len(pkt), len(data)))
            if (error, data) == (0, ""):
                log.warning("connection closed...")
                conn.close()
                connected = False
                pkt = b''
                exp_len = ctrl_frm.MIN_LEN
                parse_state = PARSE_HDR
                poller.immediate_wake()
            elif len(data) > 0:
                pkt += data
                if len(pkt) == exp_len:
                    if parse_state == PARSE_HDR:
                        hdr.parse(pkt, headOnly=True)
                        if hdr.parsed:
                            exp_len = ctrl_frm.MIN_LEN + hdr.len
                            parse_state = PARSE_BODY
                        else:
                            log.warning("parse hdr failed. close conn...")
                            conn.close()
                            connected = False
                            pkt = b''
                            exp_len = ctrl_frm.MIN_LEN
                            parse_state = PARSE_HDR
                    elif parse_state == PARSE_BODY:
                        ctrl = ctrl_frm(pkt)
                        process_in(ctrl)

                        pkt = b''
                        exp_len = ctrl_frm.MIN_LEN
                        parse_state = PARSE_HDR

                    poller.immediate_wake()

                conn.recv_wait(poller)
                send_out_ququed_pkt(conn)

        if timeval.msec() >= timer_expire:
            timer_expire = timeval.msec() + TIMER_INTERVAL
            process_timer()

        if connected:
            send_out_ququed_pkt(conn)

        poller.timer_wait(1000)
        poller.block()
    

if __name__ == '__main__':
    main()
