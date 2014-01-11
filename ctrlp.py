#!/bin/sh -
# vim: sts=4 sw=4 et

import subprocess
import argparse
import lib.daemon
import lib.vlog
import lib.timeval
import lib.unixctl
import lib.unixctl.server
import lib.util

from lib.stream import *
from lib.poller import *
from lib.socket_util import *
from lib.packet.ipv4 import *

from proto.ctrl_frm import *
from proto.service import *

vlog = lib.vlog.Vlog("ctrlp")
exiting = False

#import logging
#logging.basicConfig(filename='debug.vlog',level=logging.DEBUG)
#logging.basicConfig(level=logging.DEBUG)
#vlog = logging.getLogger('ctrlplane')

MYID                = 1

#VTYSH_ROUTE_CMD     = 'vtysh -c "show ip route" | grep -v "inactive" | grep -v "sat_tun" | grep "^..\*.*" | cut -d "*" -f 2 | cut -d " " -f 2'
VTYSH_ROUTE_CMD     = 'vtysh -c "show ip route"'
VTYSH_ROUTE_CMD    += ' | grep -v "inactive"'
VTYSH_ROUTE_CMD    += ' | grep -v "sat_tun"'
VTYSH_ROUTE_CMD    += ' | grep -v "127.0.0"'
VTYSH_ROUTE_CMD    += ' | grep "^..\*.*"'
VTYSH_ROUTE_CMD    += ' | cut -d "*" -f 2'
VTYSH_ROUTE_CMD    += ' | cut -d " " -f 2'
FLUSH_SAT_TUN_CMD   = 'ip route flush dev sat_tun'
TURN_ON_FORWARD     = 'echo 1 > /proc/sys/net/ipv4/ip_forward'
STATE_NOT_CONNECTED = 0
STATE_IN_PROGRESS   = 1
STATE_CONNECTED     = 2
TIMER_INTERVAL      = 500      # in ms
PROP_INTERVAL       = 20000    # in ms, propergate route info to other sites
CONN_INTERVAL       = 1000     # in ms, manage conn to other sites (actually via service host)
PARSE_HDR           = 0
PARSE_BODY          = 1

SOFT_TIMEOUT = 30
HARD_TIMEOUT = 0
CONN_TIMEOUT = 5000            # in ms

site_dic = {}                  # site_dic[remote_site] = reachable network set
state_dic = {}                 # state_dic[remote_site] = connection state
route_dic = {}                 # route_dic[(net, masknum)] = remote_site
ctrl_pkt_list = []             # queue for packet to data path
conn_dic = {}                  # remote site connection
xid_dic = {}                   # xid_dic[xid] = remote_site_num, for recogonize comm proc between
                               #     service host and i
local_route_set = set()


def enqueue_ctrl_pkt(ctrl):
    global ctrl_pkt_list 

    #print "%s"%hexdump(ctrl.pack())
    ctrl_pkt_list.append(ctrl.pack())

def rule_add(dn, site, idle, hard):
    vlog.info("add forwarding rule: %s/%d to site %d, idle:%d hard:%d"%(dn[0], dn[1], site, idle, hard))
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
    vlog.info("remove forwarding rule: to %s/%d"%(dn[0], dn[1]))
    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_RULE_RM
    ctrl.next = rule();
    ctrl.next.ip = dn[0]
    ctrl.next.mask = dn[1]
    ctrl.len = rule.MIN_LEN
    enqueue_ctrl_pkt(ctrl)

# remove route in dest net set 's' which via site 'site'
def rm_route(s, site):
    global site_dic, state_dic, route_dic

    for k in s:
        if route_dic[k] != site:  # route is not via 'site'
            continue

        # remove data path anyway
        if state_dic[site] == STATE_CONNECTED:
            rule_rm(k)
        # find out if this dest network is reachable via any other site
        find = False
        for id in site_dic:
            if k in site_dic[id]:
                find = True
                if state_dic[id] == STATE_CONNECTED:
                    rule_add(k, id, SOFT_TIMEOUT, HARD_TIMEOUT)
                route_dic[k] = id
                vlog.info("route %s/%d change from via %d to %d"%(k[0], k[1], site, id))
                break
        # if no other site reachable, just remove the static route
        # dp route will be removed when soft_to reach
        if not find:
            del route_dic[k]
            cmd = "ip route del %s/%d dev sat_tun" % (k[0], k[1])
            os.system(cmd)
            vlog.info("route removed: %s/%d"%(k[0], k[1]))

def add_route(s, id):
    global route_dic

    for k in s:
        if not k in route_dic:
            vlog.info("add route to dev sat_tun: %s/%d"%k)
            route_dic[k] = id
            cmd = "ip route add %s/%d dev sat_tun" % (k[0], k[1])
            os.system(cmd)

def process_srvc_ctrl(rt):
    global site_dic, state_dic, local_route_set

    if not isinstance(rt, packet_base) or (isinstance(rt, packet_base) and not rt.parsed):
        vlog.error("route table data is unable to be parsed")
        return
    if rt.site in site_dic:
        add_set = rt.dn - site_dic[rt.site] - local_route_set
        rm_set = site_dic[rt.site] - rt.dn - local_route_set
        if len(add_set) > 0 or len(rm_set) > 0:
            site_dic[rt.site] = rt.dn
        rm_route(rm_set, rt.site)
        add_route(add_set, rt.site)
    else:
        site_dic[rt.site] = rt.dn
        add_route(rt.dn - local_route_set, rt.site)
        state_dic[rt.site] = STATE_NOT_CONNECTED

def req_conn(site):
    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_SERVICE
    ctrl.next = service()
    ctrl.next.type = service.SRVC_RES_REQ
    ctrl.next.next = res()
    xid = ctrl.next.next.xid
    ctrl.next.next.site = site
    ctrl.next.len = res.MIN_LEN
    ctrl.len = service.MIN_LEN + ctrl.next.len
    enqueue_ctrl_pkt(ctrl)
    return xid

def srvc_ctrl():
    global local_route_set

    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_SERVICE
    ctrl.next = service()
    ctrl.next.len = service.MIN_LEN
    ctrl.next.type = service.SRVC_CTRL
    ctrl.next.next = rt_b()
    ctrl.next.next.site = MYID
    ctrl.next.next.set_dest_nets(local_route_set)
    ctrl.next.len = rt_b.MIN_LEN + ctrl.next.next.len
    ctrl.len = service.MIN_LEN + ctrl.next.len
    enqueue_ctrl_pkt(ctrl)

def lpm_route(ip_pkt):
    global state_dic, route_dic, conn_dic, xid_dic

    for cm in sorted(set(m for n,m in route_dic), reverse=True):
        v = (1 << cm) - 1
        m = v << (32-cm)
        t = (IPAddr(ip_pkt.dstip.toUnsigned() & m), cm)
        if t in route_dic:
            s = route_dic[t]
            if state_dic[s] == STATE_NOT_CONNECTED:
                xid = req_conn(s)
                xid_dic[xid] = s

                conn_dic[s] = {}
                conn_dic[s]['timestamp'] = lib.timeval.msec()
                conn_dic[s]['list'] = []
                conn_dic[s]['list'].append((ip_pkt,t))
                state_dic[s] = STATE_IN_PROGRESS
            elif state_dic[s] == STATE_IN_PROGRESS:
                conn_dic[s]['list'].append((ip_pkt,t))
            elif state_dic[s] == STATE_CONNECTED:
                rule_add(t, route_dic[t], SOFT_TIMEOUT, HARD_TIMEOUT)
            else:
                vlog.error("unknown site state")
            return

def process_packet_in(inp):
    if not isinstance(inp, packet_base) or (isinstance(inp, packet_base) and not inp.parsed):
        vlog.error("pkt_in packet is unable to be parsed")
        return
    #print hexdump(inp.payload)
    ip_pkt = ipv4(inp.payload)
    if not ip_pkt.parsed:
        vlog.error("pkt_in data is not a ipv4 packet")
        return
    lpm_route(ip_pkt)

def process_srvc_ack(a):
    global state_dic, route_dic, conn_dic, xid_dic

    if not isinstance(a, packet_base) or (isinstance(a, packet_base) and not a.parsed):
        vlog.error("ack pkt is unable to be parsed")
        return
    if not a.xid in xid_dic:
        vlog.error("xid is not expected(%d)" % a.xid)
        return

    xid = a.xid
    site = xid_dic[xid]
    if a.result == ack.SRVC_RSLT_ERR:
        vlog.warn("conn to site(%d) failed" % site)
        state_dic[site] = STATE_NOT_CONNECTED
    elif a.result == ack.SRVC_RSLT_OK:
        for pkt,t in conn_dic[site]['list']:
            rule_add(t, route_dic[t], SOFT_TIMEOUT, HARD_TIMEOUT)
        state_dic[site] == STATE_CONNECTED
    else:
        vlog.error("ack result's unknown(%d)" % a.result)
    del xid_dic[xid]
    state_dic[site] = STATE_NOT_CONNECTED
    del conn_dic[site]

def process_srvc_notify(n):
    vlog.warn("process_srvc_notify not implemente yet")
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
                vlog.error("cant parse this kind of service pkt:%d" % s.type)
        else:
            vlog.error("cant parse service payload")
    else:
        vlog.error("should not recv this type:%d" % ctrl.type)

def get_local_route_set():
    global local_route_set

    proc = subprocess.Popen(VTYSH_ROUTE_CMD,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True)
    out,err = proc.communicate()
    if not '/' in out:
        vlog.warn("no route found")
        return
    nets = out.split("\n")
    route_set = set()
    for net in nets:
        if len(net) == 0:
            continue
        ip,mask = net.split("/")
        route_set.add((IPAddr(ip), int(mask)))
    local_route_set = route_set

def propergate_route():
    get_local_route_set()
    srvc_ctrl()

def chk_sites(now):
    global state_dic, conn_dic, xid_dic

    for s in set(x for x in conn_dic):
        if now > conn_dic[s]['timestamp'] + CONN_TIMEOUT:
            vlog.warn("request timeout, drop(site=%d, %d pkt(s))..."%(s, len(conn_dic[s]['list'])))
            state_dic[s] = STATE_NOT_CONNECTED
            del conn_dic[s]
            for xid in set(x for x in xid_dic):
                if xid_dic[xid] == s:
                    del xid_dic[xid]

def process_timer():
    now = lib.timeval.msec()
    if now > process_timer.prop_tmr_expire:
        propergate_route()
        process_timer.prop_tmr_expire = now + PROP_INTERVAL
    if now > process_timer.conn_tmr_expire:
        chk_sites(now)
        process_timer.conn_tmr_expire = now + CONN_INTERVAL
process_timer.prop_tmr_expire = 0
process_timer.conn_tmr_expire = 0

def send_out_ququed_pkt(conn):
    global ctrl_pkt_list 

    for p in ctrl_pkt_list:
        conn.send(p)
        ctrl_pkt_list.remove(p)

def unixctl_exit(conn, unused_argv, aux):
    assert aux == "aux_exit"
    global exiting

    exiting = True
    conn.reply(None)

def unixctl_log(conn, argv, unused_aux):
    vlog.info(str(argv[0]))
    conn.reply(None)

def main():
    global site_dic, state_dic, route_dic, ctrl_pkt_list, conn_dic, xid_dic

    parser = argparse.ArgumentParser(
        description="IPGW ctrlp: control plane for IP access gateway")
    parser.add_argument("--unixctl", help="UNIXCTL socket location or 'none'.")
    lib.daemon.add_args(parser)
    lib.vlog.add_args(parser)
    args = parser.parse_args()
    lib.daemon.handle_args(args)
    lib.vlog.handle_args(args)

    lib.daemon.daemonize_start()
    error, unixctl_srvr = lib.unixctl.server.UnixctlServer.create(args.unixctl)
    if error:
        lib.util.ovs_fatal(error, "could not create unixctl server at %s"
                           % args.unixctl, vlog)
    lib.unixctl.command_register("exit", "", 0, 0, unixctl_exit, "aux_exit")
    lib.unixctl.command_register("log", "[arg ...]", 1, 2, unixctl_log, None)
    lib.daemon.daemonize_complete()

    poller = Poller()
    error, server = PassiveStream.open("punix:/tmp/ctrl.sock")
    hdr = ctrl_frm()
    connected = False
    pkt = b''
    exp_len = ctrl_frm.MIN_LEN
    parse_state = PARSE_HDR
    poller.timer_wait(TIMER_INTERVAL)
    vlog.info("ctrlplane started...")
    while not exiting:
        if not connected:
            error, conn = server.accept()
            if conn == None:
                server.wait(poller)
            else:
                vlog.info("connection established...")
                vlog.info("flush sat_tun, init...")
		os.system(FLUSH_SAT_TUN_CMD)
                site_dic = {}
                state_dic = {}
                route_dic = {}
                ctrl_pkt_list = []
                conn_dic = {}
                xid_dic = {}
                get_local_route_set()
                vlog.info("turn on ip forward...")
                os.system(TURN_ON_FORWARD)

                connected = True
        if connected:
            error, data = conn.recv(exp_len-len(pkt))
            if (error, data) == (0, ""):
                vlog.info("connection closed...")
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
                            vlog.warn("parse hdr failed. close conn...")
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

            process_timer()

        if connected:
            send_out_ququed_pkt(conn)

        poller.timer_wait(TIMER_INTERVAL)

        unixctl_srvr.run()
        unixctl_srvr.wait(poller)
        if exiting:
            poller.immediate_wake()

        poller.block()
    

if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        # Let system.exit() calls complete normally
        raise
    except:
        vlog.exception("traceback")
        sys.exit(lib.daemon.RESTART_EXIT_CODE)
