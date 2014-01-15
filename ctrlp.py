#!/bin/sh -
# vim: sts=4 sw=4 et

import subprocess
import argparse
import json
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
CFG_FILE            = '/mnt/app_part/ipgw/cp.cfg'
STATE_NOT_CONNECTED = 0
STATE_IN_PROGRESS   = 1
STATE_CONNECTED     = 2
TIMER_INTERVAL      = 500      # in ms
PROP_INTERVAL       = 20000    # in ms, propergate route info to other sites
CHECK_INTERVAL      = 1000     # in ms, manage conn to other sites (actually via service host)
PARSE_HDR           = 0
PARSE_BODY          = 1
ID_RANGE            = range(0, 65536)
PROP_INTVL_RANGE    = range(5, 121)
SITE_TIMEOUT_RANGE  = range(10, 1201)
SOFT_TIMEOUT_RANGE  = range(2, 3601)
HARD_TIMEOUT_RANGE  = range(0, 86401)   # 0 means permanent, max=24h
CONN_REQ_TIMEOUT_RANGE  = range(1, 31)

SOFT_TIMEOUT = 30
HARD_TIMEOUT = 600

CONN_REQ_TIMEOUT = 5000         # in ms
SITE_TIMEOUT = 45000            # in ms

site_id = -1
prop_intvl = PROP_INTERVAL
conn_req_timeout = CONN_REQ_TIMEOUT
site_timeout = SITE_TIMEOUT
soft_timeout = SOFT_TIMEOUT
hard_timeout = HARD_TIMEOUT

site_dic = {}                   # site_dic[remote_site]['rn'] = reachable network set
                                # site_dic[remote_site]['state'] = connection state
route_dic = {}                  # route_dic[(net, masknum)] = remote_site
ctrl_pkt_list = []              # queue for packet to data path
conn_dic = {}                   # dic to store data while request in progress
                                # conn_dic[remote_site]['...'] = ...
xid_dic = {}                    # xid_dic[xid] = remote_site_num, for recogonize comm proc between
                                #     service host and i
local_route_set = set()


def cur_timestamp():
    return lib.timeval.msec()

def enqueue_ctrl_pkt(ctrl):
    global ctrl_pkt_list 

    #print "%s"%hexdump(ctrl.pack())
    ctrl_pkt_list.append(ctrl.pack())

def rule_add(dn, site, idle, hard):
    vlog.info("add forwarding rule: %s/%d via site %d, idle:%d hard:%d"%(dn[0], dn[1], site, idle, hard))
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
    vlog.info("remove forwarding rule: %s/%d"%(dn[0], dn[1]))
    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_RULE_RM
    ctrl.next = rule();
    ctrl.next.ip = dn[0]
    ctrl.next.mask = dn[1]
    ctrl.len = rule.MIN_LEN
    enqueue_ctrl_pkt(ctrl)

# remove route in dest net set 's' which via site 'site'
def rm_route(s, site):
    global route_dic

    for k in s:
        if route_dic[k] != site:  # route is not via 'site'
            continue

        # remove data path anyway
        if site_dic[site]['state'] == STATE_CONNECTED:
            rule_rm(k)
        # find out if this dest network is reachable via any other site
        find = False
        for id in site_dic:
            if k in site_dic[id]['rn']:
                find = True
                if site_dic[id]['state'] == STATE_CONNECTED:
                    rule_add(k, id, soft_timeout, hard_timeout)
                route_dic[k] = id
                vlog.info("route %s/%d change from via %d to site(%d)"%(k[0], k[1], site, id))
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
    global site_dic

    if not isinstance(rt, packet_base) or (isinstance(rt, packet_base) and not rt.parsed):
        vlog.error("route table data is unable to be parsed")
        return
    if rt.site in site_dic:
        # update timestamp & routes in site_dic
        site_dic[rt.site]['timestamp'] = cur_timestamp()
        add_set = rt.dn - site_dic[rt.site]['rn'] - local_route_set
        rm_set = site_dic[rt.site]['rn'] - rt.dn - local_route_set
        if len(add_set) > 0 or len(rm_set) > 0:
            site_dic[rt.site]['rn'] = rt.dn
        rm_route(rm_set, rt.site)
        add_route(add_set, rt.site)
    else:
        # create item in site_dic
        site_dic[rt.site] = {}
        site_dic[rt.site]['rn'] = rt.dn
        add_route(rt.dn - local_route_set, rt.site)
        site_dic[rt.site]['state'] = STATE_NOT_CONNECTED
        site_dic[rt.site]['timestamp'] = cur_timestamp()

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
    ctrl = ctrl_frm();
    ctrl.type = ctrl_frm.IPGW_SERVICE
    ctrl.next = service()
    ctrl.next.len = service.MIN_LEN
    ctrl.next.type = service.SRVC_CTRL
    ctrl.next.next = rt_b()
    ctrl.next.next.site = site_id
    ctrl.next.next.set_dest_nets(local_route_set)
    ctrl.next.len = rt_b.MIN_LEN + ctrl.next.next.len
    ctrl.len = service.MIN_LEN + ctrl.next.len
    enqueue_ctrl_pkt(ctrl)

def lpm_route(ip_pkt):
    global site_dic, conn_dic, xid_dic

    for cm in sorted(set(m for n,m in route_dic), reverse=True):
        v = (1 << cm) - 1
        m = v << (32-cm)
        t = (IPAddr(ip_pkt.dstip.toUnsigned() & m), cm)
        if t in route_dic:
            s = route_dic[t]
            if site_dic[s]['state'] == STATE_NOT_CONNECTED:
                xid = req_conn(s)
                xid_dic[xid] = s

                conn_dic[s] = {}
                conn_dic[s]['timestamp'] = cur_timestamp()
                conn_dic[s]['list'] = []
                # save the first pkt and routing decision
                conn_dic[s]['list'].append((ip_pkt,t))
                site_dic[s]['state'] = STATE_IN_PROGRESS
            elif site_dic[s]['state'] == STATE_IN_PROGRESS:
                # save the first pkt and routing decision
                conn_dic[s]['list'].append((ip_pkt,t))
            elif site_dic[s]['state'] == STATE_CONNECTED:
                # just place a rule in data path
                rule_add(t, s, soft_timeout, hard_timeout)
            else:
                vlog.error("unknown site state")
            # routing dicision has made, return
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
    global site_dic, conn_dic, xid_dic

    if not isinstance(a, packet_base) or (isinstance(a, packet_base) and not a.parsed):
        vlog.error("ack pkt is unable to be parsed")
        return
    if not a.xid in xid_dic:
        vlog.err("xid is not expected(%d)" % a.xid)
        return

    xid = a.xid
    site = xid_dic[xid]
    if a.result == ack.SRVC_RSLT_ERR:
        vlog.warn("req conn to site(%d) failed" % site)
        site_dic[site]['state'] = STATE_NOT_CONNECTED
    elif a.result == ack.SRVC_RSLT_OK:
        # make a set to avoid duplicate 't'(target network)
        s = set(t for pkt,t in conn_dic[site]['list'])
        # add all target network via 'site' to data path
        for t in s:
            rule_add(t, site, soft_timeout, hard_timeout)
        site_dic[site]['state'] = STATE_CONNECTED
    else:
        vlog.error("ack result's unknown(%d)" % a.result)
        site_dic[site]['state'] = STATE_NOT_CONNECTED
    del xid_dic[xid]
    del conn_dic[site]

def process_srvc_notify(n):
    global site_dic

    if not isinstance(n, packet_base) or (isinstance(n, packet_base) and not n.parsed):
        vlog.error("notify pkt is unable to be parsed")
        return
    if n.site not in site_dic:
        vlog.warn("invalid site(%d)", n.site)
        return
    if n.type != nofify.SRVC_NOTIFY_LOGOUT and n.type != nofify.SRVC_NOTIFY_ERR:
        vlog.warn("unknown notify type(%d)", n.type)
        return
    if n.type == nofify.SRVC_NOTIFY_LOGOUT:
        vlog.info("site(%d) LOGOUT", n.site)
    if n.type == nofify.SRVC_NOTIFY_ERR:
        vlog.info("site(%d) ERR", n.site)

    if n.site in conn_dic:
        del conn_dic[n.site]
        for xid in set(x for x in xid_dic):
            if xid_dic[xid] == n.site:
                del xid_dic[xid]
    rm_route(site_dic[n.site]['rn'], n.site)
    del site_dic[n.site]
    vlog.info("site(%d) and related route removed", n.site)

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
                vlog.error("can't parse this kind of service pkt:%d" % s.type)
        else:
            vlog.error("can't parse service payload")
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
    global site_dic, conn_dic, xid_dic

    for s in set(x for x in site_dic):
        if now > site_dic[s]['timestamp'] + site_timeout:
            vlog.warn("site info timeout, drop all route via site(%d)"%s)
            rm_route(site_dic[s]['rn'], s)
            if s in conn_dic:
                del conn_dic[s]
            for xid in set(x for x in xid_dic):
                if xid_dic[xid] == s:
                    del xid_dic[xid]
            del site_dic[s]

def chk_conn(now):
    global site_dic, conn_dic, xid_dic

    for s in set(x for x in conn_dic):
        if now > conn_dic[s]['timestamp'] + conn_req_timeout:
            vlog.warn("request timeout, drop(site(%d), %d pkt(s))..."%(s, len(conn_dic[s]['list'])))
            site_dic[s]['state'] = STATE_NOT_CONNECTED
            del conn_dic[s]
            for xid in set(x for x in xid_dic):
                if xid_dic[xid] == s:
                    del xid_dic[xid]

def process_timer():
    now = cur_timestamp()
    if now > process_timer.check_tmr_expire:
        chk_sites(now)
        chk_conn(now)
        process_timer.check_tmr_expire = now + CHECK_INTERVAL
    if now > process_timer.prop_tmr_expire:
        propergate_route()
        process_timer.prop_tmr_expire = now + prop_intvl
process_timer.prop_tmr_expire = 0
process_timer.check_tmr_expire = 0

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
    global site_id, prop_intvl, conn_req_timeout, soft_timeout, hard_timeout
    global site_dic, route_dic, ctrl_pkt_list, conn_dic, xid_dic

    parser = argparse.ArgumentParser(
        description="IPGW ctrlp: control plane for IP access gateway")
    parser.add_argument("-f", "--cfgfile", metavar="FILE", help="use FILE as configuration file")
    parser.add_argument("--unixctl", help="UNIXCTL socket location or 'none'.")
    lib.daemon.add_args(parser)
    lib.vlog.add_args(parser)
    args = parser.parse_args()
    lib.daemon.handle_args(args)
    lib.vlog.handle_args(args)

    lib.daemon.daemonize_start()

    if args.cfgfile is not None:
        cfgfile = args.cfgfile
    else:
        cfgfile = CFG_FILE
    try:
        f = open(cfgfile, 'r')
    except IOError as e:
        vlog.err("open cfg file err(%s): %s"%(cfgfile, e.strerror))
        sys.exit(lib.daemon.RESTART_EXIT_CODE)
    try:
        cfg = json.load(f)
    except ValueError as e:
        vlog.err("parse configuration file failed(%s): %s"%(cfgfile, e))
        sys.exit(lib.daemon.RESTART_EXIT_CODE)
    except:
        vlog.err("parse configuration unexpected error(%s)"%cfgfile)
        sys.exit(lib.daemon.RESTART_EXIT_CODE)
    f.close()

    if ('ID' not in cfg) or (type(cfg['ID']) is not int) or (cfg['ID'] not in ID_RANGE):
        vlog.err("'ID' not found or invalid in cfgfile(%s)"%cfgfile)
        sys.exit(lib.daemon.RESTART_EXIT_CODE)
    site_id = cfg['ID']

    if 'PROP_INTVL' in cfg:
        if (type(cfg['PROP_INTVL']) != int) or (cfg['PROP_INTVL'] not in PROP_INTVL_RANGE):
            vlog.warn("'PROP_INTVL' invalid in cfgfile")
        else:
            prop_intvl = cfg['PROP_INTVL'] * 1000
    if 'CONN_REQ_TIMEOUT' in cfg:
        if (type(cfg['CONN_REQ_TIMEOUT']) != int) or (cfg['CONN_REQ_TIMEOUT'] not in CONN_REQ_TIMEOUT_RANGE):
            vlog.warn("'CONN_REQ_TIMEOUT' invalid in cfgfile")
        else:
            conn_req_timeout = cfg['CONN_REQ_TIMEOUT'] * 1000
    if 'SITE_TIMEOUT' in cfg:
        if (type(cfg['SITE_TIMEOUT']) != int) or (cfg['SITE_TIMEOUT'] not in SITE_TIMEOUT_RANGE):
            vlog.warn("'SITE_TIMEOUT' invalid in cfgfile")
        else:
            site_timeout = cfg['SITE_TIMEOUT'] * 1000
    if 'SOFT_TIMEOUT' in cfg:
        if (type(cfg['SOFT_TIMEOUT']) != int) or (cfg['SOFT_TIMEOUT'] not in SOFT_TIMEOUT_RANGE):
            vlog.warn("'SOFT_TIMEOUT' invalid in cfgfile")
        else:
            soft_timeout = cfg['SOFT_TIMEOUT']
    if 'HARD_TIMEOUT' in cfg:
        if (type(cfg['HARD_TIMEOUT']) != int) or (cfg['HARD_TIMEOUT'] not in HARD_TIMEOUT_RANGE):
            vlog.warn("'HARD_TIMEOUT' invalid in cfgfile")
        else:
            hard_timeout = cfg['HARD_TIMEOUT']

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
    except KeyboardInterrupt:
        vlog.info("KeyboardInterrupt")
    except:
        vlog.exception("traceback")
        sys.exit(lib.daemon.RESTART_EXIT_CODE)
