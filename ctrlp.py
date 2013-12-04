#!/bin/sh -
# vim: sts=4 sw=4 et

from lib.daemon import *
from lib.vlog import *
from lib.stream import *
from lib.poller import *

def main():
    lib.vlog.Vlog.init()
    #set_detach()
    #set_monitor()
    daemonize_start()
    daemonize_complete()

    poller = Poller()
    error, server = PassiveStream.open("punix:/tmp/ctrl.sock")
    connected = False
    while True:
        if not connected:
            error, conn = server.accept()
            print conn
            if conn == None:
                server.wait(poller)
            else:
                connected = True
        if connected:
            error, data = conn.recv(50)
            if len(data) > 0:
                print "data->",data
            conn.recv_wait(poller)
        poller.block()
        print "unblocked..."
    

if __name__ == '__main__':
    main()
